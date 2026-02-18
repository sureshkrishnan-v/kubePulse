// Package metadata provides PID-to-Kubernetes-pod resolution.
package metadata

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sWatcher watches Kubernetes pod events and updates the metadata cache.
type K8sWatcher struct {
	clientset *kubernetes.Clientset
	cache     *Cache
	logger    *zap.Logger
	nodeName  string
}

// NewK8sWatcher creates a Kubernetes pod watcher that populates the metadata cache.
// It uses in-cluster config when running inside a pod, or kubeconfig from
// KUBECONFIG env / ~/.kube/config when running outside.
func NewK8sWatcher(metaCache *Cache, logger *zap.Logger) (*K8sWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig for development
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.ExpandEnv("$HOME/.kube/config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("building kubernetes config: %w", err)
		}
		logger.Info("Using kubeconfig for Kubernetes access", zap.String("path", kubeconfig))
	} else {
		logger.Info("Using in-cluster Kubernetes config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	nodeName := os.Getenv("KUBEPULSE_NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	return &K8sWatcher{
		clientset: clientset,
		cache:     metaCache,
		logger:    logger,
		nodeName:  nodeName,
	}, nil
}

// Run starts watching pod events on the local node and populating the cache.
// It blocks until ctx is cancelled.
func (w *K8sWatcher) Run(ctx context.Context) error {
	// Create informer factory with node field selector to watch only local pods
	factory := informers.NewSharedInformerFactoryWithOptions(
		w.clientset,
		0, // no resync
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", w.nodeName)
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()

	// Register event handlers
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.updatePodContainers(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			w.updatePodContainers(pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// Handle DeletedFinalStateUnknown
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			w.deletePodContainers(pod)
		},
	})

	w.logger.Info("Starting Kubernetes pod watcher",
		zap.String("node", w.nodeName))

	// Start the informer
	factory.Start(ctx.Done())

	// Wait for cache sync
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("failed to sync pod informer cache")
	}
	w.logger.Info("Kubernetes pod cache synced")

	<-ctx.Done()
	return ctx.Err()
}

// updatePodContainers updates the cache with container IDs from a pod.
func (w *K8sWatcher) updatePodContainers(pod *corev1.Pod) {
	for _, status := range pod.Status.ContainerStatuses {
		containerID := extractContainerIDFromStatus(status.ContainerID)
		if containerID == "" {
			continue
		}

		meta := PodMeta{
			PodName:       pod.Name,
			Namespace:     pod.Namespace,
			NodeName:      pod.Spec.NodeName,
			ContainerName: status.Name,
			ContainerID:   containerID,
		}

		w.cache.UpdatePod(containerID, meta)
		w.logger.Debug("Cached pod metadata",
			zap.String("pod", pod.Name),
			zap.String("namespace", pod.Namespace),
			zap.String("container", status.Name),
			zap.String("containerID", containerID[:12]))
	}
}

// deletePodContainers removes container IDs from the cache when a pod is deleted.
func (w *K8sWatcher) deletePodContainers(pod *corev1.Pod) {
	for _, status := range pod.Status.ContainerStatuses {
		containerID := extractContainerIDFromStatus(status.ContainerID)
		if containerID == "" {
			continue
		}
		w.cache.DeletePod(containerID)
		w.logger.Debug("Removed pod from cache",
			zap.String("pod", pod.Name),
			zap.String("namespace", pod.Namespace))
	}
}

// extractContainerIDFromStatus parses the container ID from a Kubernetes
// container status string like "containerd://abc123..." or "docker://abc123..."
func extractContainerIDFromStatus(raw string) string {
	// Format: <runtime>://<containerID>
	idx := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			idx = i + 2
			break
		}
	}
	if idx > 0 && idx < len(raw) {
		return raw[idx:]
	}
	return raw
}
