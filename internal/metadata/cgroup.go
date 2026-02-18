// Package metadata provides PID-to-Kubernetes-pod resolution.
//
// Resolution flow:
//
//	PID → /proc/<pid>/cgroup → containerID → k8s cache → {pod, namespace, node}
package metadata

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// containerIDRegexps matches container IDs from various cgroup formats:
// - cgroup v1: /kubepods/burstable/pod<uid>/<containerID>
// - cgroup v2: /kubepods.slice/kubepods-burstable.slice/.../<containerID>
// - Docker: /docker/<containerID>
// - Containerd: /system.slice/containerd.service/kubepods-.../<containerID>
var containerIDRegexps = []*regexp.Regexp{
	// Standard cgroup v1 with kubepods
	regexp.MustCompile(`[a-f0-9]{64}`),
	// CRI-O format: crio-<containerID>
	regexp.MustCompile(`crio-([a-f0-9]{64})`),
	// Containerd format: containerd://<containerID>
	regexp.MustCompile(`containerd://([a-f0-9]{64})`),
}

// ContainerIDFromPID reads /proc/<pid>/cgroup and extracts the container ID.
// Returns empty string if the process is not in a container.
func ContainerIDFromPID(pid uint32) (string, error) {
	return containerIDFromCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
}

// containerIDFromCgroupFile reads a cgroup file and extracts the container ID.
// Exported for testing.
func containerIDFromCgroupFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening cgroup file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		containerID := extractContainerID(line)
		if containerID != "" {
			return containerID, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading cgroup file: %w", err)
	}

	return "", nil // Not a containerized process
}

// extractContainerID extracts a 64-char hex container ID from a cgroup line.
func extractContainerID(line string) string {
	// Skip non-kubernetes cgroup lines
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return ""
	}
	cgroupPath := parts[2]

	// Try each regex pattern
	for _, re := range containerIDRegexps {
		matches := re.FindStringSubmatch(cgroupPath)
		if len(matches) > 1 {
			return matches[1]
		}
		if len(matches) == 1 && len(matches[0]) == 64 {
			return matches[0]
		}
	}

	return ""
}
