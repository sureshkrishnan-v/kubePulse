package metadata

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "cgroup v1 kubepods",
			line:     "12:memory:/kubepods/burstable/pod1234/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:     "docker container",
			line:     "11:devices:/docker/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:     "cri-o container",
			line:     "0::/kubepods.slice/kubepods-pod123.slice/crio-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:     "bare host process",
			line:     "12:memory:/user.slice/user-1000.slice/session-1.scope",
			expected: "",
		},
		{
			name:     "empty line",
			line:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractContainerID(tt.line)
			if result != tt.expected {
				t.Errorf("extractContainerID(%q) = %q, want %q", tt.line, result, tt.expected)
			}
		})
	}
}

func TestContainerIDFromCgroupFile(t *testing.T) {
	// Create temp cgroup file
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup")

	content := `12:memory:/kubepods/burstable/pod-uid/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
11:devices:/kubepods/burstable/pod-uid/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
0::/kubepods/burstable/pod-uid/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	containerID, err := containerIDFromCgroupFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containerID != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("unexpected container ID: %q", containerID)
	}
}

func TestContainerIDFromCgroupFile_NotContainer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup")

	content := `12:memory:/user.slice/user-1000.slice/session-1.scope
0::/user.slice/user-1000.slice/session-1.scope
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	containerID, err := containerIDFromCgroupFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containerID != "" {
		t.Errorf("expected empty container ID for non-container process, got %q", containerID)
	}
}

func TestCache_BasicLookup(t *testing.T) {
	cache := NewCache(CacheConfig{MaxSize: 100, TTL: time.Minute})

	// Pre-populate container index
	cache.UpdatePod("container123", PodMeta{
		PodName:   "my-pod",
		Namespace: "default",
		NodeName:  "node1",
	})

	// Override resolver for testing
	cache.resolveContainerID = func(pid uint32) (string, error) {
		if pid == 42 {
			return "container123", nil
		}
		return "", nil
	}

	// Lookup should find the pod
	meta, found := cache.Lookup(42)
	if !found {
		t.Fatal("expected to find pod metadata")
	}
	if meta.PodName != "my-pod" {
		t.Errorf("unexpected pod name: %q", meta.PodName)
	}
	if meta.Namespace != "default" {
		t.Errorf("unexpected namespace: %q", meta.Namespace)
	}

	// Lookup unknown PID
	_, found = cache.Lookup(999)
	if found {
		t.Fatal("expected not to find metadata for unknown PID")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	cache := NewCache(CacheConfig{MaxSize: 100, TTL: 10 * time.Millisecond})

	cache.UpdatePod("container123", PodMeta{
		PodName:   "my-pod",
		Namespace: "default",
	})

	cache.resolveContainerID = func(pid uint32) (string, error) {
		return "container123", nil
	}

	// First lookup should succeed
	_, found := cache.Lookup(42)
	if !found {
		t.Fatal("expected to find pod metadata")
	}

	// Wait for TTL
	time.Sleep(20 * time.Millisecond)

	// Should re-resolve (still finds because container index is still populated)
	meta, found := cache.Lookup(42)
	if !found {
		t.Fatal("expected to re-resolve pod metadata after TTL")
	}
	if meta.PodName != "my-pod" {
		t.Errorf("unexpected pod name after re-resolve: %q", meta.PodName)
	}
}

func TestCache_DeletePod(t *testing.T) {
	cache := NewCache(CacheConfig{MaxSize: 100, TTL: time.Minute})

	cache.UpdatePod("container123", PodMeta{
		PodName:   "my-pod",
		Namespace: "default",
	})

	cache.resolveContainerID = func(pid uint32) (string, error) {
		return "container123", nil
	}

	_, found := cache.Lookup(42)
	if !found {
		t.Fatal("expected to find pod metadata")
	}

	// Delete the pod
	cache.DeletePod("container123")

	// Clear PID cache to force re-lookup
	cache.mu.Lock()
	delete(cache.entries, 42)
	cache.mu.Unlock()

	// Lookup should no longer find it
	_, found = cache.Lookup(42)
	if found {
		t.Fatal("expected NOT to find pod metadata after deletion")
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewCache(CacheConfig{MaxSize: 100, TTL: time.Minute})
	cache.UpdatePod("c1", PodMeta{PodName: "p1"})
	cache.UpdatePod("c2", PodMeta{PodName: "p2"})

	pids, containers := cache.Stats()
	if pids != 0 {
		t.Errorf("expected 0 PID entries, got %d", pids)
	}
	if containers != 2 {
		t.Errorf("expected 2 container entries, got %d", containers)
	}
}
