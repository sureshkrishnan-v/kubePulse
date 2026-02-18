// Package metadata provides PID-to-Kubernetes-pod resolution.
package metadata

import (
	"sync"
	"time"
)

// PodMeta holds Kubernetes pod metadata for metrics labeling.
type PodMeta struct {
	PodName       string
	Namespace     string
	NodeName      string
	ContainerName string
	ContainerID   string
}

// cacheEntry wraps PodMeta with an expiry time for TTL eviction.
type cacheEntry struct {
	meta    PodMeta
	expires time.Time
}

// Cache is a thread-safe LRU cache mapping PIDs to PodMeta.
// It has a configurable TTL and max size.
type Cache struct {
	mu      sync.RWMutex
	entries map[uint32]cacheEntry
	maxSize int
	ttl     time.Duration

	// containerIndex maps containerID → PodMeta for fast lookup
	containerIndex map[string]PodMeta
	ciMu           sync.RWMutex

	// resolver function: PID → containerID
	resolveContainerID func(pid uint32) (string, error)
}

// CacheConfig configures the metadata cache.
type CacheConfig struct {
	MaxSize int           // Maximum number of PID entries (default: 8192)
	TTL     time.Duration // TTL for cache entries (default: 60s)
}

// DefaultCacheConfig returns sensible default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		MaxSize: 8192,
		TTL:     60 * time.Second,
	}
}

// NewCache creates a new metadata cache.
func NewCache(config CacheConfig) *Cache {
	if config.MaxSize <= 0 {
		config.MaxSize = 8192
	}
	if config.TTL <= 0 {
		config.TTL = 60 * time.Second
	}

	return &Cache{
		entries:            make(map[uint32]cacheEntry, config.MaxSize),
		maxSize:            config.MaxSize,
		ttl:                config.TTL,
		containerIndex:     make(map[string]PodMeta),
		resolveContainerID: ContainerIDFromPID,
	}
}

// Lookup resolves a PID to PodMeta.
// If the PID is cached and not expired, returns the cached value.
// If not cached, resolves container ID via /proc and looks up k8s metadata.
func (c *Cache) Lookup(pid uint32) (PodMeta, bool) {
	// Check cache first
	c.mu.RLock()
	entry, found := c.entries[pid]
	c.mu.RUnlock()

	if found && time.Now().Before(entry.expires) {
		return entry.meta, true
	}

	// Cache miss or expired — resolve container ID
	containerID, err := c.resolveContainerID(pid)
	if err != nil || containerID == "" {
		return PodMeta{}, false
	}

	// Look up pod metadata by container ID
	c.ciMu.RLock()
	meta, found := c.containerIndex[containerID]
	c.ciMu.RUnlock()

	if !found {
		return PodMeta{}, false
	}

	// Cache the result
	c.set(pid, meta)
	return meta, true
}

// UpdatePod updates the container-to-pod index when a pod is discovered.
// This is called by the Kubernetes informer when pods are added or updated.
func (c *Cache) UpdatePod(containerID string, meta PodMeta) {
	c.ciMu.Lock()
	c.containerIndex[containerID] = meta
	c.ciMu.Unlock()
}

// DeletePod removes a container from the index when a pod is deleted.
// This is called by the Kubernetes informer when pods are deleted.
func (c *Cache) DeletePod(containerID string) {
	c.ciMu.Lock()
	delete(c.containerIndex, containerID)
	c.ciMu.Unlock()
}

// set stores a PID → PodMeta entry in the cache with TTL.
func (c *Cache) set(pid uint32, meta PodMeta) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if cache is full
	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[pid] = cacheEntry{
		meta:    meta,
		expires: time.Now().Add(c.ttl),
	}
}

// evict removes expired entries. If still over capacity, removes ~25% oldest.
func (c *Cache) evict() {
	now := time.Now()

	// First pass: remove expired entries
	for pid, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, pid)
		}
	}

	// If still over capacity, remove 25% of entries (oldest first)
	if len(c.entries) >= c.maxSize {
		toRemove := c.maxSize / 4
		removed := 0
		for pid := range c.entries {
			if removed >= toRemove {
				break
			}
			delete(c.entries, pid)
			removed++
		}
	}
}

// Stats returns cache statistics.
func (c *Cache) Stats() (pidEntries, containerEntries int) {
	c.mu.RLock()
	pidEntries = len(c.entries)
	c.mu.RUnlock()

	c.ciMu.RLock()
	containerEntries = len(c.containerIndex)
	c.ciMu.RUnlock()

	return
}
