package core

import (
	"sync"
	"sync/atomic"
	"time"
)

// BufferPool manages reusable byte buffers to reduce allocations
type BufferPool struct {
	pools map[int]*sync.Pool
	sizes []int
	stats *PoolStats
}

// PoolStats tracks buffer pool usage statistics
type PoolStats struct {
	Gets      int64
	Puts      int64
	Hits      int64
	Misses    int64
	Created   int64
	StartTime time.Time
}

// TrackedBufferPool extends BufferPool with detailed tracking
type TrackedBufferPool struct {
	*BufferPool
	activeBuffers int64
	totalBytes    int64
}

// Buffer size categories for different use cases
const (
	SmallBufferSize  = 512   // Small packets, control messages
	MediumBufferSize = 1500  // Standard MTU packets
	LargeBufferSize  = 8192  // Large packets, file transfers
	XLBufferSize     = 32768 // Extra large buffers for bulk operations
)

var (
	// Global buffer pool instance
	globalBufferPool *TrackedBufferPool
	poolOnce         sync.Once
)

// NewBufferPool creates a new buffer pool with predefined sizes
func NewBufferPool() *BufferPool {
	sizes := []int{SmallBufferSize, MediumBufferSize, LargeBufferSize, XLBufferSize}
	pools := make(map[int]*sync.Pool)

	stats := &PoolStats{
		StartTime: time.Now(),
	}

	for _, size := range sizes {
		currentSize := size // Capture for closure
		pools[size] = &sync.Pool{
			New: func() interface{} {
				atomic.AddInt64(&stats.Created, 1)
				buffer := make([]byte, currentSize)
				return &buffer
			},
		}
	}

	return &BufferPool{
		pools: pools,
		sizes: sizes,
		stats: stats,
	}
}

// NewTrackedBufferPool creates a tracked buffer pool
func NewTrackedBufferPool() *TrackedBufferPool {
	return &TrackedBufferPool{
		BufferPool: NewBufferPool(),
	}
}

// GetBuffer retrieves a buffer of at least the specified size
func (bp *BufferPool) GetBuffer(size int) []byte {
	atomic.AddInt64(&bp.stats.Gets, 1)

	// Find the smallest buffer that fits
	for _, poolSize := range bp.sizes {
		if poolSize >= size {
			if pool, exists := bp.pools[poolSize]; exists {
				atomic.AddInt64(&bp.stats.Hits, 1)
				buffer := pool.Get().(*[]byte)
				return (*buffer)[:size] // Return slice of requested size
			}
		}
	}

	// No suitable pool found, create new buffer
	atomic.AddInt64(&bp.stats.Misses, 1)
	atomic.AddInt64(&bp.stats.Created, 1)
	return make([]byte, size)
}

// PutBuffer returns a buffer to the pool
func (bp *BufferPool) PutBuffer(buffer []byte) {
	atomic.AddInt64(&bp.stats.Puts, 1)

	// Find the appropriate pool based on capacity
	capacity := cap(buffer)
	for _, poolSize := range bp.sizes {
		if capacity == poolSize {
			if pool, exists := bp.pools[poolSize]; exists {
				// Reset buffer length to full capacity
				buffer = buffer[:capacity]
				// Clear buffer for security
				for i := range buffer {
					buffer[i] = 0
				}
				pool.Put(&buffer)
				return
			}
		}
	}
	// Buffer doesn't match any pool size, let GC handle it
}

// GetStats returns current pool statistics
func (bp *BufferPool) GetStats() PoolStats {
	return PoolStats{
		Gets:      atomic.LoadInt64(&bp.stats.Gets),
		Puts:      atomic.LoadInt64(&bp.stats.Puts),
		Hits:      atomic.LoadInt64(&bp.stats.Hits),
		Misses:    atomic.LoadInt64(&bp.stats.Misses),
		Created:   atomic.LoadInt64(&bp.stats.Created),
		StartTime: bp.stats.StartTime,
	}
}

// GetBuffer retrieves a buffer with tracking
func (tbp *TrackedBufferPool) GetBuffer(size int) []byte {
	buffer := tbp.BufferPool.GetBuffer(size)
	atomic.AddInt64(&tbp.activeBuffers, 1)
	atomic.AddInt64(&tbp.totalBytes, int64(cap(buffer)))
	return buffer
}

// PutBuffer returns a buffer with tracking
func (tbp *TrackedBufferPool) PutBuffer(buffer []byte) {
	atomic.AddInt64(&tbp.activeBuffers, -1)
	atomic.AddInt64(&tbp.totalBytes, -int64(cap(buffer)))
	tbp.BufferPool.PutBuffer(buffer)
}

// GetActiveBuffers returns the number of active buffers
func (tbp *TrackedBufferPool) GetActiveBuffers() int64 {
	return atomic.LoadInt64(&tbp.activeBuffers)
}

// GetTotalBytes returns total bytes in active buffers
func (tbp *TrackedBufferPool) GetTotalBytes() int64 {
	return atomic.LoadInt64(&tbp.totalBytes)
}

// GetExtendedStats returns extended statistics
func (tbp *TrackedBufferPool) GetExtendedStats() map[string]interface{} {
	stats := tbp.GetStats()
	uptime := time.Since(stats.StartTime)

	hitRate := float64(0)
	if stats.Gets > 0 {
		hitRate = float64(stats.Hits) / float64(stats.Gets) * 100
	}

	return map[string]interface{}{
		"gets":            stats.Gets,
		"puts":            stats.Puts,
		"hits":            stats.Hits,
		"misses":          stats.Misses,
		"created":         stats.Created,
		"active_buffers":  tbp.GetActiveBuffers(),
		"total_bytes":     tbp.GetTotalBytes(),
		"hit_rate":        hitRate,
		"uptime_seconds":  uptime.Seconds(),
		"gets_per_second": float64(stats.Gets) / uptime.Seconds(),
	}
}

// GetGlobalBufferPool returns the global buffer pool instance
func GetGlobalBufferPool() *TrackedBufferPool {
	poolOnce.Do(func() {
		globalBufferPool = NewTrackedBufferPool()
	})
	return globalBufferPool
}

// Convenience functions for global pool access

// GetBuffer gets a buffer from the global pool
func GetBuffer(size int) []byte {
	return GetGlobalBufferPool().GetBuffer(size)
}

// PutBuffer returns a buffer to the global pool
func PutBuffer(buffer []byte) {
	GetGlobalBufferPool().PutBuffer(buffer)
}

// GetPoolStats returns global pool statistics
func GetPoolStats() map[string]interface{} {
	return GetGlobalBufferPool().GetExtendedStats()
}
