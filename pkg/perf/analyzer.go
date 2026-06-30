package perf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SchedAnalyzer CPU 调度分析器
type SchedAnalyzer struct {
	samples   map[uint32]*ProcessCPU
	mu        sync.RWMutex
	interval  time.Duration
}

// ProcessCPU 进程 CPU 使用
type ProcessCPU struct {
	PID       uint32
	Comm      string
	TotalNS   uint64
	UserNS    uint64
	SystemNS  uint64
}

// NewSchedAnalyzer 创建调度分析器
func NewSchedAnalyzer(interval time.Duration) *SchedAnalyzer {
	return &SchedAnalyzer{
		samples:  make(map[uint32]*ProcessCPU),
		interval: interval,
	}
}

// RecordSample 记录 CPU 采样
func (s *SchedAnalyzer) RecordSample(pid uint32, comm string, deltaNS uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	proc, ok := s.samples[pid]
	if !ok {
		proc = &ProcessCPU{PID: pid, Comm: comm}
		s.samples[pid] = proc
	}
	proc.TotalNS += deltaNS
}

// GetTopCPU 获取 Top CPU 使用进程
func (s *SchedAnalyzer) GetTopCPU(n int) []*ProcessCPU {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var procs []*ProcessCPU
	for _, p := range s.samples {
		procs = append(procs, p)
	}

	// 简单排序
	for i := 0; i < len(procs); i++ {
		for j := i + 1; j < len(procs); j++ {
			if procs[j].TotalNS > procs[i].TotalNS {
				procs[i], procs[j] = procs[j], procs[i]
			}
		}
	}

	if n > len(procs) {
		n = len(procs)
	}
	return procs[:n]
}

// Reset 重置采样数据
func (s *SchedAnalyzer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = make(map[uint32]*ProcessCPU)
}

// MemLeakDetector 内存泄漏检测器
type MemLeakDetector struct {
	allocs map[uint32]*AllocInfo
	mu      sync.RWMutex
}

// AllocInfo 分配信息
type AllocInfo struct {
	PID      uint32
	Bytes    uint64
	Count    uint64
	AllocNS  uint64
	FreeNS   uint64
}

// NewMemLeakDetector 创建内存泄漏检测器
func NewMemLeakDetector() *MemLeakDetector {
	return &MemLeakDetector{
		allocs: make(map[uint32]*AllocInfo),
	}
}

// RecordAlloc 记录内存分配
func (m *MemLeakDetector) RecordAlloc(pid uint32, bytes uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.allocs[pid]
	if !ok {
		info = &AllocInfo{PID: pid}
		m.allocs[pid] = info
	}
	info.Bytes += bytes
	info.Count++
}

// RecordFree 记录内存释放
func (m *MemLeakDetector) RecordFree(pid uint32, bytes uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.allocs[pid]
	if ok && info.Bytes >= bytes {
		info.Bytes -= bytes
	}
}

// GetTopAlloc 获取 Top 内存分配进程
func (m *MemLeakDetector) GetTopAlloc(n int) []*AllocInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allocs []*AllocInfo
	for _, a := range m.allocs {
		allocs = append(allocs, a)
	}

	for i := 0; i < len(allocs); i++ {
		for j := i + 1; j < len(allocs); j++ {
			if allocs[j].Bytes > allocs[i].Bytes {
				allocs[i], allocs[j] = allocs[j], allocs[i]
			}
		}
	}

	if n > len(allocs) {
		n = len(allocs)
	}
	return allocs[:n]
}

// BlockIOAnalyzer 块设备 IO 分析器
type BlockIOAnalyzer struct {
	ios     map[string]*BlockIOStats
	mu      sync.RWMutex
}

// BlockIOStats 块 IO 统计
type BlockIOStats struct {
	Device    string
	ReadCount uint64
	WriteCount uint64
	ReadBytes uint64
	WriteBytes uint64
	ReadLatNS  uint64
	WriteLatNS uint64
}

// NewBlockIOAnalyzer 创建块 IO 分析器
func NewBlockIOAnalyzer() *BlockIOAnalyzer {
	return &BlockIOAnalyzer{
		ios: make(map[string]*BlockIOStats),
	}
}

// RecordIO 记录 IO 事件
func (b *BlockIOAnalyzer) RecordIO(device string, isWrite bool, bytes, latencyNS uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	stats, ok := b.ios[device]
	if !ok {
		stats = &BlockIOStats{Device: device}
		b.ios[device] = stats
	}

	if isWrite {
		stats.WriteCount++
		stats.WriteBytes += bytes
		stats.WriteLatNS += latencyNS
	} else {
		stats.ReadCount++
		stats.ReadBytes += bytes
		stats.ReadLatNS += latencyNS
	}
}

// GetStats 获取所有设备统计
func (b *BlockIOAnalyzer) GetStats() map[string]*BlockIOStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]*BlockIOStats)
	for k, v := range b.ios {
		result[k] = v
	}
	return result
}

// HostMetrics 主机指标采集
type HostMetrics struct {
	CPU    float64
	Mem    float64
	Disk   float64
	NetRx  uint64
	NetTx  uint64
}

// CollectHostMetrics 采集主机指标
func CollectHostMetrics() *HostMetrics {
	m := &HostMetrics{}

	// CPU 使用率
	m.CPU = collectCPUUsage()

	// 内存使用率
	m.Mem = collectMemUsage()

	// 磁盘使用率
	m.Disk = collectDiskUsage()

	// 网络流量
	m.NetRx, m.NetTx = collectNetStats()

	return m
}

func collectCPUUsage() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				user, _ := strconv.ParseUint(fields[1], 10, 64)
				nice, _ := strconv.ParseUint(fields[2], 10, 64)
				system, _ := strconv.ParseUint(fields[3], 10, 64)
				idle, _ := strconv.ParseUint(fields[4], 10, 64)
				total := user + nice + system + idle
				if total > 0 {
					return float64(user+system) / float64(total) * 100
				}
			}
		}
	}
	return 0
}

func collectMemUsage() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	var total, available uint64
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch {
		case strings.HasPrefix(fields[0], "MemTotal"):
			total = val
		case strings.HasPrefix(fields[0], "MemAvailable"):
			available = val
		}
	}

	if total > 0 {
		return float64(total-available) / float64(total) * 100
	}
	return 0
}

func collectDiskUsage() float64 {
	// 简化: 使用 df 获取根分区使用率
	return 0
}

func collectNetStats() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // 跳过标题行
		}

		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}

		fields := strings.Fields(line[idx+1:])
		if len(fields) >= 10 {
			r, _ := strconv.ParseUint(fields[0], 10, 64)
			t, _ := strconv.ParseUint(fields[8], 10, 64)
			rx += r
			tx += t
		}
	}
	return
}
