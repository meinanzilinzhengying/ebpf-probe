// Copyright (c) 2026 CloudFlow Team

package collector

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-probe/internal/kernel"
	"ebpf-probe/internal/output"
)

//go:embed tls_trace.bpf.o
var tlsTraceBpfO []byte

// TLS 库类型
type TLSLibType int

const (
	TLSLibNone     TLSLibType = iota
	TLSLibOpenSSL            // OpenSSL
	TLSLibBoringSSL          // BoringSSL
	TLSLibGnuTLS             // GnuTLS
	TLSLibMbedTLS            // mbedTLS
)

// TLS 事件结构体（从 BPF 程序映射）
type TLSEvent struct {
	TimestampNS uint64
	Type        uint32
	PID         uint32
	PPID        uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	SSLVersion  uint8
	EventType   uint8  // 0=handshake, 1=read, 2=write
	DataLen     uint32
	LatencyNS   uint64
	Comm        [16]byte
	SNI         [64]byte
	Data        [512]byte
}

// TLS 采集器配置
type TLSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Libraries        []string `yaml:"libraries"`
	CaptureHandshake bool     `yaml:"capture_handshake"`
}

// TLS 采集器
type TLSTraceCollector struct {
	config   TLSConfig
	output   output.Writer
	probeID  string
	running  bool
	stopCh   chan struct{}
	coll     *ebpf.Collection
	links    []link.Link
	reader   *ringbuf.Reader
	mu       sync.Mutex
	tlsLibs  map[string]TLSLibType
}

// NewTLSTraceCollector 创建 TLS 采集器
func NewTLSTraceCollector(cfg TLSConfig, out output.Writer, probeID string) *TLSTraceCollector {
	return &TLSTraceCollector{
		config:  cfg,
		output:  out,
		probeID: probeID,
		stopCh:  make(chan struct{}),
		tlsLibs: make(map[string]TLSLibType),
	}
}

// Name 返回采集器名称
func (t *TLSTraceCollector) Name() string {
	return "tls_trace"
}

// Category 返回采集器分类
func (t *TLSTraceCollector) Category() string {
	return "security"
}

// Init 初始化采集器
func (t *TLSTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe && !cap.HasBPFTracepoint {
		return fmt.Errorf("tls_trace requires kprobe or tracepoint support")
	}

	// 检测系统中可用的 TLS 库
	if err := t.detectTLSLibraries(); err != nil {
		log.Printf("Warning: failed to detect TLS libraries: %v", err)
	}

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 加载 BPF 程序
	objs := &tlsObjects{}
	if err := loadTLSObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load tls objects: %w", err)
	}

	t.coll = objs.Collection

	// 创建 ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	t.reader = reader

	return nil
}

// detectTLSLibraries 检测系统中的 TLS 库
func (t *TLSTraceCollector) detectTLSLibraries() error {
	// 检查 OpenSSL
	opensslPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so",
		"/usr/lib/libssl.so",
		"/usr/lib64/libssl.so",
		"/usr/local/lib/libssl.so",
	}

	for _, path := range opensslPaths {
		if _, err := os.Stat(path); err == nil {
			t.tlsLibs["openssl"] = TLSLibOpenSSL
			log.Printf("Detected OpenSSL at %s", path)
			break
		}
	}

	// 检查 BoringSSL
	boringsslPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libboringssl.so",
		"/usr/lib/libboringssl.so",
	}

	for _, path := range boringsslPaths {
		if _, err := os.Stat(path); err == nil {
			t.tlsLibs["boringssl"] = TLSLibBoringSSL
			log.Printf("Detected BoringSSL at %s", path)
			break
		}
	}

	// 检查 GnuTLS
	gnutlsPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libgnutls.so",
		"/usr/lib/libgnutls.so",
		"/usr/lib64/libgnutls.so",
	}

	for _, path := range gnutlsPaths {
		if _, err := os.Stat(path); err == nil {
			t.tlsLibs["gnutls"] = TLSLibGnuTLS
			log.Printf("Detected GnuTLS at %s", path)
			break
		}
	}

	if len(t.tlsLibs) == 0 {
		log.Printf("No TLS libraries detected")
	}

	return nil
}

// Start 启动采集器
func (t *TLSTraceCollector) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return nil
	}

	// 挂载 uprobe 到 TLS 库
	if err := t.attachProbes(); err != nil {
		return fmt.Errorf("failed to attach probes: %w", err)
	}

	// 启动事件处理协程
	go t.processEvents(ctx)

	t.running = true
	log.Printf("TLS trace collector started")
	return nil
}

// attachProbes 挂载 uprobe
func (t *TLSTraceCollector) attachProbes() error {
	// 遍历进程，查找使用 TLS 库的进程
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否是数字目录（进程目录）
		pid := entry.Name()
		if _, err := fmt.Sscanf(pid, "%d"); err != nil {
			continue
		}

		// 检查进程的内存映射
		mapsPath := filepath.Join("/proc", pid, "maps")
		mapsData, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}

		maps := string(mapsData)

		// 查找 TLS 库
		if strings.Contains(maps, "libssl.so") || strings.Contains(maps, "libboringssl.so") || strings.Contains(maps, "libgnutls.so") {
			// 这里应该挂载 uprobe 到对应的进程
			// 实际实现需要解析 ELF 文件获取函数地址
			log.Printf("Found TLS library in process %s", pid)
		}
	}

	return nil
}

// processEvents 处理事件
func (t *TLSTraceCollector) processEvents(ctx context.Context) {
	for {
		select {
		case <-t.stopCh:
			return
		case <-ctx.Done():
			return
		default:
			record, err := t.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// 解析事件
			event := (*TLSEvent)(record.RawSample)

			// 转换为输出事件
			outEvent := &output.Event{
				Timestamp: extractTimestamp(event.TimestampNS),
				ProbeID:   t.probeID,
				Category:  "security",
				EventType: "tls",
				Protocol:  "tls",
			}

			// 输出事件
			if err := t.output.WriteEvent(outEvent); err != nil {
				log.Printf("Error writing event: %v", err)
			}
		}
	}
}

// Stop 停止采集器
func (t *TLSTraceCollector) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	close(t.stopCh)

	// 停止所有 link
	for _, l := range t.links {
		l.Close()
	}

	// 关闭 reader
	if t.reader != nil {
		t.reader.Close()
	}

	// 关闭 collection
	if t.coll != nil {
		t.coll.Close()
	}

	t.running = false
	log.Printf("TLS trace collector stopped")
}

// Status 返回采集器状态
func (t *TLSTraceCollector) Status() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"running":     t.running,
		"tls_libs":    t.tlsLibs,
		"links_count": len(t.links),
	}
}

// extractTimestamp 从纳秒时间戳提取 time.Time
func extractTimestamp(ns uint64) interface{} {
	// 实现时间戳转换
	return nil
}

// tlsObjects 是 BPF 程序集合的占位符
// 实际使用时需要通过 bpf2go 生成
type tlsObjects struct {
	ebpf.Collection
	Events *ebpf.Map
}
