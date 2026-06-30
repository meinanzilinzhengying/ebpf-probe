// Copyright (c) 2026 CloudFlow Team

package collector

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-probe/internal/kernel"
	"ebpf-probe/internal/output"
)

//go:embed log_collect.bpf.o
var logCollectBpfO []byte

// 日志事件结构体（从 BPF 程序映射）
type LogEvent struct {
	TimestampNS uint64
	Type        uint32
	PID         uint32
	PPID        uint32
	FD          uint32
	DataLen     uint32
	Comm        [16]byte
	Data        [4096]byte
}

// 日志采集器配置
type LogCollectConfig struct {
	Enabled         bool     `yaml:"enabled"`
	BufferSize      int      `yaml:"buffer_size"`
	MaxLineLength   int      `yaml:"max_line_length"`
	FilterPatterns  []string `yaml:"filter_patterns"`
}

// 日志采集器
type LogCollectCollector struct {
	config   LogCollectConfig
	output   output.Writer
	probeID  string
	running  bool
	stopCh   chan struct{}
	coll     *ebpf.Collection
	links    []link.Link
	reader   *ringbuf.Reader
	mu       sync.Mutex
}

// NewLogCollectCollector 创建日志采集器
func NewLogCollectCollector(cfg LogCollectConfig, out output.Writer, probeID string) *LogCollectCollector {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 4096
	}
	if cfg.MaxLineLength == 0 {
		cfg.MaxLineLength = 8192
	}

	return &LogCollectCollector{
		config:  cfg,
		output:  out,
		probeID: probeID,
		stopCh:  make(chan struct{}),
	}
}

// Name 返回采集器名称
func (l *LogCollectCollector) Name() string {
	return "log_collect"
}

// Category 返回采集器分类
func (l *LogCollectCollector) Category() string {
	return "logging"
}

// Init 初始化采集器
func (l *LogCollectCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFTracepoint {
		return fmt.Errorf("log_collect requires tracepoint support")
	}

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 加载 BPF 程序
	objs := &logCollectObjects{}
	if err := loadLogCollectObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load log_collect objects: %w", err)
	}

	l.coll = objs.Collection

	// 创建 ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	l.reader = reader

	return nil
}

// Start 启动采集器
func (l *LogCollectCollector) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	// 启动事件处理协程
	go l.processEvents(ctx)

	l.running = true
	log.Printf("Log collect collector started")
	return nil
}

// processEvents 处理事件
func (l *LogCollectCollector) processEvents(ctx context.Context) {
	for {
		select {
		case <-l.stopCh:
			return
		case <-ctx.Done():
			return
		default:
			record, err := l.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// 解析事件
			event := (*LogEvent)(record.RawSample)

			// 转换为输出事件
			outEvent := &output.Event{
				Timestamp: extractTimestamp(event.TimestampNS),
				ProbeID:   l.probeID,
				Category:  "logging",
				EventType: "log",
				Details:   string(event.Data[:event.DataLen]),
			}

			// 输出事件
			if err := l.output.WriteEvent(outEvent); err != nil {
				log.Printf("Error writing event: %v", err)
			}
		}
	}
}

// Stop 停止采集器
func (l *LogCollectCollector) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return
	}

	close(l.stopCh)

	// 停止所有 link
	for _, l := range l.links {
		l.Close()
	}

	// 关闭 reader
	if l.reader != nil {
		l.reader.Close()
	}

	// 关闭 collection
	if l.coll != nil {
		l.coll.Close()
	}

	l.running = false
	log.Printf("Log collect collector stopped")
}

// Status 返回采集器状态
func (l *LogCollectCollector) Status() map[string]interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	return map[string]interface{}{
		"running":     l.running,
		"links_count": len(l.links),
	}
}

// logCollectObjects 是 BPF 程序集合的占位符
type logCollectObjects struct {
	ebpf.Collection
	Events *ebpf.Map
}
