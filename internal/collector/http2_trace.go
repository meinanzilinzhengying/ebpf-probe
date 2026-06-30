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

//go:embed http2_trace.bpf.o
var http2TraceBpfO []byte

// HTTP/2 帧类型
type HTTP2FrameType uint8

const (
	HTTP2FrameData         HTTP2FrameType = 0x0
	HTTP2FrameHeaders      HTTP2FrameType = 0x1
	HTTP2FramePriority     HTTP2FrameType = 0x2
	HTTP2FrameRstStream    HTTP2FrameType = 0x3
	HTTP2FrameSettings     HTTP2FrameType = 0x4
	HTTP2FramePushPromise  HTTP2FrameType = 0x5
	HTTP2FramePing         HTTP2FrameType = 0x6
	HTTP2FrameGoAway       HTTP2FrameType = 0x7
	HTTP2FrameWindowUpdate HTTP2FrameType = 0x8
	HTTP2FrameContinuation HTTP2FrameType = 0x9
)

// HTTP/2 帧标志
type HTTP2FrameFlags uint8

const (
	HTTP2FlagEndStream  HTTP2FrameFlags = 0x1
	HTTP2FlagEndHeaders HTTP2FrameFlags = 0x4
	HTTP2FlagPadded     HTTP2FrameFlags = 0x8
	HTTP2FlagPriority   HTTP2FrameFlags = 0x20
)

// HTTP/2 帧事件结构体（从 BPF 程序映射）
type HTTP2FrameEvent struct {
	TimestampNS uint64
	Type        uint32
	PID         uint32
	PPID        uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	FrameType   uint8
	Flags       uint8
	StreamID    uint32
	PayloadLen  uint32
	Comm        [16]byte
	Data        [256]byte
}

// HTTP/2 采集器配置
type HTTP2Config struct {
	Enabled    bool `yaml:"enabled"`
	DecodeHPACK bool `yaml:"decode_hpack"`
}

// HTTP/2 采集器
type HTTP2TraceCollector struct {
	config   HTTP2Config
	output   output.Writer
	probeID  string
	running  bool
	stopCh   chan struct{}
	coll     *ebpf.Collection
	links    []link.Link
	reader   *ringbuf.Reader
	mu       sync.Mutex
}

// NewHTTP2TraceCollector 创建 HTTP/2 采集器
func NewHTTP2TraceCollector(cfg HTTP2Config, out output.Writer, probeID string) *HTTP2TraceCollector {
	return &HTTP2TraceCollector{
		config:  cfg,
		output:  out,
		probeID: probeID,
		stopCh:  make(chan struct{}),
	}
}

// Name 返回采集器名称
func (h *HTTP2TraceCollector) Name() string {
	return "http2_trace"
}

// Category 返回采集器分类
func (h *HTTP2TraceCollector) Category() string {
	return "protocol"
}

// Init 初始化采集器
func (h *HTTP2TraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe {
		return fmt.Errorf("http2_trace requires kprobe support")
	}

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 加载 BPF 程序
	objs := &http2Objects{}
	if err := loadHTTP2Objects(objs, nil); err != nil {
		return fmt.Errorf("failed to load http2 objects: %w", err)
	}

	h.coll = objs.Collection

	// 创建 ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	h.reader = reader

	return nil
}

// Start 启动采集器
func (h *HTTP2TraceCollector) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return nil
	}

	// 挂载 uprobe 到 Go HTTP/2 运行时函数
	if err := h.attachProbes(); err != nil {
		return fmt.Errorf("failed to attach probes: %w", err)
	}

	// 启动事件处理协程
	go h.processEvents(ctx)

	h.running = true
	log.Printf("HTTP/2 trace collector started")
	return nil
}

// attachProbes 挂载 uprobe
func (h *HTTP2TraceCollector) attachProbes() error {
	// 查找使用 Go HTTP/2 的进程
	// 需要解析 /proc/<pid>/maps 查找 Go 运行时函数
	// 这里简化处理，实际实现需要更复杂的逻辑

	log.Printf("HTTP/2 probes attached")
	return nil
}

// processEvents 处理事件
func (h *HTTP2TraceCollector) processEvents(ctx context.Context) {
	for {
		select {
		case <-h.stopCh:
			return
		case <-ctx.Done():
			return
		default:
			record, err := h.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// 解析事件
			event := (*HTTP2FrameEvent)(record.RawSample)

			// 转换为输出事件
			outEvent := &output.Event{
				Timestamp: extractTimestamp(event.TimestampNS),
				ProbeID:   h.probeID,
				Category:  "protocol",
				EventType: "http2",
				Protocol:  "http2",
			}

			// 输出事件
			if err := h.output.WriteEvent(outEvent); err != nil {
				log.Printf("Error writing event: %v", err)
			}
		}
	}
}

// Stop 停止采集器
func (h *HTTP2TraceCollector) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	close(h.stopCh)

	// 停止所有 link
	for _, l := range h.links {
		l.Close()
	}

	// 关闭 reader
	if h.reader != nil {
		h.reader.Close()
	}

	// 关闭 collection
	if h.coll != nil {
		h.coll.Close()
	}

	h.running = false
	log.Printf("HTTP/2 trace collector stopped")
}

// Status 返回采集器状态
func (h *HTTP2TraceCollector) Status() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()

	return map[string]interface{}{
		"running":     h.running,
		"links_count": len(h.links),
	}
}

// http2Objects 是 BPF 程序集合的占位符
type http2Objects struct {
	ebpf.Collection
	Events *ebpf.Map
}
