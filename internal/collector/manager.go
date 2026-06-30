package collector

import (
	"context"
	"fmt"
	"log"
	"sync"

	"ebpf-probe/internal/kernel"
	"ebpf-probe/internal/output"
)

// Collector 采集器接口
type Collector interface {
	Name() string
	Category() string
	Init(cap kernel.Capabilities) error
	Start(ctx context.Context) error
	Stop()
	Status() map[string]interface{}
}

// CollectorConfig 采集器配置
type CollectorConfig struct {
	// P0 核心采集器
	NetworkFlow bool `yaml:"network_flow"`
	ProcessExec bool `yaml:"process_exec"`
	FileOpen    bool `yaml:"file_open"`
	TCPConnect  bool `yaml:"tcp_connect"`
	HostMetrics bool `yaml:"host_metrics"`

	// P1 扩展采集器
	Syscall      bool `yaml:"syscall"`
	HTTPTrace    bool `yaml:"http_trace"`
	DNSTrace     bool `yaml:"dns_trace"`
	DBTrace      bool `yaml:"db_trace"`
	SchedTrace   bool `yaml:"sched_trace"`
	MemTrace     bool `yaml:"mem_trace"`
	BlockTrace   bool `yaml:"block_trace"`
	SecurityTrace bool `yaml:"security_trace"`

	// 新增采集器 (Cloud-Metrics 功能)
	TLSTrace    bool `yaml:"tls_trace"`
	HTTP2Trace  bool `yaml:"http2_trace"`
	LogCollect  bool `yaml:"log_collect"`
	L7Sniffer   bool `yaml:"l7_sniffer"`
}

// Manager 采集器管理器
type Manager struct {
	collectors map[string]Collector
	cap        kernel.Capabilities
	output     output.Writer
	probeID    string
	mu         sync.RWMutex
}

// NewManager 创建管理器
func NewManager(cap kernel.Capabilities, out output.Writer, probeID string) *Manager {
	return &Manager{
		collectors: make(map[string]Collector),
		cap:        cap,
		output:     out,
		probeID:    probeID,
	}
}

// InitFromConfig 根据配置初始化采集器
func (m *Manager) InitFromConfig(cfg CollectorConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	type collectorDef struct {
		enabled bool
		factory func() Collector
	}

	defs := []collectorDef{
		{cfg.NetworkFlow, func() Collector { return nil }}, // network_flow 由外部提供
		{cfg.ProcessExec, func() Collector { return nil }}, // process_exec 由外部提供
		{cfg.TCPConnect, func() Collector { return nil }},  // tcp_connect 由外部提供
		{cfg.HostMetrics, func() Collector { return nil }}, // host_metrics 由外部提供
		{cfg.HTTPTrace, func() Collector { return nil }},   // http_trace 由外部提供
		{cfg.DNSTrace, func() Collector { return nil }},    // dns_trace 由外部提供
		{cfg.DBTrace, func() Collector { return nil }},     // db_trace 由外部提供

		{cfg.TLSTrace, func() Collector {
			return NewTLSTraceCollector(
				TLSConfig{Enabled: true, CaptureHandshake: true},
				m.output, m.probeID,
			)
		}},
		{cfg.HTTP2Trace, func() Collector {
			return NewHTTP2TraceCollector(
				HTTP2Config{Enabled: true, DecodeHPACK: true},
				m.output, m.probeID,
			)
		}},
		{cfg.LogCollect, func() Collector {
			return NewLogCollectCollector(
				LogCollectConfig{Enabled: true, BufferSize: 4096, MaxLineLength: 8192},
				m.output, m.probeID,
			)
		}},
	}

	for _, def := range defs {
		if !def.enabled {
			continue
		}
		c := def.factory()
		if c == nil {
			continue
		}
		if err := c.Init(m.cap); err != nil {
			log.Printf("skip collector %s: %v", c.Name(), err)
			continue
		}
		m.collectors[c.Name()] = c
	}

	return nil
}

// Register 注册采集器
func (m *Manager) Register(c Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := c.Init(m.cap); err != nil {
		return fmt.Errorf("init collector %s: %w", c.Name(), err)
	}
	m.collectors[c.Name()] = c
	return nil
}

// StartAll 启动所有采集器
func (m *Manager) StartAll(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, c := range m.collectors {
		if err := c.Start(ctx); err != nil {
			log.Printf("start collector %s failed: %v", name, err)
			continue
		}
		log.Printf("collector %s started", name)
	}
	return nil
}

// StopAll 停止所有采集器
func (m *Manager) StopAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, c := range m.collectors {
		c.Stop()
		log.Printf("collector %s stopped", name)
	}
}

// Status 返回所有采集器状态
func (m *Manager) Status() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]map[string]interface{})
	for name, c := range m.collectors {
		status[name] = c.Status()
	}
	return status
}

// GetCollector 获取指定采集器
func (m *Manager) GetCollector(name string) (Collector, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.collectors[name]
	return c, ok
}
