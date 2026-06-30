package output

import "time"

// Writer 数据输出接口
type Writer interface {
	WriteEvent(ev *Event) error
	WriteBatch(events []*Event) error
	WriteMetrics(probeID string, cpu, mem, disk float64, netRx, netTx, diskRead, diskWrite uint64) error
	WriteProcessEvent(ts time.Time, probeID string, pid uint32, comm, exe, args, eventType string) error
	WriteFileEvent(ts time.Time, probeID string, pid uint32, comm, filename, operation string, result int32) error
	WriteSyscallEvent(ts time.Time, probeID string, pid uint32, comm string, syscallNr, latencyNs, count uint64) error
	Close() error
	Flush()
}

// Event 通用事件结构
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	ProbeID     string    `json:"probe_id"`
	Category    string    `json:"category"`
	EventType   string    `json:"event_type"`
	SrcIP       string    `json:"src_ip,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	SrcPort     uint16    `json:"src_port,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Bytes       uint64    `json:"bytes,omitempty"`
	Packets     uint64    `json:"packets,omitempty"`
	LatencyMs   float64   `json:"latency_ms,omitempty"`
	Service     string    `json:"service,omitempty"`
	Details     string    `json:"details,omitempty"`
	Tags        string    `json:"tags,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	ClusterID   string    `json:"cluster_id,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	NodeName    string    `json:"node_name,omitempty"`
}
