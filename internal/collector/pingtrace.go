package collector

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingTraceConfig 网络路径追踪配置
type PingTraceConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Count     int    `yaml:"count"`
	Type      string `yaml:"type"`     // c=client, s=server
	Timeout   int    `yaml:"timeout"`  // ms
	IsNs      bool   `yaml:"is_ns"`    // namespace 模式
	DstIP     string `yaml:"dst_ip"`
	Interval  int    `yaml:"interval"` // ms
}

// PingHop 跳跃信息
type PingHop struct {
	TTL     int
	IP      net.IP
	RTT     time.Duration
	Timeout bool
}

// PingTraceResult 追踪结果
type PingTraceResult struct {
	DstIP      net.IP
	Hops       []PingHop
	AvgRTT     time.Duration
	MinRTT     time.Duration
	MaxRTT     time.Duration
	PacketLoss float64
}

// PingTraceCollector 网络路径追踪采集器
type PingTraceCollector struct {
	config   PingTraceConfig
	running  bool
	mu       sync.Mutex
	stopCh   chan struct{}
	results  chan *PingTraceResult
}

// NewPingTraceCollector 创建网络路径追踪采集器
func NewPingTraceCollector(cfg PingTraceConfig) *PingTraceCollector {
	if cfg.Count == 0 {
		cfg.Count = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 1000
	}
	if cfg.Interval == 0 {
		cfg.Interval = 100
	}

	return &PingTraceCollector{
		config:  cfg,
		stopCh:  make(chan struct{}),
		results: make(chan *PingTraceResult, 100),
	}
}

// Name 返回采集器名称
func (p *PingTraceCollector) Name() string {
	return "pingtrace"
}

// Category 返回采集器分类
func (p *PingTraceCollector) Category() string {
	return "network"
}

// Init 初始化采集器
func (p *PingTraceCollector) Init() error {
	return nil
}

// Start 启动采集器
func (p *PingTraceCollector) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.running = true

	if p.config.Type == "c" {
		go p.runClient()
	} else {
		go p.runServer()
	}

	log.Printf("pingtrace collector started (type=%s, dst=%s)", p.config.Type, p.config.DstIP)
	return nil
}

func (p *PingTraceCollector) runClient() {
	dst := net.ParseIP(p.config.DstIP)
	if dst == nil {
		log.Printf("pingtrace: invalid destination IP: %s", p.config.DstIP)
		return
	}

	ticker := time.NewTicker(time.Duration(p.config.Interval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			result := p.tracePath(dst)
			if result != nil {
				select {
				case p.results <- result:
				default:
				}
			}
		}
	}
}

func (p *PingTraceCollector) tracePath(dst net.IP) *PingTraceResult {
	result := &PingTraceResult{
		DstIP: dst,
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("pingtrace: listen failed: %v", err)
		return nil
	}
	defer conn.Close()

	var rtts []time.Duration
	sent := 0
	received := 0

	for ttl := 1; ttl <= 30; ttl++ {
		hop := PingHop{TTL: ttl}

		// 设置 TTL
		err := conn.SetTTL(ttl)
		if err != nil {
			continue
		}

		// 构建 ICMP Echo 请求
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   1234,
				Seq:  ttl,
				Data: []byte("pingtrace"),
			},
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			continue
		}

		start := time.Now()
		_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: dst})
		if err != nil {
			continue
		}

		sent++

		// 读取响应
		conn.SetReadDeadline(time.Now().Add(time.Duration(p.config.Timeout) * time.Millisecond))
		buf := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			hop.Timeout = true
			result.Hops = append(result.Hops, hop)
			continue
		}

		rtt := time.Since(start)
		received++
		rtts = append(rtts, rtt)

		hop.IP = peer.(*net.IPAddr).IP
		hop.RTT = rtt
		result.Hops = append(result.Hops, hop)

		// 解析 ICMP 响应
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		// 如果是 Echo Reply，说明到达目标
		if reply.Type == ipv4.ICMPTypeEchoReply {
			break
		}

		// 如果是 Time Exceeded，继续追踪
		if reply.Type != ipv4.ICMPTypeTimeExceeded {
			break
		}
	}

	// 计算统计信息
	if len(rtts) > 0 {
		var total time.Duration
		result.MinRTT = rtts[0]
		result.MaxRTT = rtts[0]

		for _, rtt := range rtts {
			total += rtt
			if rtt < result.MinRTT {
				result.MinRTT = rtt
			}
			if rtt > result.MaxRTT {
				result.MaxRTT = rtt
			}
		}
		result.AvgRTT = total / time.Duration(len(rtts))
	}

	if sent > 0 {
		result.PacketLoss = float64(sent-received) / float64(sent) * 100
	}

	return result
}

func (p *PingTraceCollector) runServer() {
	// 服务端模式：响应 ICMP Echo 请求
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("pingtrace server: listen failed: %v", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.stopCh:
			return
		default:
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}

			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}

			if msg.Type == ipv4.ICMPTypeEcho {
				// 回复 Echo
				echo, ok := msg.Body.(*icmp.Echo)
				if !ok {
					continue
				}

				reply := icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Code: 0,
					Body: &icmp.Echo{
						ID:   echo.ID,
						Seq:  echo.Seq,
						Data: echo.Data,
					},
				}

				replyBytes, err := reply.Marshal(nil)
				if err != nil {
					continue
				}

				conn.WriteTo(replyBytes, peer)
			}
		}
	}
}

// Stop 停止采集器
func (p *PingTraceCollector) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}

	close(p.stopCh)
	p.running = false
	log.Printf("pingtrace collector stopped")
}

// GetResult 获取追踪结果
func (p *PingTraceCollector) GetResult() *PingTraceResult {
	select {
	case result := <-p.results:
		return result
	default:
		return nil
	}
}

// Status 返回采集器状态
func (p *PingTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{
		"running": p.running,
		"type":    p.config.Type,
		"dst_ip":  p.config.DstIP,
	}
}

// FormatTracePath 格式化追踪路径
func FormatTracePath(result *PingTraceResult) string {
	if result == nil {
		return ""
	}

	output := fmt.Sprintf("Tracing route to %s:\n", result.DstIP)
	for i, hop := range result.Hops {
		if hop.Timeout {
			output += fmt.Sprintf("  %2d  *\n", i+1)
		} else {
			output += fmt.Sprintf("  %2d  %s  %v\n", i+1, hop.IP, hop.RTT)
		}
	}

	output += fmt.Sprintf("\nRound-trip: min/avg/max = %v/%v/%v, loss = %.1f%%",
		result.MinRTT, result.AvgRTT, result.MaxRTT, result.PacketLoss)

	return output
}
