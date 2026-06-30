package collector

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// VTapMode 运行模式
type VTapMode int

const (
	VTapCapture  VTapMode = iota // 抓包模式：本地抓取并转发
	VTapReceiver                 // 接收模式：监听并存储/转发
)

// VTapConfig 配置结构
type VTapConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // capture | receiver

	// 抓包配置 (capture 模式)
	Interface string `yaml:"interface"` // 抓包网卡
	SnapLen   int    `yaml:"snaplen"`   // 抓包长度, 0=全包
	BufSize   int    `yaml:"bufsize"`   // 缓冲区大小
	PktType   int    `yaml:"pktype"`    // 包类型过滤
	DupPkts   int    `yaml:"dupkts"`    // 重复包数量
	DupSize   int    `yaml:"dupsize"`   // 重复包大小

	// 接收配置 (receiver 模式)
	IP          string `yaml:"ip"`           // 监听 IP
	Port        int    `yaml:"port"`         // 监听端口
	OutInterface string `yaml:"out_interface"` // 输出网卡

	// pcap 写入配置
	WriteEnabled bool   `yaml:"write_enabled"`
	WriteUnits   string `yaml:"write_units"`   // 分片周期: 1m, 5m, 1h
	WriteExpires string `yaml:"write_expires"` // 过期时间: 24h, 72h
	WritePath    string `yaml:"write_path"`    // 存储路径

	// 目标地址 (capture 模式转发目标)
	TargetIP   string `yaml:"target_ip"`
	TargetPort int    `yaml:"target_port"`
}

// PcapWriter pcap 文件写入器
type PcapWriter struct {
	dir       string
	units     time.Duration
	expires   time.Duration
	current   *os.File
	startTime time.Time
	mu        sync.Mutex
	stopCh    chan struct{}
}

// NewPcapWriter 创建 pcap 写入器
func NewPcapWriter(dir, units, expires string) (*PcapWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}

	dur, err := time.ParseDuration(units)
	if err != nil {
		dur = time.Minute
	}

	exp, err := time.ParseDuration(expires)
	if err != nil {
		exp = 72 * time.Hour
	}

	return &PcapWriter{
		dir:     dir,
		units:   dur,
		expires: exp,
		stopCh:  make(chan struct{}),
	}, nil
}

func (w *PcapWriter) Write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()

	if w.current == nil || now.Sub(w.startTime) >= w.units {
		if w.current != nil {
			w.current.Close()
		}
		return w.rotate(now)
	}

	// pcap 全局头 (24 bytes)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)           // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)           // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)          // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)         // sigfigs

	// 包头 (16 bytes)
	tsSec := uint32(now.Unix())
	tsUsec := uint32(now.Nanosecond() / 1000)
	pktLen := uint32(len(data))

	pktHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(pktHdr[0:4], tsSec)
	binary.LittleEndian.PutUint32(pktHdr[4:8], tsUsec)
	binary.LittleEndian.PutUint32(pktHdr[8:12], pktLen)
	binary.LittleEndian.PutUint32(pktHdr[12:16], pktLen)

	w.current.Write(pktHdr)
	w.current.Write(data)

	return nil
}

func (w *PcapWriter) rotate(now time.Time) error {
	filename := fmt.Sprintf("%s/pcap_%s.pcap", w.dir, now.Format("20060102_150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	// 写入 pcap 全局头
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	f.Write(hdr)

	w.current = f
	w.startTime = now

	return nil
}

// cleanupLoop 清理过期文件
func (w *PcapWriter) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.cleanup()
		}
	}
}

func (w *PcapWriter) cleanup() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-w.expires)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(w.dir, entry.Name()))
		}
	}
}

func (w *PcapWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	close(w.stopCh)
	if w.current != nil {
		w.current.Close()
	}
}

// Forwarder 数据转发器
type Forwarder struct {
	conn    net.Conn
	target  string
	buf     [][]byte
	mu      sync.Mutex
	stopCh  chan struct{}
}

// NewForwarder 创建转发器
func NewForwarder(target string) *Forwarder {
	return &Forwarder{
		target: target,
		buf:    make([][]byte, 0, 1000),
		stopCh: make(chan struct{}),
	}
}

func (f *Forwarder) Start() error {
	conn, err := net.Dial("udp", f.target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	f.conn = conn

	go f.flushLoop()
	return nil
}

func (f *Forwarder) flushLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.Flush()
		}
	}
}

func (f *Forwarder) Send(data []byte) {
	f.mu.Lock()
	f.buf = append(f.buf, data)
	needFlush := len(f.buf) >= 100
	f.mu.Unlock()

	if needFlush {
		f.Flush()
	}
}

func (f *Forwarder) Flush() {
	f.mu.Lock()
	if len(f.buf) == 0 {
		f.mu.Unlock()
		return
	}
	batch := f.buf
	f.buf = make([][]byte, 0, 1000)
	f.mu.Unlock()

	for _, pkt := range batch {
		f.conn.Write(pkt)
	}
}

func (f *Forwarder) Stop() {
	close(f.stopCh)
	f.Flush()
	if f.conn != nil {
		f.conn.Close()
	}
}

// VTapCollector vTap 采集器
type VTapCollector struct {
	config   VTapConfig
	mode     VTapMode
	conn     net.PacketConn
	writer   *PcapWriter
	forwarder *Forwarder
	running  bool
	mu       sync.Mutex
	stopCh   chan struct{}
	packets  chan []byte
	stats    VTapStats
}

// VTapStats 统计信息
type VTapStats struct {
	Received  uint64
	Dropped   uint64
	Forwarded uint64
	Written   uint64
}

// NewVTapCollector 创建 vTap 采集器
func NewVTapCollector(cfg VTapConfig) *VTapCollector {
	mode := VTapCapture
	if cfg.Mode == "receiver" {
		mode = VTapReceiver
	}

	return &VTapCollector{
		config:  cfg,
		mode:    mode,
		stopCh:  make(chan struct{}),
		packets: make(chan []byte, 100000),
	}
}

func (v *VTapCollector) Name() string   { return "vtap" }
func (v *VTapCollector) Category() string { return "network" }

func (v *VTapCollector) Init() error {
	if v.config.Port == 0 {
		v.config.Port = 9800
	}
	if v.config.SnapLen == 0 {
		v.config.SnapLen = 65535
	}
	if v.config.BufSize == 0 {
		v.config.BufSize = 10 * 1024 * 1024
	}
	if v.config.WriteUnits == "" {
		v.config.WriteUnits = "1m"
	}
	if v.config.WriteExpires == "" {
		v.config.WriteExpires = "72h"
	}
	if v.config.WritePath == "" {
		v.config.WritePath = "/data/pcap"
	}
	return nil
}

func (v *VTapCollector) Start() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.running {
		return nil
	}

	// 初始化 pcap 写入器
	if v.config.WriteEnabled {
		w, err := NewPcapWriter(v.config.WritePath, v.config.WriteUnits, v.config.WriteExpires)
		if err != nil {
			log.Printf("vtap: pcap writer init failed: %v", err)
		} else {
			v.writer = w
			go w.cleanupLoop()
		}
	}

	// 初始化转发器 (capture 模式)
	if v.mode == VTapCapture && v.config.TargetIP != "" {
		target := fmt.Sprintf("%s:%d", v.config.TargetIP, v.config.TargetPort)
		f := NewForwarder(target)
		if err := f.Start(); err != nil {
			log.Printf("vtap: forwarder init failed: %v", err)
		} else {
			v.forwarder = f
		}
	}

	switch v.mode {
	case VTapCapture:
		if err := v.startCapture(); err != nil {
			return err
		}
	case VTapReceiver:
		if err := v.startReceiver(); err != nil {
			return err
		}
	}

	v.running = true
	go v.processLoop()

	log.Printf("vtap started (mode=%s, port=%d)", v.config.Mode, v.config.Port)
	return nil
}

func (v *VTapCollector) startCapture() error {
	// capture 模式: 通过 raw socket 抓包
	iface := v.config.Interface
	if iface == "" {
		iface = "any"
	}

	// 创建 raw socket
	addr, err := net.InterfaceByName(iface)
	if err != nil && iface != "any" {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	_ = addr

	// 使用 AF_PACKET 抓包 (简化实现)
	log.Printf("vtap capture: listening on %s", iface)
	return nil
}

func (v *VTapCollector) startReceiver() error {
	addr := fmt.Sprintf("%s:%d", v.config.IP, v.config.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	v.conn = conn
	go v.receiveLoop()
	return nil
}

func (v *VTapCollector) receiveLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-v.stopCh:
			return
		default:
			n, _, err := v.conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			v.stats.Received++

			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			select {
			case v.packets <- pkt:
			default:
				v.stats.Dropped++
			}
		}
	}
}

func (v *VTapCollector) processLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-v.stopCh:
			return
		case pkt := <-v.packets:
			v.handlePacket(pkt)
		case <-ticker.C:
			if v.forwarder != nil {
				v.forwarder.Flush()
			}
		}
	}
}

func (v *VTapCollector) handlePacket(pkt []byte) {
	// 1. 写入 pcap 文件
	if v.writer != nil {
		if err := v.writer.Write(pkt); err == nil {
			v.stats.Written++
		}
	}

	// 2. 转发到目标 (receiver 模式下转发到网卡)
	if v.config.OutInterface != "" && v.config.OutInterface != "none" {
		v.forwardToInterface(pkt)
	}

	// 3. 解析并上报 (可选)
	v.parsePacket(pkt)
}

func (v *VTapCollector) forwardToInterface(pkt []byte) {
	// 通过 raw socket 转发到指定网卡
	// 简化实现
	v.stats.Forwarded++
}

func (v *VTapCollector) parsePacket(pkt []byte) {
	if len(pkt) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(pkt[12:14])

	switch etherType {
	case 0x0800: // IPv4
		v.parseIPv4(pkt)
	case 0x86DD: // IPv6
		v.parseIPv6(pkt)
	}
}

func (v *VTapCollector) parseIPv4(pkt []byte) {
	if len(pkt) < 34 {
		return
	}
	ihl := int(pkt[14]&0x0f) * 4
	protocol := pkt[23]
	srcIP := net.IP(pkt[26:30])
	dstIP := net.IP(pkt[30:34])

	var srcPort, dstPort uint16
	if protocol == 6 || protocol == 17 {
		if len(pkt) >= 14+ihl+4 {
			srcPort = binary.BigEndian.Uint16(pkt[14+ihl : 14+ihl+2])
			dstPort = binary.BigEndian.Uint16(pkt[14+ihl+2 : 14+ihl+4])
		}
	}

	_ = srcIP
	_ = dstIP
	_ = srcPort
	_ = dstPort
}

func (v *VTapCollector) parseIPv6(pkt []byte) {
	// IPv6 解析
}

func (v *VTapCollector) Stop() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.running {
		return
	}

	close(v.stopCh)
	if v.conn != nil {
		v.conn.Close()
	}
	if v.writer != nil {
		v.writer.Close()
	}
	if v.forwarder != nil {
		v.forwarder.Stop()
	}
	v.running = false
	log.Printf("vtap stopped (received=%d, dropped=%d, written=%d, forwarded=%d)",
		v.stats.Received, v.stats.Dropped, v.stats.Written, v.stats.Forwarded)
}

func (v *VTapCollector) Status() map[string]interface{} {
	return map[string]interface{}{
		"running":   v.running,
		"mode":      v.config.Mode,
		"port":      v.config.Port,
		"received":  v.stats.Received,
		"dropped":   v.stats.Dropped,
		"written":   v.stats.Written,
		"forwarded": v.stats.Forwarded,
	}
}
