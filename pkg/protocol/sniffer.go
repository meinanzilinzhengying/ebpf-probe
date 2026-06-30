// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// L7 协议类型
type L7Protocol int

const (
	L7ProtocolNone   L7Protocol = iota
	L7ProtocolHTTP              // HTTP/1.0, HTTP/1.1
	L7ProtocolHTTPS             // HTTPS
	L7ProtocolHTTP2             // HTTP/2
	L7ProtocolMySQL             // MySQL
	L7ProtocolRedis             // Redis
	L7ProtocolKafka             // Kafka
	L7ProtocolDubbo             // Apache Dubbo
	L7ProtocolDNS               // DNS (UDP)
)

// 协议名称映射
var protocolNames = map[L7Protocol]string{
	L7ProtocolNone:   "unknown",
	L7ProtocolHTTP:   "http",
	L7ProtocolHTTPS:  "https",
	L7ProtocolHTTP2:  "http2",
	L7ProtocolMySQL:  "mysql",
	L7ProtocolRedis:  "redis",
	L7ProtocolKafka:  "kafka",
	L7ProtocolDubbo:  "dubbo",
	L7ProtocolDNS:    "dns",
}

// 端口号常量
const (
	PortHTTP      = 80
	PortHTTPS     = 443
	PortHTTPAlt   = 8080
	PortMySQL     = 3306
	PortRedis     = 6379
	PortKafka     = 9092
	PortDubbo     = 20880
	PortDNS       = 53
)

// MySQL 协议常量
const (
	MySQLPacketHeaderSize = 4
	MySQLMagicByte        = 0x00
	MySQLQueryCommand     = 0x03
	MySQLHandshakeV10     = 0x0a
)

// Redis 协议常量
const (
	RespArray   = '*'
	RespBulk    = '$'
	RespSimple  = '+'
	RespError   = '-'
	RespInteger = ':'
)

// Kafka 协议常量
const (
	KafkaProduceAPIKey   = 0
	KafkaFetchAPIKey     = 1
	KafkaMetadataAPIKey  = 3
	KafkaMaxAPIKey       = 62
)

// Dubbo 协议常量
const (
	DubboMagic = 0xdabb
)

// L7Sniffer L7 协议嗅探器
type L7Sniffer struct {
	portOverride map[uint16]L7Protocol
}

// NewL7Sniffer 创建 L7 协议嗅探器
func NewL7Sniffer(portOverride map[uint16]L7Protocol) *L7Sniffer {
	if portOverride == nil {
		portOverride = make(map[uint16]L7Protocol)
	}

	return &L7Sniffer{
		portOverride: portOverride,
	}
}

// DetectProtocol 检测 L7 协议类型
func (s *L7Sniffer) DetectProtocol(data []byte, srcPort, dstPort uint16) L7Protocol {
	if len(data) < 4 {
		return L7ProtocolNone
	}

	// 检查端口覆盖配置
	if proto, ok := s.portOverride[dstPort]; ok {
		return proto
	}
	if proto, ok := s.portOverride[srcPort]; ok {
		return proto
	}

	// 根据端口号预分类
	proto := s.detectByPort(srcPort, dstPort)
	if proto != L7ProtocolNone {
		// 验证协议特征
		if s.verifyProtocol(data, proto) {
			return proto
		}
	}

	// 特征检测
	return s.detectByPayload(data)
}

// detectByPort 根据端口号检测协议
func (s *L7Sniffer) detectByPort(srcPort, dstPort uint16) L7Protocol {
	// HTTP/HTTPS
	if dstPort == PortHTTP || dstPort == PortHTTPS || dstPort == PortHTTPAlt {
		return L7ProtocolHTTP
	}
	if srcPort == PortHTTP || srcPort == PortHTTPS || srcPort == PortHTTPAlt {
		return L7ProtocolHTTP
	}

	// MySQL
	if dstPort == PortMySQL || srcPort == PortMySQL {
		return L7ProtocolMySQL
	}

	// Redis
	if dstPort == PortRedis || srcPort == PortRedis {
		return L7ProtocolRedis
	}

	// Kafka
	if dstPort == PortKafka || srcPort == PortKafka {
		return L7ProtocolKafka
	}

	// Dubbo
	if dstPort == PortDubbo || srcPort == PortDubbo {
		return L7ProtocolDubbo
	}

	// DNS
	if dstPort == PortDNS || srcPort == PortDNS {
		return L7ProtocolDNS
	}

	return L7ProtocolNone
}

// verifyProtocol 验证协议特征
func (s *L7Sniffer) verifyProtocol(data []byte, proto L7Protocol) bool {
	switch proto {
	case L7ProtocolHTTP:
		return s.verifyHTTP(data)
	case L7ProtocolMySQL:
		return s.verifyMySQL(data)
	case L7ProtocolRedis:
		return s.verifyRedis(data)
	case L7ProtocolKafka:
		return s.verifyKafka(data)
	case L7ProtocolDubbo:
		return s.verifyDubbo(data)
	case L7ProtocolDNS:
		return s.verifyDNS(data)
	default:
		return false
	}
}

// verifyHTTP 验证 HTTP 协议
func (s *L7Sniffer) verifyHTTP(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// HTTP 请求方法
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
	for _, method := range methods {
		if len(data) >= len(method) && string(data[:len(method)]) == method {
			// 检查后面是否是空格
			if len(data) > len(method) && data[len(method)] == ' ' {
				return true
			}
		}
	}

	// HTTP 响应
	if len(data) >= 4 && string(data[:4]) == "HTTP" {
		return true
	}

	return false
}

// verifyMySQL 验证 MySQL 协议
func (s *L7Sniffer) verifyMySQL(data []byte) bool {
	if len(data) < MySQLPacketHeaderSize {
		return false
	}

	// MySQL 握手包
	if data[0] == MySQLMagicByte && data[4] == MySQLHandshakeV10 {
		return true
	}

	// MySQL 查询包
	if data[0] == MySQLQueryCommand {
		return true
	}

	// MySQL OK 包
	if data[0] == 0x00 && len(data) > 1 {
		// 检查是否有受影响行数
		return true
	}

	// MySQL EOF 包
	if data[0] == 0xfe && len(data) == 5 {
		return true
	}

	return false
}

// verifyRedis 验证 Redis 协议
func (s *L7Sniffer) verifyRedis(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// RESP 协议
	switch data[0] {
	case RespArray, RespBulk, RespSimple, RespError, RespInteger:
		return true
	}

	// Inline 命令（简单检测）
	if len(data) >= 3 {
		cmd := strings.ToUpper(string(data[:3]))
		if cmd == "GET" || cmd == "SET" || cmd == "DEL" || cmd == "PING" {
			return true
		}
	}

	return false
}

// verifyKafka 验证 Kafka 协议
func (s *L7Sniffer) verifyKafka(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Kafka 请求/响应格式
	// 请求: [4字节长度][2字节API Key][2字节API Version]...
	// 响应: [4字节长度][2字节Correlation ID]...
	length := binary.BigEndian.Uint32(data[:4])
	if length > 0 && length < 1048576 { // 1MB 合理范围
		return true
	}

	return false
}

// verifyDubbo 验证 Dubbo 协议
func (s *L7Sniffer) verifyDubbo(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// Dubbo 魔数
	magic := binary.BigEndian.Uint16(data[:2])
	if magic == DubboMagic {
		return true
	}

	return false
}

// verifyDNS 验证 DNS 协议
func (s *L7Sniffer) verifyDNS(data []byte) bool {
	if len(data) < 12 {
		return false
	}

	// DNS 报文头
	// Transaction ID (2 bytes)
	// Flags (2 bytes)
	// Questions (2 bytes)
	// Answer RRs (2 bytes)
	// Authority RRs (2 bytes)
	// Additional RRs (2 bytes)

	questions := binary.BigEndian.Uint16(data[4:6])
	answers := binary.BigEndian.Uint16(data[6:8])

	// 合理的问答数量
	if questions < 100 && answers < 100 {
		return true
	}

	return false
}

// detectByPayload 根据载荷特征检测协议
func (s *L7Sniffer) detectByPayload(data []byte) L7Protocol {
	// HTTP 响应
	if len(data) >= 4 && string(data[:4]) == "HTTP" {
		return L7ProtocolHTTP
	}

	// MySQL 协议
	if len(data) >= 4 {
		// MySQL 握手包特征
		if data[0] == MySQLMagicByte {
			return L7ProtocolMySQL
		}
		// MySQL 查询包特征
		if data[0] == MySQLQueryCommand {
			return L7ProtocolMySQL
		}
	}

	// Redis 协议
	if len(data) >= 1 {
		switch data[0] {
		case RespArray, RespBulk, RespSimple, RespError, RespInteger:
			return L7ProtocolRedis
		}
	}

	// Dubbo 协议
	if len(data) >= 2 {
		magic := binary.BigEndian.Uint16(data[:2])
		if magic == DubboMagic {
			return L7ProtocolDubbo
		}
	}

	// DNS 协议
	if len(data) >= 12 {
		questions := binary.BigEndian.Uint16(data[4:6])
		answers := binary.BigEndian.Uint16(data[6:8])
		if questions < 100 && answers < 100 {
			return L7ProtocolDNS
		}
	}

	return L7ProtocolNone
}

// GetProtocolName 获取协议名称
func GetProtocolName(proto L7Protocol) string {
	if name, ok := protocolNames[proto]; ok {
		return name
	}
	return "unknown"
}

// ParseL7Event 解析 L7 事件数据
func ParseL7Event(data []byte, proto L7Protocol) (interface{}, error) {
	switch proto {
	case L7ProtocolHTTP:
		return ParseHTTPRequest(data)
	case L7ProtocolMySQL:
		return ParseMySQLPacket(data)
	case L7ProtocolRedis:
		return ParseRedisPacket(data)
	case L7ProtocolKafka:
		return ParseKafkaPacket(data)
	case L7ProtocolDubbo:
		return ParseDubboPacket(data)
	case L7ProtocolDNS:
		return ParseDNSPacket(data, 0, 0, 0, 0, 0)
	default:
		return nil, fmt.Errorf("unsupported protocol: %v", proto)
	}
}
