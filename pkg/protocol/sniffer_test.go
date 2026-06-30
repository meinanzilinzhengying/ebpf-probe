package protocol

import (
	"testing"
)

func TestL7Sniffer_DetectHTTP(t *testing.T) {
	sniffer := NewL7Sniffer(nil)

	tests := []struct {
		name     string
		data     []byte
		srcPort  uint16
		dstPort  uint16
		expected L7Protocol
	}{
		{
			name:     "HTTP GET",
			data:     []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			srcPort:  12345,
			dstPort:  80,
			expected: L7ProtocolHTTP,
		},
		{
			name:     "HTTP POST",
			data:     []byte("POST /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			srcPort:  12345,
			dstPort:  8080,
			expected: L7ProtocolHTTP,
		},
		{
			name:     "HTTP Response",
			data:     []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"),
			srcPort:  80,
			dstPort:  12345,
			expected: L7ProtocolHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.DetectProtocol(tt.data, tt.srcPort, tt.dstPort)
			if result != tt.expected {
				t.Errorf("DetectProtocol() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestL7Sniffer_DetectRedis(t *testing.T) {
	sniffer := NewL7Sniffer(nil)

	tests := []struct {
		name     string
		data     []byte
		expected L7Protocol
	}{
		{
			name:     "Redis Array",
			data:     []byte("*3\r\n$3\r\nSET\r\n$5\r\nhello\r\n$5\r\nworld\r\n"),
			expected: L7ProtocolRedis,
		},
		{
			name:     "Redis Simple",
			data:     []byte("+OK\r\n"),
			expected: L7ProtocolRedis,
		},
		{
			name:     "Redis Integer",
			data:     []byte(":1\r\n"),
			expected: L7ProtocolRedis,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.DetectProtocol(tt.data, 0, PortRedis)
			if result != tt.expected {
				t.Errorf("DetectProtocol() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestL7Sniffer_DetectMySQL(t *testing.T) {
	sniffer := NewL7Sniffer(nil)

	tests := []struct {
		name     string
		data     []byte
		expected L7Protocol
	}{
		{
			name:     "MySQL Handshake",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x34, 0x34},
			expected: L7ProtocolMySQL,
		},
		{
			name:     "MySQL Query",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54},
			expected: L7ProtocolMySQL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.DetectProtocol(tt.data, 0, PortMySQL)
			if result != tt.expected {
				t.Errorf("DetectProtocol() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRedisParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Simple String",
			data:    []byte("+OK\r\n"),
			wantErr: false,
		},
		{
			name:    "Error",
			data:    []byte("-ERR unknown command\r\n"),
			wantErr: false,
		},
		{
			name:    "Integer",
			data:    []byte(":42\r\n"),
			wantErr: false,
		},
		{
			name:    "Bulk String",
			data:    []byte("$5\r\nhello\r\n"),
			wantErr: false,
		},
		{
			name:    "Null Bulk",
			data:    []byte("$-1\r\n"),
			wantErr: false,
		},
		{
			name:    "Array",
			data:    []byte("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRedisPacket(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRedisPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("ParseRedisPacket() returned nil")
			}
		})
	}
}

func TestMySQLParser_IsMySQLPacket(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid packet",
			data:     []byte{0x01, 0x00, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x01, 0x00},
			expected: false,
		},
		{
			name:     "Zero length",
			data:     []byte{0x00, 0x00, 0x00, 0x01},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMySQLPacket(tt.data)
			if result != tt.expected {
				t.Errorf("IsMySQLPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHTTPSParser_IsTLSRecord(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "TLS Handshake",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
			expected: true,
		},
		{
			name:     "TLS Application Data",
			data:     []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: true,
		},
		{
			name:     "Not TLS",
			data:     []byte{0x47, 0x45, 0x54, 0x20, 0x2f},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0x16, 0x03},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTLSRecord(tt.data)
			if result != tt.expected {
				t.Errorf("IsTLSRecord() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetProtocolName(t *testing.T) {
	tests := []struct {
		proto    L7Protocol
		expected string
	}{
		{L7ProtocolHTTP, "http"},
		{L7ProtocolMySQL, "mysql"},
		{L7ProtocolRedis, "redis"},
		{L7ProtocolKafka, "kafka"},
		{L7ProtocolDubbo, "dubbo"},
		{L7ProtocolNone, "unknown"},
	}

	for _, tt := range tests {
		result := GetProtocolName(tt.proto)
		if result != tt.expected {
			t.Errorf("GetProtocolName(%v) = %v, want %v", tt.proto, result, tt.expected)
		}
	}
}
