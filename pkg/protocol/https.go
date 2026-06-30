// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// TLS 版本
type TLSVersion uint16

const (
	TLSVersionSSL30  TLSVersion = 0x0300
	TLSVersionTLS10  TLSVersion = 0x0301
	TLSVersionTLS11  TLSVersion = 0x0302
	TLSVersionTLS12  TLSVersion = 0x0303
	TLSVersionTLS13  TLSVersion = 0x0304
)

// TLS 版本名称映射
var tlsVersionNames = map[TLSVersion]string{
	TLSVersionSSL30: "SSLv3.0",
	TLSVersionTLS10: "TLSv1.0",
	TLSVersionTLS11: "TLSv1.1",
	TLSVersionTLS12: "TLSv1.2",
	TLSVersionTLS13: "TLSv1.3",
}

// TLS 记录类型
type TLSContentType uint8

const (
	TLSContentTypeChangeCipherSpec TLSContentType = 20
	TLSContentTypeAlert            TLSContentType = 21
	TLSContentTypeHandshake        TLSContentType = 22
	TLSContentTypeApplicationData  TLSContentType = 23
)

// TLS 握手消息类型
type TLSHandshakeType uint8

const (
	TLSHandshakeClientHello       TLSHandshakeType = 1
	TLSHandshakeServerHello       TLSHandshakeType = 2
	TLSHandshakeCertificate       TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerHelloDone   TLSHandshakeType = 14
	TLSHandshakeCertificateVerify TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange TLSHandshakeType = 16
	TLSHandshakeFinished          TLSHandshakeType = 20
)

// TLS 握手消息类型名称
var tlsHandshakeTypeNames = map[TLSHandshakeType]string{
	TLSHandshakeClientHello:        "ClientHello",
	TLSHandshakeServerHello:        "ServerHello",
	TLSHandshakeCertificate:        "Certificate",
	TLSHandshakeServerKeyExchange:  "ServerKeyExchange",
	TLSHandshakeCertificateRequest: "CertificateRequest",
	TLSHandshakeServerHelloDone:    "ServerHelloDone",
	TLSHandshakeCertificateVerify:  "CertificateVerify",
	TLSHandshakeClientKeyExchange:  "ClientKeyExchange",
	TLSHandshakeFinished:           "Finished",
}

// TLS 扩展类型
type TLSExtensionType uint16

const (
	TLSExtensionServerName         TLSExtensionType = 0x0000
	TLSExtensionMaxFragmentLength  TLSExtensionType = 0x0001
	TLSExtensionClientCertificateURL TLSExtensionType = 0x0002
	TLSExtensionTrustedCAKeys      TLSExtensionType = 0x0003
	TLSExtensionStatusRequest      TLSExtensionType = 0x0005
	TLSExtensionSupportedGroups   TLSExtensionType = 0x000a
	TLSExtensionECPointFormats     TLSExtensionType = 0x000b
	TLSExtensionSignatureAlgorithms TLSExtensionType = 0x000d
	TLSExtensionApplicationLayerProtocolNegotiation TLSExtensionType = 0x0010
	TLSExtensionSignedCertificateTimestamp TLSExtensionType = 0x0012
	TLSExtensionSessionTicket      TLSExtensionType = 0x0023
	TLSExtensionKeyShare           TLSExtensionType = 0x0033
	TLSExtensionPSKKeyExchangeModes TLSExtensionType = 0x0044
	TLSExtensionSupportedVersions TLSExtensionType = 0x002b
)

// TLS 握手记录
type TLSRecord struct {
	ContentType TLSContentType
	Version     TLSVersion
	Length      uint16
	Data        []byte
}

// TLS ClientHello
type TLSClientHello struct {
	Version        TLSVersion
	Random         [32]byte
	SessionID      []byte
	CipherSuites   []uint16
	CompressionMethods []uint8
	Extensions     []TLSExtension
	ServerName     string
	ALPNProtocols  []string
}

// TLS ServerHello
type TLSServerHello struct {
	Version         TLSVersion
	Random          [32]byte
	SessionID       []byte
	CipherSuite     uint16
	CompressionMethod uint8
	Extensions      []TLSExtension
	ALPNProtocol    string
}

// TLS 扩展
type TLSExtension struct {
	Type   TLSExtensionType
	Length uint16
	Data   []byte
}

// TLSEvent 事件结构体
type TLSHandshakeEvent struct {
	TimestampNS uint64
	PID         uint32
	EventType   uint8  // 0=handshake, 1=read, 2=write
	Version     TLSVersion
	ServerName  string
	CipherSuite uint16
	ALPNProtocol string
}

// TLS 数据事件
type TLSDataEvent struct {
	TimestampNS uint64
	PID         uint32
	EventType   uint8  // 1=read, 2=write
	DataLen     uint32
	Data        []byte
}

// ParseTLSRecord 解析 TLS 记录
func ParseTLSRecord(data []byte) (*TLSRecord, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record")
	}

	record := &TLSRecord{
		ContentType: TLSContentType(data[0]),
		Version:     TLSVersion(binary.BigEndian.Uint16(data[1:3])),
		Length:      binary.BigEndian.Uint16(data[3:5]),
	}

	if len(data) < 5+int(record.Length) {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	record.Data = data[5 : 5+record.Length]

	return record, nil
}

// ParseTLSClientHello 解析 TLS ClientHello
func ParseTLSClientHello(data []byte) (*TLSClientHello, error) {
	if len(data) < 43 { // 2+32+1+2+1+2 最小长度
		return nil, fmt.Errorf("data too short for ClientHello")
	}

	hello := &TLSClientHello{
		Version: TLSVersion(binary.BigEndian.Uint16(data[0:2])),
	}

	// Random (32 bytes)
	copy(hello.Random[:], data[2:34])

	// Session ID
	sessionIDLen := int(data[34])
	if len(data) < 35+sessionIDLen {
		return nil, fmt.Errorf("incomplete session ID")
	}
	hello.SessionID = data[35 : 35+sessionIDLen]

	// Cipher Suites
	offset := 35 + sessionIDLen
	if len(data) < offset+2 {
		return nil, fmt.Errorf("incomplete cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+cipherSuitesLen {
		return nil, fmt.Errorf("incomplete cipher suites data")
	}
	hello.CipherSuites = make([]uint16, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen; i += 2 {
		hello.CipherSuites[i/2] = binary.BigEndian.Uint16(data[offset+i : offset+i+2])
	}
	offset += cipherSuitesLen

	// Compression Methods
	if len(data) < offset+1 {
		return nil, fmt.Errorf("incomplete compression methods")
	}
	compressionMethodsLen := int(data[offset])
	offset++

	if len(data) < offset+compressionMethodsLen {
		return nil, fmt.Errorf("incomplete compression methods data")
	}
	hello.CompressionMethods = data[offset : offset+compressionMethodsLen]
	offset += compressionMethodsLen

	// Extensions
	if offset < len(data) {
		if len(data) < offset+2 {
			return nil, fmt.Errorf("incomplete extensions length")
		}
		extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if len(data) < offset+extensionsLen {
			return nil, fmt.Errorf("incomplete extensions data")
		}

		hello.Extensions, _ = parseTLSExtensions(data[offset : offset+extensionsLen])

		// 解析 Server Name 扩展
		for _, ext := range hello.Extensions {
			if ext.Type == TLSExtensionServerName {
				hello.ServerName = parseServerNameExtension(ext.Data)
			}
			if ext.Type == TLSExtensionApplicationLayerProtocolNegotiation {
				hello.ALPNProtocols = parseALPNExtension(ext.Data)
			}
		}
	}

	return hello, nil
}

// parseTLSExtensions 解析 TLS 扩展
func parseTLSExtensions(data []byte) ([]TLSExtension, error) {
	var extensions []TLSExtension
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		ext := TLSExtension{
			Type:   TLSExtensionType(binary.BigEndian.Uint16(data[offset : offset+2])),
			Length: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4

		if offset+int(ext.Length) > len(data) {
			break
		}

		ext.Data = data[offset : offset+int(ext.Length)]
		offset += int(ext.Length)

		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// parseServerNameExtension 解析 Server Name 扩展
func parseServerNameExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Server Name List Length
	_ = binary.BigEndian.Uint16(data[0:2])

	// Server Name Type
	nameType := data[2]

	// 只处理 host_name 类型
	if nameType != 0 {
		return ""
	}

	// Server Name Length
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))

	if len(data) < 5+nameLen {
		return ""
	}

	return string(data[5 : 5+nameLen])
}

// parseALPNExtension 解析 ALPN 扩展
func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	// Protocol List Length
	_ = binary.BigEndian.Uint16(data[0:2])

	var protocols []string
	offset := 2

	for offset < len(data) {
		if offset >= len(data) {
			break
		}

		// Protocol Length
		protoLen := int(data[offset])
		offset++

		if offset+protoLen > len(data) {
			break
		}

		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}

	return protocols
}

// GetTLSVersionName 获取 TLS 版本名称
func GetTLSVersionName(version TLSVersion) string {
	if name, ok := tlsVersionNames[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(version))
}

// GetTLSHandshakeTypeName 获取 TLS 握手类型名称
func GetTLSHandshakeTypeName(handshakeType TLSHandshakeType) string {
	if name, ok := tlsHandshakeTypeNames[handshakeType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", uint8(handshakeType))
}

// IsTLSRecord 检查是否是 TLS 记录
func IsTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	contentType := TLSContentType(data[0])
	version := TLSVersion(binary.BigEndian.Uint16(data[1:3]))

	// 检查内容类型
	if contentType != TLSContentTypeHandshake && contentType != TLSContentTypeApplicationData &&
		contentType != TLSContentTypeChangeCipherSpec && contentType != TLSContentTypeAlert {
		return false
	}

	// 检查版本
	_, ok := tlsVersionNames[version]
	return ok
}

// GetTLSInfo 从 TLS 数据中提取信息
func GetTLSInfo(data []byte) (string, TLSVersion, string) {
	if !IsTLSRecord(data) {
		return "", 0, ""
	}

	record, err := ParseTLSRecord(data)
	if err != nil {
		return "", 0, ""
	}

	version := record.Version
	versionName := GetTLSVersionName(version)

	// 如果是握手记录，尝试解析 ClientHello
	if record.ContentType == TLSContentTypeHandshake && len(record.Data) > 0 {
		handshakeType := TLSHandshakeType(record.Data[0])
		handshakeName := GetTLSHandshakeTypeName(handshakeType)

		if handshakeType == TLSHandshakeClientHello && len(record.Data) > 1 {
			hello, err := ParseTLSClientHello(record.Data[1:])
			if err == nil && hello.ServerName != "" {
				return handshakeName, version, hello.ServerName
			}
			return handshakeName, version, ""
		}

		return handshakeName, version, ""
	}

	return "", version, ""
}

// CheckHTTPOverTLS 检查是否是 HTTP over TLS
func CheckHTTPOverTLS(data []byte) bool {
	if !IsTLSRecord(data) {
		return false
	}

	record, err := ParseTLSRecord(data)
	if err != nil {
		return false
	}

	// 检查是否是 Application Data
	if record.ContentType == TLSContentTypeApplicationData {
		return true
	}

	// 检查是否是 ClientHello（可能包含 ALPN）
	if record.ContentType == TLSContentTypeHandshake && len(record.Data) > 0 {
		handshakeType := TLSHandshakeType(record.Data[0])
		if handshakeType == TLSHandshakeClientHello {
			hello, err := ParseTLSClientHello(record.Data[1:])
			if err == nil {
				for _, proto := range hello.ALPNProtocols {
					if strings.HasPrefix(proto, "http") {
						return true
					}
				}
			}
		}
	}

	return false
}
