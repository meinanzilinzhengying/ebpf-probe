// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
)

// Dubbo 协议常量
const (
	DubboMagic           = 0xdabb
	DubboHeaderLength    = 16
	DubboMaxBodyLength   = 8 * 1024 * 1024 // 8MB
)

// Dubbo 请求状态
type DubboStatus uint8

const (
	DubboStatusOK           DubboStatus = 20
	DubboStatusClientTimeout DubboStatus = 30
	DubboStatusServerTimeout DubboStatus = 31
	DubboStatusBadRequest   DubboStatus = 40
	DubboStatusBadResponse  DubboStatus = 50
	DubboStatusServiceNotFound DubboStatus = 60
	DubboStatusServiceError DubboStatus = 70
	DubboStatusServerError  DubboStatus = 80
	DubboStatusClientError  DubboStatus = 90
)

// Dubbo 状态名称
var dubboStatusNames = map[DubboStatus]string{
	DubboStatusOK:               "OK",
	DubboStatusClientTimeout:    "CLIENT_TIMEOUT",
	DubboStatusServerTimeout:    "SERVER_TIMEOUT",
	DubboStatusBadRequest:       "BAD_REQUEST",
	DubboStatusBadResponse:      "BAD_RESPONSE",
	DubboStatusServiceNotFound:  "SERVICE_NOT_FOUND",
	DubboStatusServiceError:     "SERVICE_ERROR",
	DubboStatusServerError:      "SERVER_ERROR",
	DubboStatusClientError:      "CLIENT_ERROR",
}

// Dubbo 序列化类型
type DubboSerializationType uint8

const (
	DubboSerializationHessian2 DubboSerializationType = 2
	DubboSerializationJson     DubboSerializationType = 6
	DubboSerializationProtobuf DubboSerializationType = 12
)

// Dubbo 消息类型
type DubboMessageType uint8

const (
	DubboMessageRequest  DubboMessageType = 1
	DubboMessageResponse DubboMessageType = 2
)

// Dubbo 事件类型
type DubboEventType uint8

const (
	DubboEventResponse DubboEventType = 0
	DubboEventBinary   DubboEventType = 1
	DubboEventEvent    DubboEventType = 2
	DubboEventTwoWay   DubboEventType = 4
)

// Dubbo 协议头
type DubboProtocolHeader struct {
	Magic           uint16
	Flags           uint8
	Status          DubboStatus
	Serialization   DubboSerializationType
	MessageType     DubboMessageType
	EventType       DubboEventType
	IsTwoWay        bool
	IsEvent         bool
	BodyLength      int32
	RequestID       int64
}

// Dubbo 请求
type DubboRequest struct {
	Header    DubboProtocolHeader
	ServiceName string
	MethodName string
	ParameterTypes []string
	Arguments  []interface{}
	Attachments map[string]string
}

// Dubbo 响应
type DubboResponse struct {
	Header    DubboProtocolHeader
	Result    interface{}
	ErrorMessage string
	Attachments map[string]string
}

// Dubbo 事件
type DubboEvent struct {
	TimestampNS  uint64
	PID          uint32
	ServiceName  string
	MethodName   string
	Status       DubboStatus
	LatencyNS    uint64
	IsError      bool
	ErrorMessage string
}

// ParseDubboProtocolHeader 解析 Dubbo 协议头
func ParseDubboProtocolHeader(data []byte) (*DubboProtocolHeader, error) {
	if len(data) < DubboHeaderLength {
		return nil, fmt.Errorf("data too short for Dubbo header")
	}

	header := &DubboProtocolHeader{}

	// Magic number (2 bytes)
	header.Magic = binary.BigEndian.Uint16(data[0:2])
	if header.Magic != DubboMagic {
		return nil, fmt.Errorf("invalid Dubbo magic number: 0x%04x", header.Magic)
	}

	// Flags (1 byte)
	header.Flags = data[2]

	// 解析标志位
	header.MessageType = DubboMessageType((header.Flags >> 5) & 0x01)
	header.IsTwoWay = header.Flags&0x20 != 0
	header.IsEvent = header.Flags&0x10 != 0

	// Status (1 byte) - 只在响应中有效
	header.Status = DubboStatus(data[3])

	// 检查是否是响应
	if header.MessageType == DubboMessageResponse {
		// 响应的状态码在 data[3]
		header.Status = DubboStatus(data[3])
	} else {
		// 请求的状态码在 data[3]
		header.Status = DubboStatus(data[3])
	}

	// Serialization type (从标志位中提取)
	header.Serialization = DubboSerializationType(data[2] & 0x1f)

	// Request ID (8 bytes)
	header.RequestID = int64(binary.BigEndian.Uint64(data[4:12]))

	// Body length (4 bytes)
	header.BodyLength = int32(binary.BigEndian.Uint32(data[12:16]))

	// 验证 body 长度
	if header.BodyLength < 0 || header.BodyLength > DubboMaxBodyLength {
		return nil, fmt.Errorf("invalid body length: %d", header.BodyLength)
	}

	return header, nil
}

// ParseDubboRequest 解析 Dubbo 请求
func ParseDubboRequest(data []byte) (*DubboRequest, error) {
	if len(data) < DubboHeaderLength {
		return nil, fmt.Errorf("data too short for Dubbo request")
	}

	header, err := ParseDubboProtocolHeader(data)
	if err != nil {
		return nil, err
	}

	request := &DubboRequest{
		Header: *header,
	}

	// 如果是事件消息，不需要解析 body
	if header.IsEvent {
		return request, nil
	}

	// 解析 body（根据序列化类型不同而不同）
	// 这里只解析基础结构
	if len(data) > DubboHeaderLength {
		body := data[DubboHeaderLength:]
		_ = body // 实际解析需要根据序列化类型实现
	}

	return request, nil
}

// ParseDubboResponse 解析 Dubbo 响应
func ParseDubboResponse(data []byte) (*DubboResponse, error) {
	if len(data) < DubboHeaderLength {
		return nil, fmt.Errorf("data too short for Dubbo response")
	}

	header, err := ParseDubboProtocolHeader(data)
	if err != nil {
		return nil, err
	}

	response := &DubboResponse{
		Header: *header,
	}

	// 如果是事件消息，不需要解析 body
	if header.IsEvent {
		return response, nil
	}

	// 解析 body（根据序列化类型不同而不同）
	// 这里只解析基础结构
	if len(data) > DubboHeaderLength {
		body := data[DubboHeaderLength:]
		_ = body // 实际解析需要根据序列化类型实现
	}

	return response, nil
}

// GetDubboStatusName 获取 Dubbo 状态名称
func GetDubboStatusName(status DubboStatus) string {
	if name, ok := dubboStatusNames[status]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(status))
}

// GetDubboMessageTypeName 获取 Dubbo 消息类型名称
func GetDubboMessageTypeName(msgType DubboMessageType) string {
	switch msgType {
	case DubboMessageRequest:
		return "Request"
	case DubboMessageResponse:
		return "Response"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(msgType))
	}
}

// GetDubboSerializationName 获取 Dubbo 序列化类型名称
func GetDubboSerializationName(serialization DubboSerializationType) string {
	switch serialization {
	case DubboSerializationHessian2:
		return "Hessian2"
	case DubboSerializationJson:
		return "JSON"
	case DubboSerializationProtobuf:
		return "Protobuf"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(serialization))
	}
}

// IsDubboPacket 检查是否是 Dubbo 协议包
func IsDubboPacket(data []byte) bool {
	if len(data) < DubboHeaderLength {
		return false
	}

	// 检查 magic number
	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != DubboMagic {
		return false
	}

	// 检查 flags
	flags := data[2]
	msgType := (flags >> 5) & 0x01
	if msgType > 1 {
		return false
	}

	// 检查 body 长度
	bodyLength := int32(binary.BigEndian.Uint32(data[12:16]))
	if bodyLength < 0 || bodyLength > DubboMaxBodyLength {
		return false
	}

	return true
}

// DubboInvocation Dubbo 调用信息
type DubboInvocation struct {
	ServiceName    string
	MethodName     string
	ParameterTypes []string
	Arguments      []interface{}
	Attachments    map[string]string
}

// Hessian2Decoder Hessian2 解码器（简化版）
type Hessian2Decoder struct {
	data   []byte
	offset int
}

// NewHessian2Decoder 创建 Hessian2 解码器
func NewHessian2Decoder(data []byte) *Hessian2Decoder {
	return &Hessian2Decoder{
		data:   data,
		offset: 0,
	}
}

// ReadByte 读取一个字节
func (d *Hessian2Decoder) ReadByte() (byte, error) {
	if d.offset >= len(d.data) {
		return 0, fmt.Errorf("end of data")
	}
	b := d.data[d.offset]
	d.offset++
	return b, nil
}

// ReadInt32 读取一个 32 位整数
func (d *Hessian2Decoder) ReadInt32() (int32, error) {
	if d.offset+4 > len(d.data) {
		return 0, fmt.Errorf("not enough data for int32")
	}
	value := int32(binary.BigEndian.Uint32(d.data[d.offset : d.offset+4]))
	d.offset += 4
	return value, nil
}

// ReadInt64 读取一个 64 位整数
func (d *Hessian2Decoder) ReadInt64() (int64, error) {
	if d.offset+8 > len(d.data) {
		return 0, fmt.Errorf("not enough data for int64")
	}
	value := int64(binary.BigEndian.Uint64(d.data[d.offset : d.offset+8]))
	d.offset += 8
	return value, nil
}

// ReadString 读取一个字符串
func (d *Hessian2Decoder) ReadString() (string, error) {
	if d.offset >= len(d.data) {
		return "", fmt.Errorf("end of data")
	}

	// 读取长度
	length, err := d.ReadInt32()
	if err != nil {
		return "", err
	}

	if length < 0 {
		return "", fmt.Errorf("invalid string length")
	}

	// 读取字符串数据
	if d.offset+int(length) > len(d.data) {
		return "", fmt.Errorf("not enough data for string")
	}

	value := string(d.data[d.offset : d.offset+int(length)])
	d.offset += int(length)

	return value, nil
}
