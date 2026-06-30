// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
)

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

// HTTP/2 帧类型名称
var http2FrameTypeNames = map[HTTP2FrameType]string{
	HTTP2FrameData:         "DATA",
	HTTP2FrameHeaders:      "HEADERS",
	HTTP2FramePriority:     "PRIORITY",
	HTTP2FrameRstStream:    "RST_STREAM",
	HTTP2FrameSettings:     "SETTINGS",
	HTTP2FramePushPromise:  "PUSH_PROMISE",
	HTTP2FramePing:         "PING",
	HTTP2FrameGoAway:       "GOAWAY",
	HTTP2FrameWindowUpdate: "WINDOW_UPDATE",
	HTTP2FrameContinuation: "CONTINUATION",
}

// HTTP/2 帧标志
type HTTP2FrameFlags uint8

const (
	HTTP2FlagEndStream  HTTP2FrameFlags = 0x1
	HTTP2FlagEndHeaders HTTP2FrameFlags = 0x4
	HTTP2FlagPadded     HTTP2FrameFlags = 0x8
	HTTP2FlagPriority   HTTP2FrameFlags = 0x20
)

// HTTP/2 SETTINGS 参数
type HTTP2SettingID uint16

const (
	HTTP2SettingsHeaderTableSize      HTTP2SettingID = 0x1
	HTTP2SettingsEnablePush           HTTP2SettingID = 0x2
	HTTP2SettingsMaxConcurrentStreams HTTP2SettingID = 0x3
	HTTP2SettingsInitialWindowSize    HTTP2SettingID = 0x4
	HTTP2SettingsMaxFrameSize         HTTP2SettingID = 0x5
	HTTP2SettingsMaxHeaderListSize    HTTP2SettingID = 0x6
)

// HTTP/2 RST_STREAM 错误码
type HTTP2ErrorCode uint32

const (
	HTTP2ErrorNoError            HTTP2ErrorCode = 0x0
	HTTP2ErrorProtocolError      HTTP2ErrorCode = 0x1
	HTTP2ErrorInternalError      HTTP2ErrorCode = 0x2
	HTTP2ErrorFlowControlError   HTTP2ErrorCode = 0x3
	HTTP2ErrorSettingsTimeout    HTTP2ErrorCode = 0x4
	HTTP2ErrorStreamClosed       HTTP2ErrorCode = 0x5
	HTTP2ErrorFrameSizeError     HTTP2ErrorCode = 0x6
	HTTP2ErrorRefusedStream      HTTP2ErrorCode = 0x7
	HTTP2ErrorCancel             HTTP2ErrorCode = 0x8
	HTTP2ErrorCompressionError   HTTP2ErrorCode = 0x9
	HTTP2ErrorConnectError       HTTP2ErrorCode = 0xa
	HTTP2ErrorEnhanceYourCalm    HTTP2ErrorCode = 0xb
	HTTP2ErrorInadequateSecurity HTTP2ErrorCode = 0xc
	HTTP2ErrorHttp11Required     HTTP2ErrorCode = 0xd
)

// HTTP/2 帧
type HTTP2Frame struct {
	Length      uint32
	Type        HTTP2FrameType
	Flags       HTTP2FrameFlags
	StreamID    uint32
	Payload     []byte
}

// HTTP/2 SETTINGS 帧
type HTTP2SettingsFrame struct {
	Settings []HTTP2Setting
}

// HTTP/2 SETTINGS 参数
type HTTP2Setting struct {
	ID    HTTP2SettingID
	Value uint32
}

// HTTP/2 HEADERS 帧
type HTTP2HeadersFrame struct {
	StreamID   uint32
	EndStream  bool
	EndHeaders bool
	Priority   *HTTP2PriorityField
	HeaderBlockFragment []byte
}

// HTTP/2 PRIORITY 帧
type HTTP2PriorityField struct {
	StreamDependency uint32
	Weight           uint8
	Exclusive        bool
}

// HTTP/2 RST_STREAM 帧
type HTTP2RstStreamFrame struct {
	StreamID  uint32
	ErrorCode HTTP2ErrorCode
}

// HTTP/2 GOAWAY 帧
type HTTP2GoAwayFrame struct {
	LastStreamID uint32
	ErrorCode    HTTP2ErrorCode
	DebugData    []byte
}

// HTTP/2 WINDOW_UPDATE 帧
type HTTP2WindowUpdateFrame struct {
	StreamID    uint32
	Increment   uint32
}

// HTTP/2 PING 帧
type HTTP2PingFrame struct {
	OpaqueData [8]byte
}

// HTTP/2 事件
type HTTP2FrameEvent struct {
	TimestampNS uint64
	PID         uint32
	FrameType   HTTP2FrameType
	Flags       HTTP2FrameFlags
	StreamID    uint32
	PayloadLen  uint32
	Data        []byte
}

// HTTP/2 请求
type HTTP2Request struct {
	StreamID    uint32
	Method      string
	Path        string
	Authority   string
	Scheme      string
	Headers     map[string]string
}

// HTTP/2 响应
type HTTP2Response struct {
	StreamID    uint32
	StatusCode  int
	Headers     map[string]string
}

// HPACK 静态表
var hpackStaticTable = map[uint8]string{
	0:  "",
	1:  ":authority",
	2:  ":method",
	3:  ":method",
	4:  ":path",
	5:  ":path",
	6:  ":scheme",
	7:  ":scheme",
	8:  ":status",
	9:  ":status",
	10: ":status",
	11: ":status",
	12: ":status",
	13: ":status",
	14: ":status",
	15: ":status",
	16: ":status",
	17: ":status",
	18: ":status",
	19: ":status",
	20: "accept-charset",
	21: "accept-encoding",
	22: "accept-language",
	23: "accept-ranges",
	24: "accept",
	25: "access-control-allow-origin",
	26: "age",
	27: "allow",
	28: "authorization",
	29: "cache-control",
	30: "content-disposition",
	31: "content-encoding",
	32: "content-language",
	33: "content-length",
	34: "content-location",
	35: "content-range",
	36: "content-type",
	37: "cookie",
	38: "date",
	39: "etag",
	40: "expect",
	41: "expires",
	42: "from",
	43: "host",
	44: "if-match",
	45: "if-modified-since",
	46: "if-none-match",
	47: "if-range",
	48: "if-unmodified-since",
	49: "last-modified",
	50: "link",
	51: "location",
	52: "max-forwards",
	53: "proxy-authenticate",
	54: "proxy-authorization",
	55: "range",
	56: "referer",
	57: "refresh",
	58: "retry-after",
	59: "server",
	60: "set-cookie",
	61: "strict-transport-security",
	62: "transfer-encoding",
	63: "user-agent",
	64: "vary",
	65: "via",
	66: "www-authenticate",
}

// HTTP/2 魔数
const HTTP2Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ParseHTTP2Frame 解析 HTTP/2 帧
func ParseHTTP2Frame(data []byte) (*HTTP2Frame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short for HTTP/2 frame")
	}

	frame := &HTTP2Frame{
		Length:   uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]),
		Type:     HTTP2FrameType(data[3]),
		Flags:    HTTP2FrameFlags(data[4]),
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF, // 去掉保留位
	}

	if len(data) < 9+int(frame.Length) {
		return nil, fmt.Errorf("incomplete HTTP/2 frame")
	}

	frame.Payload = data[9 : 9+frame.Length]

	return frame, nil
}

// ParseHTTP2SettingsFrame 解析 SETTINGS 帧
func ParseHTTP2SettingsFrame(payload []byte) (*HTTP2SettingsFrame, error) {
	if len(payload)%6 != 0 {
		return nil, fmt.Errorf("invalid SETTINGS frame length")
	}

	settingsFrame := &HTTP2SettingsFrame{
		Settings: make([]HTTP2Setting, 0, len(payload)/6),
	}

	for i := 0; i < len(payload); i += 6 {
		setting := HTTP2Setting{
			ID:    HTTP2SettingID(binary.BigEndian.Uint16(payload[i : i+2])),
			Value: binary.BigEndian.Uint32(payload[i+2 : i+6]),
		}
		settingsFrame.Settings = append(settingsFrame.Settings, setting)
	}

	return settingsFrame, nil
}

// ParseHTTP2HeadersFrame 解析 HEADERS 帧
func ParseHTTP2HeadersFrame(frame *HTTP2Frame) (*HTTP2HeadersFrame, error) {
	headersFrame := &HTTP2HeadersFrame{
		StreamID:   frame.StreamID,
		EndStream:  frame.Flags&HTTP2FlagEndStream != 0,
		EndHeaders: frame.Flags&HTTP2FlagEndHeaders != 0,
	}

	offset := 0
	payload := frame.Payload

	// 检查是否包含优先级信息
	if frame.Flags&HTTP2FlagPriority != 0 {
		if len(payload) < 5 {
			return nil, fmt.Errorf("invalid HEADERS frame with priority")
		}

		headersFrame.Priority = &HTTP2PriorityField{
			StreamDependency: binary.BigEndian.Uint32(payload[0:4]) & 0x7FFFFFFF,
			Exclusive:        payload[0]&0x80 != 0,
			Weight:           payload[4],
		}
		offset = 5
	}

	headersFrame.HeaderBlockFragment = payload[offset:]

	return headersFrame, nil
}

// ParseHTTP2RstStreamFrame 解析 RST_STREAM 帧
func ParseHTTP2RstStreamFrame(frame *HTTP2Frame) (*HTTP2RstStreamFrame, error) {
	if len(frame.Payload) != 4 {
		return nil, fmt.Errorf("invalid RST_STREAM frame length")
	}

	return &HTTP2RstStreamFrame{
		StreamID:  frame.StreamID,
		ErrorCode: HTTP2ErrorCode(binary.BigEndian.Uint32(frame.Payload)),
	}, nil
}

// ParseHTTP2GoAwayFrame 解析 GOAWAY 帧
func ParseHTTP2GoAwayFrame(frame *HTTP2Frame) (*HTTP2GoAwayFrame, error) {
	if len(frame.Payload) < 8 {
		return nil, fmt.Errorf("invalid GOAWAY frame length")
	}

	return &HTTP2GoAwayFrame{
		LastStreamID: binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF,
		ErrorCode:    HTTP2ErrorCode(binary.BigEndian.Uint32(frame.Payload[4:8])),
		DebugData:    frame.Payload[8:],
	}, nil
}

// ParseHTTP2WindowUpdateFrame 解析 WINDOW_UPDATE 帧
func ParseHTTP2WindowUpdateFrame(frame *HTTP2Frame) (*HTTP2WindowUpdateFrame, error) {
	if len(frame.Payload) != 4 {
		return nil, fmt.Errorf("invalid WINDOW_UPDATE frame length")
	}

	return &HTTP2WindowUpdateFrame{
		StreamID:  frame.StreamID,
		Increment: binary.BigEndian.Uint32(frame.Payload) & 0x7FFFFFFF,
	}, nil
}

// ParseHTTP2PingFrame 解析 PING 帧
func ParseHTTP2PingFrame(frame *HTTP2Frame) (*HTTP2PingFrame, error) {
	if len(frame.Payload) != 8 {
		return nil, fmt.Errorf("invalid PING frame length")
	}

	pingFrame := &HTTP2PingFrame{}
	copy(pingFrame.OpaqueData[:], frame.Payload)

	return pingFrame, nil
}

// GetHTTP2FrameTypeName 获取 HTTP/2 帧类型名称
func GetHTTP2FrameTypeName(frameType HTTP2FrameType) string {
	if name, ok := http2FrameTypeNames[frameType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(frameType))
}

// GetHTTP2ErrorCodeName 获取 HTTP/2 错误码名称
func GetHTTP2ErrorCodeName(errorCode HTTP2ErrorCode) string {
	switch errorCode {
	case HTTP2ErrorNoError:
		return "NO_ERROR"
	case HTTP2ErrorProtocolError:
		return "PROTOCOL_ERROR"
	case HTTP2ErrorInternalError:
		return "INTERNAL_ERROR"
	case HTTP2ErrorFlowControlError:
		return "FLOW_CONTROL_ERROR"
	case HTTP2ErrorSettingsTimeout:
		return "SETTINGS_TIMEOUT"
	case HTTP2ErrorStreamClosed:
		return "STREAM_CLOSED"
	case HTTP2ErrorFrameSizeError:
		return "FRAME_SIZE_ERROR"
	case HTTP2ErrorRefusedStream:
		return "REFUSED_STREAM"
	case HTTP2ErrorCancel:
		return "CANCEL"
	case HTTP2ErrorCompressionError:
		return "COMPRESSION_ERROR"
	case HTTP2ErrorConnectError:
		return "CONNECT_ERROR"
	case HTTP2ErrorEnhanceYourCalm:
		return "ENHANCE_YOUR_CALM"
	case HTTP2ErrorInadequateSecurity:
		return "INADEQUATE_SECURITY"
	case HTTP2ErrorHttp11Required:
		return "HTTP_1_1_REQUIRED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint32(errorCode))
	}
}

// IsHTTP2Magic 检查是否是 HTTP/2 魔数
func IsHTTP2Magic(data []byte) bool {
	if len(data) < len(HTTP2Magic) {
		return false
	}
	return string(data[:len(HTTP2Magic)]) == HTTP2Magic
}

// ParseHTTP2 请求解析 HTTP/2 请求
func ParseHTTP2Request(frame *HTTP2HeadersFrame, decoder *HPACKDecoder) (*HTTP2Request, error) {
	if frame == nil || decoder == nil {
		return nil, fmt.Errorf("invalid frame or decoder")
	}

	headers, err := decoder.Decode(frame.HeaderBlockFragment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	request := &HTTP2Request{
		StreamID: frame.StreamID,
		Headers:  headers,
	}

	// 提取常用头
	request.Method = headers[":method"]
	request.Path = headers[":path"]
	request.Authority = headers[":authority"]
	request.Scheme = headers[":scheme"]

	return request, nil
}

// HTTP2Response 解析 HTTP/2 响应
func ParseHTTP2Response(frame *HTTP2HeadersFrame, decoder *HPACKDecoder) (*HTTP2Response, error) {
	if frame == nil || decoder == nil {
		return nil, fmt.Errorf("invalid frame or decoder")
	}

	headers, err := decoder.Decode(frame.HeaderBlockFragment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	response := &HTTP2Response{
		StreamID: frame.StreamID,
		Headers:  headers,
	}

	// 提取状态码
	if status, ok := headers[":status"]; ok {
		fmt.Sscanf(status, "%d", &response.StatusCode)
	}

	return response, nil
}

// HPACKDecoder HPACK 解码器
type HPACKDecoder struct {
	dynamicTable []headerField
}

type headerField struct {
	name  string
	value string
}

// NewHPACKDecoder 创建 HPACK 解码器
func NewHPACKDecoder() *HPACKDecoder {
	return &HPACKDecoder{
		dynamicTable: make([]headerField, 0),
	}
}

// Decode 解码 HPACK 头部块
func (d *HPACKDecoder) Decode(data []byte) (map[string]string, error) {
	headers := make(map[string]string)
	offset := 0

	for offset < len(data) {
		// 解析单个头部字段
		name, value, consumed, err := d.decodeHeaderField(data[offset:])
		if err != nil {
			return nil, err
		}

		headers[name] = value
		offset += consumed
	}

	return headers, nil
}

// decodeHeaderField 解码单个头部字段
func (d *HPACKDecoder) decodeHeaderField(data []byte) (string, string, int, error) {
	if len(data) == 0 {
		return "", "", 0, fmt.Errorf("empty data")
	}

	// 检查是否是索引头部
	if data[0]&0x80 != 0 {
		// 索引头部
		index, consumed := d.decodeInteger(data, 7)
		if consumed == 0 {
			return "", "", 0, fmt.Errorf("invalid index")
		}

		// 从静态表或动态表获取
		if index < uint64(len(hpackStaticTable)) {
			return hpackStaticTable[uint8(index)], "", consumed, nil
		}
		return "", "", consumed, nil
	}

	// 检查是否是字面量头部
	if data[0]&0xC0 == 0x40 {
		// 带索引的字面量头部
		_, consumed := d.decodeInteger(data, 6)
		if consumed == 0 {
			return "", "", 0, fmt.Errorf("invalid name index")
		}

		// 解析名称
		name, nameConsumed, err := d.decodeString(data[consumed:])
		if err != nil {
			return "", "", 0, err
		}
		consumed += nameConsumed

		// 解析值
		value, valueConsumed, err := d.decodeString(data[consumed:])
		if err != nil {
			return "", "", 0, err
		}
		consumed += valueConsumed

		// 添加到动态表
		d.dynamicTable = append(d.dynamicTable, headerField{name: name, value: value})

		return name, value, consumed, nil
	}

	// 不带索引的字面量头部
	_, consumed := d.decodeInteger(data, 4)
	if consumed == 0 {
		return "", "", 0, fmt.Errorf("invalid name index")
	}

	// 解析名称
	name, nameConsumed, err := d.decodeString(data[consumed:])
	if err != nil {
		return "", "", 0, err
	}
	consumed += nameConsumed

	// 解析值
	value, valueConsumed, err := d.decodeString(data[consumed:])
	if err != nil {
		return "", "", 0, err
	}
	consumed += valueConsumed

	return name, value, consumed, nil
}

// decodeInteger 解码 HPACK 整数
func (d *HPACKDecoder) decodeInteger(data []byte, prefix int) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	mask := uint8((1 << uint(prefix)) - 1)
	result := uint64(data[0] & mask)

	if result < uint64(mask) {
		return result, 1
	}

	offset := 1
	shift := uint(prefix)
	for offset < len(data) {
		b := data[offset]
		offset++

		result += uint64(b&0x7F) << shift
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}

	return result, offset
}

// decodeString 解码 HPACK 字符串
func (d *HPACKDecoder) decodeString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, fmt.Errorf("empty data")
	}

	// 检查是否是 Huffman 编码
	huffman := data[0]&0x80 != 0

	length, consumed := d.decodeInteger(data, 7)
	if consumed == 0 {
		return "", 0, fmt.Errorf("invalid length")
	}

	if uint64(consumed)+length > uint64(len(data)) {
		return "", 0, fmt.Errorf("incomplete string")
	}

	stringData := data[consumed : consumed+int(length)]

	if huffman {
		// TODO: 实现 Huffman 解码
		return string(stringData), consumed + int(length), nil
	}

	return string(stringData), consumed + int(length), nil
}
