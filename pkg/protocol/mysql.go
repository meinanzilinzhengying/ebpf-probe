// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// MySQL 协议常量
const (
	MySQLPacketHeaderSize = 4
	MySQLMaxPacketSize    = 1<<24 - 1
)

// MySQL 命令类型
type MySQLCommandType uint8

const (
	MySQLCommandSleep         MySQLCommandType = 0x00
	MySQLCommandQuit          MySQLCommandType = 0x01
	MySQLCommandInitDB        MySQLCommandType = 0x02
	MySQLCommandQuery         MySQLCommandType = 0x03
	MySQLCommandOptions       MySQLCommandType = 0x0b
	MySQLCommandStatV         MySQLCommandType = 0x09
	MySQLCommandRefresh       MySQLCommandType = 0x08
	MySQLCommandPing          MySQLCommandType = 0x0e
	MySQLCommandProcessInfo   MySQLCommandType = 0x0a
	MySQLCommandConnect       MySQLCommandType = 0x0b
	MySQLCommandProcessKill  MySQLCommandType = 0x0c
	MySQLCommandDebug         MySQLCommandType = 0x0d
	MySQLCommandBinlogDump    MySQLCommandType = 0x12
	MySQLCommandTableDump     MySQLCommandType = 0x13
	MySQLCommandConnectOut    MySQLCommandType = 0x14
	MySQLCommandRegisterSlave MySQLCommandType = 0x15
	MySQLCommandPrepare       MySQLCommandType = 0x16
	MySQLCommandExecute       MySQLCommandType = 0x17
	MySQLCommandSendLongData  MySQLCommandType = 0x18
	MySQLCommandCloseStmt     MySQLCommandType = 0x19
	MySQLCommandResetStmt     MySQLCommandType = 0x1a
	MySQLCommandSetOption     MySQLCommandType = 0x1b
	MySQLCommandFetch         MySQLCommandType = 0x1c
)

// MySQL 命令类型名称
var mysqlCommandTypeNames = map[MySQLCommandType]string{
	MySQLCommandSleep:         "SLEEP",
	MySQLCommandQuit:          "QUIT",
	MySQLCommandInitDB:        "INIT_DB",
	MySQLCommandQuery:         "QUERY",
	MySQLCommandOptions:       "OPTIONS",
	MySQLCommandStatV:         "STAT_V",
	MySQLCommandRefresh:       "REFRESH",
	MySQLCommandPing:          "PING",
	MySQLCommandProcessInfo:   "PROCESS_INFO",
	MySQLCommandConnect:       "CONNECT",
	MySQLCommandProcessKill:  "PROCESS_KILL",
	MySQLCommandDebug:         "DEBUG",
	MySQLCommandBinlogDump:    "BINLOG_DUMP",
	MySQLCommandTableDump:     "TABLE_DUMP",
	MySQLCommandConnectOut:    "CONNECT_OUT",
	MySQLCommandRegisterSlave: "REGISTER_SLAVE",
	MySQLCommandPrepare:       "PREPARE",
	MySQLCommandExecute:       "EXECUTE",
	MySQLCommandSendLongData:  "SEND_LONG_DATA",
	MySQLCommandCloseStmt:     "CLOSE_STMT",
	MySQLCommandResetStmt:     "RESET_STMT",
	MySQLCommandSetOption:     "SET_OPTION",
	MySQLCommandFetch:         "FETCH",
}

// MySQL 协议包
type MySQLPacket struct {
	SequenceID uint8
	Payload    []byte
}

// MySQL 握手包 (HandshakeV10)
type MySQLHandshakePacket struct {
	ProtocolVersion uint8
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
	CharacterSet    uint8
	StatusFlags     uint16
	AuthPluginName  string
}

// MySQL 查询包
type MySQLQueryPacket struct {
	Command MySQLCommandType
	SQL     string
}

// MySQL OK 包
type MySQLOKPacket struct {
	AffectedRows uint64
	LastInsertID uint64
	StatusFlags  uint16
	Warnings     uint16
}

// MySQL EOF 包
type MySQLEOFPacket struct {
	Warnings    uint16
	StatusFlags uint16
}

// MySQL 错误包
type MySQLErrorPacket struct {
	ErrorCode uint16
	SQLState  string
	Message   string
}

// MySQL 列定义包
type MySQLColumnDefinitionPacket struct {
	Catalog      string
	Schema       string
	Table        string
	OrgTable     string
	Name         string
	OrgName      string
	CharacterSet uint32
	ColumnLength uint32
	ColumnType   uint8
	Flags        uint16
	Decimals     uint8
}

// MySQL 行数据包
type MySQLRowPacket struct {
	Columns []string
}

// MySQL 事件
type MySQLEvent struct {
	TimestampNS uint64
	PID         uint32
	Command     MySQLCommandType
	SQL         string
	AffectedRows uint64
	LastInsertID uint64
	LatencyNS   uint64
	IsError     bool
	ErrorMessage string
}

// ParseMySQLPacket 解析 MySQL 协议包
func ParseMySQLPacket(data []byte) (*MySQLPacket, error) {
	if len(data) < MySQLPacketHeaderSize {
		return nil, fmt.Errorf("data too short for MySQL packet header")
	}

	// 解析包头
	payloadLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)
	sequenceID := data[3]

	if len(data) < MySQLPacketHeaderSize+payloadLen {
		return nil, fmt.Errorf("incomplete MySQL packet")
	}

	return &MySQLPacket{
		SequenceID: sequenceID,
		Payload:    data[MySQLPacketHeaderSize : MySQLPacketHeaderSize+payloadLen],
	}, nil
}

// ParseMySQLHandshake 解析 MySQL 握手包
func ParseMySQLHandshake(data []byte) (*MySQLHandshakePacket, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for handshake")
	}

	packet := &MySQLHandshakePacket{
		ProtocolVersion: data[0],
	}

	// 解析服务器版本字符串（以 0x00 结尾）
	offset := 1
	for offset < len(data) && data[offset] != 0x00 {
		offset++
	}
	packet.ServerVersion = string(data[1:offset])
	offset++ // 跳过 0x00

	// 解析连接 ID
	if offset+4 > len(data) {
		return nil, fmt.Errorf("incomplete connection ID")
	}
	packet.ConnectionID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 解析认证插件数据（部分）
	if offset+8+1 > len(data) {
		return nil, fmt.Errorf("incomplete auth plugin data")
	}
	packet.AuthPluginData = data[offset : offset+8]
	offset += 8 + 1 // 跳过填充的 0x00

	// 解析能力标志
	if offset+4 > len(data) {
		return nil, fmt.Errorf("incomplete capability flags")
	}
	packet.CapabilityFlags = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 解析字符集
	if offset+1 > len(data) {
		return nil, fmt.Errorf("incomplete character set")
	}
	packet.CharacterSet = data[offset]
	offset++

	// 解析状态标志
	if offset+2 > len(data) {
		return nil, fmt.Errorf("incomplete status flags")
	}
	packet.StatusFlags = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 解析认证插件名称
	if offset+2 > len(data) {
		// 可能是旧版本协议
		return packet, nil
	}
	nameLen := int(data[offset])
	offset++

	if offset+nameLen > len(data) {
		return packet, nil
	}
	packet.AuthPluginName = string(data[offset : offset+nameLen])

	return packet, nil
}

// ParseMySQLQuery 解析 MySQL 查询包
func ParseMySQLQuery(data []byte) (*MySQLQueryPacket, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for query")
	}

	packet := &MySQLQueryPacket{
		Command: MySQLCommandType(data[0]),
	}

	if len(data) > 1 {
		packet.SQL = string(data[1:])
	}

	return packet, nil
}

// ParseMySQLOK 解析 MySQL OK 包
func ParseMySQLOK(data []byte) (*MySQLOKPacket, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("data too short for OK packet")
	}

	packet := &MySQLOKPacket{
		AffectedRows: 0,
		LastInsertID: 0,
		StatusFlags:  0,
		Warnings:     0,
	}

	// 跳过 OK 标记 (0x00)
	offset := 1

	// 解析受影响行数
	rowCount, consumed := readLenEncInteger(data[offset:])
	packet.AffectedRows = rowCount
	offset += consumed

	// 解析最后插入 ID
	lastInsertID, consumed := readLenEncInteger(data[offset:])
	packet.LastInsertID = lastInsertID
	offset += consumed

	// 解析状态标志
	if offset+2 <= len(data) {
		packet.StatusFlags = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// 解析警告数
	if offset+2 <= len(data) {
		packet.Warnings = binary.LittleEndian.Uint16(data[offset : offset+2])
	}

	return packet, nil
}

// ParseMySQLEOF 解析 MySQL EOF 包
func ParseMySQLEOF(data []byte) (*MySQLEOFPacket, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for EOF packet")
	}

	return &MySQLEOFPacket{
		Warnings:    binary.LittleEndian.Uint16(data[1:3]),
		StatusFlags: binary.LittleEndian.Uint16(data[3:5]),
	}, nil
}

// ParseMySQLError 解析 MySQL 错误包
func ParseMySQLError(data []byte) (*MySQLErrorPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for error packet")
	}

	packet := &MySQLErrorPacket{
		ErrorCode: binary.LittleEndian.Uint16(data[1:3]),
	}

	// 检查是否是新的错误格式
	if len(data) > 3 && data[3] == '#' {
		if len(data) >= 9 {
			packet.SQLState = string(data[4:9])
			packet.Message = string(data[9:])
		}
	} else {
		packet.Message = string(data[3:])
	}

	return packet, nil
}

// GetMySQLCommandTypeName 获取 MySQL 命令类型名称
func GetMySQLCommandTypeName(command MySQLCommandType) string {
	if name, ok := mysqlCommandTypeNames[command]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(command))
}

// IsMySQLPacket 检查是否是 MySQL 协议包
func IsMySQLPacket(data []byte) bool {
	if len(data) < MySQLPacketHeaderSize {
		return false
	}

	// 检查包长度是否合理
	payloadLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)
	if payloadLen < 0 || payloadLen > MySQLMaxPacketSize {
		return false
	}

	// 检查序列号
	sequenceID := data[3]
	if sequenceID > 255 {
		return false
	}

	return true
}

// GetMySQLCommand 从查询中提取命令类型
func GetMySQLCommand(sql string) string {
	sql = strings.TrimSpace(sql)
	sql = strings.ToUpper(sql)

	if strings.HasPrefix(sql, "SELECT") {
		return "SELECT"
	}
	if strings.HasPrefix(sql, "INSERT") {
		return "INSERT"
	}
	if strings.HasPrefix(sql, "UPDATE") {
		return "UPDATE"
	}
	if strings.HasPrefix(sql, "DELETE") {
		return "DELETE"
	}
	if strings.HasPrefix(sql, "CREATE") {
		return "CREATE"
	}
	if strings.HasPrefix(sql, "ALTER") {
		return "ALTER"
	}
	if strings.HasPrefix(sql, "DROP") {
		return "DROP"
	}
	if strings.HasPrefix(sql, "TRUNCATE") {
		return "TRUNCATE"
	}
	if strings.HasPrefix(sql, "GRANT") {
		return "GRANT"
	}
	if strings.HasPrefix(sql, "REVOKE") {
		return "REVOKE"
	}
	if strings.HasPrefix(sql, "BEGIN") {
		return "BEGIN"
	}
	if strings.HasPrefix(sql, "COMMIT") {
		return "COMMIT"
	}
	if strings.HasPrefix(sql, "ROLLBACK") {
		return "ROLLBACK"
	}

	return "OTHER"
}

// readLenEncInteger 读取 Length-Encoded Integer
func readLenEncInteger(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	firstByte := data[0]

	if firstByte < 0xfb {
		return uint64(firstByte), 1
	}

	if firstByte == 0xfb {
		return 0, 1 // NULL
	}

	if firstByte == 0xfc {
		if len(data) < 3 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	}

	if firstByte == 0xfd {
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16, 4
	}

	// 0xfe
	if len(data) < 9 {
		return 0, 0
	}
	return binary.LittleEndian.Uint64(data[1:9]), 9
}
