// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// Redis RESP 协议类型
type RedisRESPType byte

const (
	RedisRESPArray   RedisRESPType = '*'
	RedisRESPBulk    RedisRESPType = '$'
	RedisRESPSimple  RedisRESPType = '+'
	RedisRESPError   RedisRESPType = '-'
	RedisRESPInteger RedisRESPType = ':'
)

// Redis 命令类型
type RedisCommandType string

const (
	// 字符串命令
	RedisCommandSet       RedisCommandType = "SET"
	RedisCommandGet       RedisCommandType = "GET"
	RedisCommandDel       RedisCommandType = "DEL"
	RedisCommandMSet      RedisCommandType = "MSET"
	RedisCommandMGet      RedisCommandType = "MGET"
	RedisCommandIncr      RedisCommandType = "INCR"
	RedisCommandDecr      RedisCommandType = "DECR"
	RedisCommandAppend    RedisCommandType = "APPEND"
	RedisCommandSetEx     RedisCommandType = "SETEX"
	RedisCommandSetNx     RedisCommandType = "SETNX"
	RedisCommandGetSet    RedisCommandType = "GETSET"
	RedisCommandStrLen    RedisCommandType = "STRLEN"

	// Hash 命令
	RedisCommandHSet      RedisCommandType = "HSET"
	RedisCommandHGet      RedisCommandType = "HGET"
	RedisCommandHDel      RedisCommandType = "HDEL"
	RedisCommandHGetAll   RedisCommandType = "HGETALL"
	RedisCommandHMSet     RedisCommandType = "HMSET"
	RedisCommandHMGet     RedisCommandType = "HMGET"
	RedisCommandHKeys     RedisCommandType = "HKEYS"
	RedisCommandHVals     RedisCommandType = "HVALS"
	RedisCommandHLen      RedisCommandType = "HLEN"
	RedisCommandHExists   RedisCommandType = "HEXISTS"

	// List 命令
	RedisCommandLPush     RedisCommandType = "LPUSH"
	RedisCommandRPush     RedisCommandType = "RPUSH"
	RedisCommandLPop      RedisCommandType = "LPOP"
	RedisCommandRPop      RedisCommandType = "RPOP"
	RedisCommandLLen      RedisCommandType = "LLEN"
	RedisCommandLRange    RedisCommandType = "LRANGE"
	RedisCommandLIndex    RedisCommandType = "LINDEX"
	RedisCommandLSet      RedisCommandType = "LSET"
	RedisCommandLRem      RedisCommandType = "LREM"

	// Set 命令
	RedisCommandSAdd      RedisCommandType = "SADD"
	RedisCommandSMembers  RedisCommandType = "SMEMBERS"
	RedisCommandSRem      RedisCommandType = "SREM"
	RedisCommandSIsMember RedisCommandType = "SISMEMBER"
	RedisCommandSCard     RedisCommandType = "SCARD"

	// Sorted Set 命令
	RedisCommandZAdd      RedisCommandType = "ZADD"
	RedisCommandZRange    RedisCommandType = "ZRANGE"
	RedisCommandZRem      RedisCommandType = "ZREM"
	RedisCommandZScore    RedisCommandType = "ZSCORE"
	RedisCommandZCard     RedisCommandType = "ZCARD"

	// 发布订阅命令
	RedisCommandPublish   RedisCommandType = "PUBLISH"
	RedisCommandSubscribe RedisCommandType = "SUBSCRIBE"

	// 事务命令
	RedisCommandMulti     RedisCommandType = "MULTI"
	RedisCommandExec      RedisCommandType = "EXEC"
	RedisCommandDiscard   RedisCommandType = "DISCARD"

	// 连接命令
	RedisCommandPing      RedisCommandType = "PING"
	RedisCommandAuth      RedisCommandType = "AUTH"
	RedisCommandSelect    RedisCommandType = "SELECT"
	RedisCommandQuit      RedisCommandType = "QUIT"
	RedisCommandEcho      RedisCommandType = "ECHO"

	// 服务器命令
	RedisCommandInfo      RedisCommandType = "INFO"
	RedisCommandDbSize    RedisCommandType = "DBSIZE"
	RedisCommandFlushAll  RedisCommandType = "FLUSHALL"
	RedisCommandFlushDb   RedisCommandType = "FLUSHDB"
)

// Redis 命令类型分类
type RedisCommandCategory string

const (
	RedisCommandCategoryRead      RedisCommandCategory = "read"
	RedisCommandCategoryWrite     RedisCommandCategory = "write"
	RedisCommandCategoryAdmin     RedisCommandCategory = "admin"
	RedisCommandCategoryPubSub    RedisCommandCategory = "pubsub"
	RedisCommandCategoryTransaction RedisCommandCategory = "transaction"
	RedisCommandCategoryConnection RedisCommandCategory = "connection"
)

// 命令分类映射
var redisCommandCategories = map[RedisCommandType]RedisCommandCategory{
	RedisCommandGet:       RedisCommandCategoryRead,
	RedisCommandMGet:      RedisCommandCategoryRead,
	RedisCommandHGet:      RedisCommandCategoryRead,
	RedisCommandHGetAll:   RedisCommandCategoryRead,
	RedisCommandHMGet:     RedisCommandCategoryRead,
	RedisCommandHKeys:     RedisCommandCategoryRead,
	RedisCommandHVals:     RedisCommandCategoryRead,
	RedisCommandHLen:      RedisCommandCategoryRead,
	RedisCommandHExists:   RedisCommandCategoryRead,
	RedisCommandLLen:      RedisCommandCategoryRead,
	RedisCommandLRange:    RedisCommandCategoryRead,
	RedisCommandLIndex:    RedisCommandCategoryRead,
	RedisCommandSMembers:  RedisCommandCategoryRead,
	RedisCommandSIsMember: RedisCommandCategoryRead,
	RedisCommandSCard:     RedisCommandCategoryRead,
	RedisCommandZRange:    RedisCommandCategoryRead,
	RedisCommandZScore:    RedisCommandCategoryRead,
	RedisCommandZCard:     RedisCommandCategoryRead,
	RedisCommandStrLen:    RedisCommandCategoryRead,

	RedisCommandSet:    RedisCommandCategoryWrite,
	RedisCommandDel:    RedisCommandCategoryWrite,
	RedisCommandMSet:   RedisCommandCategoryWrite,
	RedisCommandIncr:   RedisCommandCategoryWrite,
	RedisCommandDecr:   RedisCommandCategoryWrite,
	RedisCommandAppend: RedisCommandCategoryWrite,
	RedisCommandSetEx:  RedisCommandCategoryWrite,
	RedisCommandSetNx:  RedisCommandCategoryWrite,
	RedisCommandGetSet: RedisCommandCategoryWrite,
	RedisCommandHSet:   RedisCommandCategoryWrite,
	RedisCommandHDel:   RedisCommandCategoryWrite,
	RedisCommandHMSet:  RedisCommandCategoryWrite,
	RedisCommandLPush:  RedisCommandCategoryWrite,
	RedisCommandRPush:  RedisCommandCategoryWrite,
	RedisCommandLPop:   RedisCommandCategoryWrite,
	RedisCommandRPop:   RedisCommandCategoryWrite,
	RedisCommandLSet:   RedisCommandCategoryWrite,
	RedisCommandLRem:   RedisCommandCategoryWrite,
	RedisCommandSAdd:   RedisCommandCategoryWrite,
	RedisCommandSRem:   RedisCommandCategoryWrite,
	RedisCommandZAdd:   RedisCommandCategoryWrite,
	RedisCommandZRem:   RedisCommandCategoryWrite,
	RedisCommandPublish: RedisCommandCategoryPubSub,

	RedisCommandMulti:   RedisCommandCategoryTransaction,
	RedisCommandExec:    RedisCommandCategoryTransaction,
	RedisCommandDiscard: RedisCommandCategoryTransaction,

	RedisCommandPing:   RedisCommandCategoryConnection,
	RedisCommandAuth:   RedisCommandCategoryConnection,
	RedisCommandSelect: RedisCommandCategoryConnection,
	RedisCommandQuit:   RedisCommandCategoryConnection,
	RedisCommandEcho:   RedisCommandCategoryConnection,

	RedisCommandInfo:     RedisCommandCategoryAdmin,
	RedisCommandDbSize:   RedisCommandCategoryAdmin,
	RedisCommandFlushAll: RedisCommandCategoryAdmin,
	RedisCommandFlushDb:  RedisCommandCategoryAdmin,
}

// Redis RESP 解析结果
type RedisRESP struct {
	Type  RedisRESPType
	Value interface{}
}

// Redis 命令
type RedisCommand struct {
	Name    RedisCommandType
	Args    []string
	Raw     string
}

// Redis 事件
type RedisEvent struct {
	TimestampNS uint64
	PID         uint32
	Command     RedisCommandType
	Category    RedisCommandCategory
	Key         string
	Args        []string
	IsError     bool
	ErrorMessage string
	LatencyNS   uint64
}

// ParseRedisPacket 解析 Redis RESP 协议包
func ParseRedisPacket(data []byte) (*RedisRESP, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	respType := RedisRESPType(data[0])

	switch respType {
	case RedisRESPSimple, RedisRESPError, RedisRESPInteger:
		// 简单类型：直到 \r\n
		end := strings.Index(string(data[1:]), "\r\n")
		if end == -1 {
			return nil, fmt.Errorf("incomplete RESP simple type")
		}
		return &RedisRESP{
			Type:  respType,
			Value: string(data[1 : 1+end]),
		}, nil

	case RedisRESPBulk:
		// 批量字符串：长度 + \r\n + 数据 + \r\n
		end := strings.Index(string(data[1:]), "\r\n")
		if end == -1 {
			return nil, fmt.Errorf("incomplete bulk string length")
		}
		length, err := strconv.Atoi(string(data[1 : 1+end]))
		if err != nil {
			return nil, fmt.Errorf("invalid bulk string length: %w", err)
		}
		offset := 1 + end + 2 // 跳过长度和 \r\n
		if length == -1 {
			return &RedisRESP{Type: respType, Value: nil}, nil
		}
		if offset+length+2 > len(data) {
			return nil, fmt.Errorf("incomplete bulk string data")
		}
		return &RedisRESP{
			Type:  respType,
			Value: string(data[offset : offset+length]),
		}, nil

	case RedisRESPArray:
		// 数组：元素数量 + \r\n + 元素...
		end := strings.Index(string(data[1:]), "\r\n")
		if end == -1 {
			return nil, fmt.Errorf("incomplete array length")
		}
		length, err := strconv.Atoi(string(data[1 : 1+end]))
		if err != nil {
			return nil, fmt.Errorf("invalid array length: %w", err)
		}
		offset := 1 + end + 2
		if length == -1 {
			return &RedisRESP{Type: respType, Value: nil}, nil
		}

		elements := make([]*RedisRESP, 0, length)
		for i := 0; i < length; i++ {
			if offset >= len(data) {
				return nil, fmt.Errorf("incomplete array element")
			}
			elem, err := ParseRedisPacket(data[offset:])
			if err != nil {
				return nil, err
			}
			elements = append(elements, elem)
			// 计算元素消耗的字节数
			offset += calculateRESPSize(elem)
		}

		return &RedisRESP{
			Type:  respType,
			Value: elements,
		}, nil

	default:
		return nil, fmt.Errorf("unknown RESP type: %c", respType)
	}
}

// calculateRESPSize 计算 RESP 元素占用的字节数
func calculateRESPSize(resp *RedisRESP) int {
	switch resp.Type {
	case RedisRESPSimple, RedisRESPError, RedisRESPInteger:
		return 1 + len(resp.Value.(string)) + 2 // type + data + \r\n
	case RedisRESPBulk:
		if resp.Value == nil {
			return 4 // $-1\r\n
		}
		return 1 + len(fmt.Sprintf("%d", len(resp.Value.(string)))) + 2 + len(resp.Value.(string)) + 2
	case RedisRESPArray:
		if resp.Value == nil {
			return 4 // *-1\r\n
		}
		elems := resp.Value.([]*RedisRESP)
		size := 1 + len(fmt.Sprintf("%d", len(elems))) + 2 // *N\r\n
		for _, elem := range elems {
			size += calculateRESPSize(elem)
		}
		return size
	default:
		return 0
	}
}

// ParseRedisCommand 解析 Redis 命令
func ParseRedisCommand(data []byte) (*RedisCommand, error) {
	resp, err := ParseRedisPacket(data)
	if err != nil {
		return nil, err
	}

	if resp.Type != RedisRESPArray {
		return nil, fmt.Errorf("not a command array")
	}

	elems, ok := resp.Value.([]*RedisRESP)
	if !ok {
		return nil, fmt.Errorf("invalid array value")
	}

	if len(elems) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	// 提取命令名称
	nameStr, ok := elems[0].Value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid command name")
	}

	cmd := &RedisCommand{
		Name: RedisCommandType(strings.ToUpper(nameStr)),
		Raw:  string(data),
	}

	// 提取命令参数
	for i := 1; i < len(elems); i++ {
		if arg, ok := elems[i].Value.(string); ok {
			cmd.Args = append(cmd.Args, arg)
		}
	}

	return cmd, nil
}

// GetRedisCommandCategory 获取 Redis 命令分类
func GetRedisCommandCategory(command RedisCommandType) RedisCommandCategory {
	if cat, ok := redisCommandCategories[command]; ok {
		return cat
	}
	return RedisCommandCategoryRead // 默认为读命令
}

// IsRedisPacket 检查是否是 Redis 协议包
func IsRedisPacket(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 检查 RESP 类型标识符
	switch RedisRESPType(data[0]) {
	case RedisRESPArray, RedisRESPBulk, RedisRESPSimple, RedisRESPError, RedisRESPInteger:
		return true
	}

	// 检查 Inline 命令
	if len(data) >= 3 {
		cmd := strings.ToUpper(string(data[:3]))
		if cmd == "GET" || cmd == "SET" || cmd == "DEL" || cmd == "PING" {
			return true
		}
	}

	return false
}

// ParseRedisInlineCommand 解析 Redis Inline 命令
func ParseRedisInlineCommand(data []byte) (*RedisCommand, error) {
	// Inline 命令格式：COMMAND ARG1 ARG2 ...\r\n
	lines := strings.Split(string(data), "\r\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	parts := strings.Fields(lines[0])
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command parts")
	}

	cmd := &RedisCommand{
		Name: RedisCommandType(strings.ToUpper(parts[0])),
		Args: parts[1:],
		Raw:  string(data),
	}

	return cmd, nil
}

// GetRedisKey 从命令中提取键名
func GetRedisKey(cmd *RedisCommand) string {
	switch cmd.Name {
	case RedisCommandGet, RedisCommandSet, RedisCommandDel, RedisCommandAppend,
		RedisCommandSetEx, RedisCommandSetNx, RedisCommandGetSet, RedisCommandStrLen:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandMGet, RedisCommandMSet:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandIncr, RedisCommandDecr:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandHSet, RedisCommandHGet, RedisCommandHDel, RedisCommandHGetAll,
		RedisCommandHMSet, RedisCommandHMGet, RedisCommandHKeys, RedisCommandHVals,
		RedisCommandHLen, RedisCommandHExists:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandLPush, RedisCommandRPush, RedisCommandLPop, RedisCommandRPop,
		RedisCommandLLen, RedisCommandLRange, RedisCommandLIndex, RedisCommandLSet, RedisCommandLRem:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandSAdd, RedisCommandSMembers, RedisCommandSRem, RedisCommandSIsMember, RedisCommandSCard:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	case RedisCommandZAdd, RedisCommandZRange, RedisCommandZRem, RedisCommandZScore, RedisCommandZCard:
		if len(cmd.Args) > 0 {
			return cmd.Args[0]
		}
	}

	return ""
}

// FormatRedisCommand 格式化 Redis 命令为字符串
func FormatRedisCommand(cmd *RedisCommand) string {
	parts := []string{string(cmd.Name)}
	parts = append(parts, cmd.Args...)
	return strings.Join(parts, " ")
}
