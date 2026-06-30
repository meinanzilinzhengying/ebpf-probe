// Copyright (c) 2026 CloudFlow Team

package protocol

import (
	"encoding/binary"
	"fmt"
)

// Kafka API Key
type KafkaAPIKey int16

const (
	KafkaAPIProduce         KafkaAPIKey = 0
	KafkaAPIFetch           KafkaAPIKey = 1
	KafkaAPIListOffsets     KafkaAPIKey = 2
	KafkaAPIMetadata        KafkaAPIKey = 3
	KafkaAPILeaderAndIsr    KafkaAPIKey = 4
	KafkaAPIStopReplica     KafkaAPIKey = 5
	KafkaAPIUpdateMetadata  KafkaAPIKey = 6
	KafkaAPIControlledShutdown KafkaAPIKey = 7
	KafkaAPIOffsetCommit    KafkaAPIKey = 8
	KafkaAPIOffsetFetch     KafkaAPIKey = 9
	KafkaAPIFindCoordinator KafkaAPIKey = 10
	KafkaAPIJoinGroup       KafkaAPIKey = 11
	KafkaAPIHeartbeat       KafkaAPIKey = 12
	KafkaAPILeaveGroup      KafkaAPIKey = 13
	KafkaAPISyncGroup       KafkaAPIKey = 14
	KafkaAPIDescribeGroups  KafkaAPIKey = 15
	KafkaAPIListGroups      KafkaAPIKey = 16
	KafkaAPISaslHandshake   KafkaAPIKey = 17
	KafkaAPIApiVersions     KafkaAPIKey = 18
	KafkaAPICreateTopics    KafkaAPIKey = 19
	KafkaAPIDeleteTopics    KafkaAPIKey = 20
	KafkaAPIDeleteRecords   KafkaAPIKey = 21
	KafkaAPIInitProducerId  KafkaAPIKey = 22
	KafkaAPIOffsetForLeaderEpoch KafkaAPIKey = 23
	KafkaAPIAddPartitionsToTxn KafkaAPIKey = 24
	KafkaAPIAddOffsetsToTxn KafkaAPIKey = 25
	KafkaAPIEndTxn          KafkaAPIKey = 26
	KafkaAPIWriteTxnMarkers KafkaAPIKey = 27
	KafkaAPITxOffset        KafkaAPIKey = 28
	KafkaAPIDescribeAcls    KafkaAPIKey = 29
	KafkaAPICreateAcls      KafkaAPIKey = 30
	KafkaAPIDeleteAcls      KafkaAPIKey = 31
	KafkaAPIAlterConfigs    KafkaAPIKey = 32
	KafkaAPIAlterReplicaLogDirs KafkaAPIKey = 34
	KafkaAPIDescribeLogDirs KafkaAPIKey = 35
	KafkaAPISaslAuthenticate KafkaAPIKey = 36
	KafkaAPICreatePartitions KafkaAPIKey = 37
)

// Kafka API Key 名称
var kafkaAPIKeyNames = map[KafkaAPIKey]string{
	KafkaAPIProduce:              "Produce",
	KafkaAPIFetch:                "Fetch",
	KafkaAPIListOffsets:          "ListOffsets",
	KafkaAPIMetadata:             "Metadata",
	KafkaAPILeaderAndIsr:         "LeaderAndIsr",
	KafkaAPIStopReplica:          "StopReplica",
	KafkaAPIUpdateMetadata:       "UpdateMetadata",
	KafkaAPIControlledShutdown:   "ControlledShutdown",
	KafkaAPIOffsetCommit:         "OffsetCommit",
	KafkaAPIOffsetFetch:          "OffsetFetch",
	KafkaAPIFindCoordinator:      "FindCoordinator",
	KafkaAPIJoinGroup:            "JoinGroup",
	KafkaAPIHeartbeat:            "Heartbeat",
	KafkaAPILeaveGroup:           "LeaveGroup",
	KafkaAPISyncGroup:            "SyncGroup",
	KafkaAPIDescribeGroups:       "DescribeGroups",
	KafkaAPIListGroups:           "ListGroups",
	KafkaAPISaslHandshake:        "SaslHandshake",
	KafkaAPIApiVersions:          "ApiVersions",
	KafkaAPICreateTopics:         "CreateTopics",
	KafkaAPIDeleteTopics:         "DeleteTopics",
	KafkaAPIDeleteRecords:        "DeleteRecords",
	KafkaAPIInitProducerId:       "InitProducerId",
	KafkaAPIOffsetForLeaderEpoch: "OffsetForLeaderEpoch",
	KafkaAPIAddPartitionsToTxn:   "AddPartitionsToTxn",
	KafkaAPIAddOffsetsToTxn:      "AddOffsetsToTxn",
	KafkaAPIEndTxn:               "EndTxn",
	KafkaAPIWriteTxnMarkers:      "WriteTxnMarkers",
	KafkaAPITxOffset:             "TxnOffset",
	KafkaAPIDescribeAcls:         "DescribeAcls",
	KafkaAPICreateAcls:           "CreateAcls",
	KafkaAPIDeleteAcls:           "DeleteAcls",
	KafkaAPIAlterConfigs:         "AlterConfigs",
	KafkaAPIAlterReplicaLogDirs:  "AlterReplicaLogDirs",
	KafkaAPIDescribeLogDirs:      "DescribeLogDirs",
	KafkaAPISaslAuthenticate:     "SaslAuthenticate",
	KafkaAPICreatePartitions:     "CreatePartitions",
}

// Kafka 请求头
type KafkaRequestHeader struct {
	ApiKey     KafkaAPIKey
	ApiVersion int16
	CorrelationID int32
	ClientID   string
}

// Kafka 响应头
type KafkaResponseHeader struct {
	CorrelationID int32
}

// Kafka 请求
type KafkaRequest struct {
	Header  KafkaRequestHeader
	Topic   string
	// 其他字段根据 API Key 不同而不同
}

// Kafka 响应
type KafkaResponse struct {
	Header  KafkaResponseHeader
	// 其他字段根据 API Key 不同而不同
}

// Kafka 事件
type KafkaEvent struct {
	TimestampNS   uint64
	PID           uint32
	APIKey        KafkaAPIKey
	APIVersion    int16
	CorrelationID int32
	Topic         string
	Partition     int32
	Offset        int64
	MessageSize   int32
	IsError       bool
	ErrorCode     int16
	LatencyNS     uint64
}

// ParseKafkaRequestHeader 解析 Kafka 请求头
func ParseKafkaRequestHeader(data []byte) (*KafkaRequestHeader, int, error) {
	if len(data) < 10 {
		return nil, 0, fmt.Errorf("data too short for Kafka request header")
	}

	header := &KafkaRequestHeader{
		ApiKey:     KafkaAPIKey(binary.BigEndian.Uint16(data[0:2])),
		ApiVersion: int16(binary.BigEndian.Uint16(data[2:4])),
	}

	offset := 4

	// Correlation ID
	header.CorrelationID = int32(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Client ID (长度前缀的字符串)
	if offset+2 > len(data) {
		return nil, 0, fmt.Errorf("incomplete client ID length")
	}
	clientIDLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+clientIDLen > len(data) {
		return nil, 0, fmt.Errorf("incomplete client ID")
	}
	header.ClientID = string(data[offset : offset+clientIDLen])
	offset += clientIDLen

	return header, offset, nil
}

// ParseKafkaResponseHeader 解析 Kafka 响应头
func ParseKafkaResponseHeader(data []byte) (*KafkaResponseHeader, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("data too short for Kafka response header")
	}

	header := &KafkaResponseHeader{
		CorrelationID: int32(binary.BigEndian.Uint32(data[0:4])),
	}

	return header, 4, nil
}

// ParseKafkaRequest 解析 Kafka 请求
func ParseKafkaRequest(data []byte) (*KafkaRequest, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("data too short for Kafka request")
	}

	header, offset, err := ParseKafkaRequestHeader(data)
	if err != nil {
		return nil, err
	}

	request := &KafkaRequest{
		Header: *header,
	}

	// 根据 API Key 解析不同的请求体
	switch header.ApiKey {
	case KafkaAPIProduce:
		// Produce 请求
		if offset+2 <= len(data) {
			// transactional_id (nullable string)
			txnIDLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if txnIDLen > 0 {
				offset += txnIDLen
			}

			// acks
			if offset+2 <= len(data) {
				offset += 2
			}

			// timeout
			if offset+4 <= len(data) {
				offset += 4
			}

			// topic 数组
			if offset+4 <= len(data) {
				topicArrayLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
				offset += 4

				if topicArrayLen > 0 && offset+2 <= len(data) {
					// 第一个 topic 的名称
					topicNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
					offset += 2
					if offset+topicNameLen <= len(data) {
						request.Topic = string(data[offset : offset+topicNameLen])
					}
				}
			}
		}

	case KafkaAPIFetch:
		// Fetch 请求
		if offset+4 <= len(data) {
			// max wait time
			offset += 4
		}
		if offset+4 <= len(data) {
			// min bytes
			offset += 4
		}
		if offset+4 <= len(data) {
			// max bytes
			offset += 4
		}
		if offset+1 <= len(data) {
			// isolation level
			offset++
		}

		// topic 数组
		if offset+4 <= len(data) {
			topicArrayLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4

			if topicArrayLen > 0 && offset+2 <= len(data) {
				topicNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+topicNameLen <= len(data) {
					request.Topic = string(data[offset : offset+topicNameLen])
				}
			}
		}

	case KafkaAPIMetadata:
		// Metadata 请求
		if offset+4 <= len(data) {
			topicArrayLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4

			if topicArrayLen > 0 && offset+2 <= len(data) {
				topicNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+topicNameLen <= len(data) {
					request.Topic = string(data[offset : offset+topicNameLen])
				}
			}
		}

	case KafkaAPICreateTopics:
		// CreateTopics 请求
		if offset+4 <= len(data) {
			topicArrayLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4

			if topicArrayLen > 0 && offset+2 <= len(data) {
				topicNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+topicNameLen <= len(data) {
					request.Topic = string(data[offset : offset+topicNameLen])
				}
			}
		}

	case KafkaAPIDeleteTopics:
		// DeleteTopics 请求
		if offset+4 <= len(data) {
			topicArrayLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4

			if topicArrayLen > 0 && offset+2 <= len(data) {
				topicNameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+topicNameLen <= len(data) {
					request.Topic = string(data[offset : offset+topicNameLen])
				}
			}
		}
	}

	return request, nil
}

// ParseKafkaResponse 解析 Kafka 响应
func ParseKafkaResponse(data []byte) (*KafkaResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for Kafka response")
	}

	header, offset, err := ParseKafkaResponseHeader(data)
	if err != nil {
		return nil, err
	}

	response := &KafkaResponse{
		Header: *header,
	}

	// 响应体根据 API Key 不同而不同
	// 这里只解析头部

	return response, nil
}

// GetKafkaAPIKeyName 获取 Kafka API Key 名称
func GetKafkaAPIKeyName(apiKey KafkaAPIKey) string {
	if name, ok := kafkaAPIKeyNames[apiKey]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", int16(apiKey))
}

// IsKafkaPacket 检查是否是 Kafka 协议包
func IsKafkaPacket(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	// 检查消息大小（前4字节）
	messageSize := int32(binary.BigEndian.Uint32(data[0:4]))
	if messageSize < 0 || messageSize > 10485760 { // 10MB 最大消息大小
		return false
	}

	// 检查 API Key（前4字节之后）
	apiKey := int16(binary.BigEndian.Uint16(data[4:6]))
	if apiKey < 0 || apiKey > 62 { // Kafka API Key 范围
		return false
	}

	// 检查 API 版本
	apiVersion := int16(binary.BigEndian.Uint16(data[6:8]))
	if apiVersion < 0 || apiVersion > 20 { // 合理的版本范围
		return false
	}

	return true
}

// KafkaTopicPartition Kafka Topic-Partition 信息
type KafkaTopicPartition struct {
	Topic     string
	Partition int32
	Offset    int64
}

// KafkaMessage Kafka 消息
type KafkaMessage struct {
	Offset      int64
	Timestamp   int64
	Key         []byte
	Value       []byte
	Headers     map[string][]byte
}

// KafkaRecordBatch Kafka 记录批次
type KafkaRecordBatch struct {
	Partition      int32
	Offset         int64
	Timestamp      int64
	Magic          int8
	CRC            int32
	Attributes     int16
	LastOffsetDelta int32
	FirstTimestamp int64
	MaxTimestamp   int64
	ProducerID     int64
	ProducerEpoch  int16
	BaseSequence   int32
	Records        []KafkaMessage
}
