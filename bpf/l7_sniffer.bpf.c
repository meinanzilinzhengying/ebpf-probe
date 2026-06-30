// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CloudFlow Team

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义 ring buffer 用于输出事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// L7 协议类型
#define L7_PROTOCOL_HTTP   1
#define L7_PROTOCOL_MYSQL  2
#define L7_PROTOCOL_REDIS  3
#define L7_PROTOCOL_KAFKA  4
#define L7_PROTOCOL_DUBBO  5

// 端口号定义
#define PORT_HTTP     80
#define PORT_HTTPS    443
#define PORT_HTTP_8080 8080
#define PORT_MYSQL    3306
#define PORT_REDIS    6379
#define PORT_KAFKA    9092
#define PORT_DUBBO    20880

// MySQL 协议特征
#define MYSQL_MAGIC   0x00  // MySQL 协议第一个字节通常是 0x00

// Redis 协议特征
#define RESP_ARRAY    '*'   // 数组
#define RESP_BULK     '$'   // 批量字符串
#define RESP_SIMPLE   '+'   // 简单字符串
#define RESP_ERROR    '-'   // 错误
#define RESP_INTEGER  ':'   // 整数

// Kafka 协议特征
#define KAFKA_MAGIC_0 0x00  // Kafka 0.8.x
#define KAFKA_MAGIC_1 0x01  // Kafka 0.9.x - 0.10.x
#define KAFKA_MAGIC_2 0x02  // Kafka 0.11.x+

// Dubbo 协议特征
#define DUBBO_MAGIC   0xdabb  // Dubbo 协议魔数

// 检测 L7 协议类型
static __always_inline int detect_l7_protocol(void *data, int data_len, __u16 port) {
    if (data_len < 4) {
        return 0;
    }

    unsigned char *payload = (unsigned char *)data;

    // 根据端口号预分类
    switch (port) {
        case PORT_HTTP:
        case PORT_HTTPS:
        case PORT_HTTP_8080:
            // 检查 HTTP 方法
            if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') {
                return L7_PROTOCOL_HTTP;
            }
            if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') {
                return L7_PROTOCOL_HTTP;
            }
            if (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') {
                return L7_PROTOCOL_HTTP;
            }
            if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T') {
                return L7_PROTOCOL_HTTP;
            }
            if (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') {
                return L7_PROTOCOL_HTTP;
            }
            if (payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I') {
                return L7_PROTOCOL_HTTP;
            }
            break;

        case PORT_MYSQL:
            // MySQL 协议检测
            // 握手包: 0x00 + 协议版本 + 服务器版本字符串
            if (payload[0] == 0x00) {
                return L7_PROTOCOL_MYSQL;
            }
            // 查询包: 0x03 + 序列号 + SQL
            if (payload[0] == 0x03) {
                return L7_PROTOCOL_MYSQL;
            }
            break;

        case PORT_REDIS:
            // Redis 协议检测
            if (payload[0] == RESP_ARRAY || payload[0] == RESP_BULK ||
                payload[0] == RESP_SIMPLE || payload[0] == RESP_ERROR ||
                payload[0] == RESP_INTEGER) {
                return L7_PROTOCOL_REDIS;
            }
            break;

        case PORT_KAFKA:
            // Kafka 协议检测
            if (data_len >= 4) {
                __s32 length = *((__s32 *)payload);
                if (length > 0 && length < 1048576) {  // 1MB 合理范围
                    return L7_PROTOCOL_KAFKA;
                }
            }
            break;

        case PORT_DUBBO:
            // Dubbo 协议检测
            if (data_len >= 2) {
                __u16 magic = *((__u16 *)payload);
                if (magic == DUBBO_MAGIC) {
                    return L7_PROTOCOL_DUBBO;
                }
            }
            break;
    }

    // 无端口匹配时，尝试特征检测
    // HTTP 检测（更宽松）
    if (data_len >= 8) {
        if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') {
            return L7_PROTOCOL_HTTP;  // HTTP 响应
        }
    }

    return 0;
}

// tcp_sendmsg kprobe 处理函数
SEC("kprobe/tcp_sendmsg_l7")
int BPF_KPROBE(trace_tcp_sendmsg_l7, void *sk, void *msghdr, size_t size) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取 socket 信息
    struct sock *skp = (struct sock *)sk;
    struct sock_common common;
    bpf_probe_read_kernel(&common, sizeof(common), &skp->__sk_common);

    __u16 sport = common.skc_num;
    __u16 dport = bpf_ntohs(common.skc_dport);

    // 尝试检测 L7 协议（需要访问用户空间数据，这里简化处理）
    // 实际实现需要通过 msghdr 获取数据

    return 0;
}

// tcp_recvmsg kprobe 处理函数
SEC("kprobe/tcp_recvmsg_l7")
int BPF_KPROBE(trace_tcp_recvmsg_l7, void *sk, void *msghdr, size_t len, int flags) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取 socket 信息
    struct sock *skp = (struct sock *)sk;
    struct sock_common common;
    bpf_probe_read_kernel(&common, sizeof(common), &skp->__sk_common);

    __u16 sport = common.skc_num;
    __u16 dport = bpf_ntohs(common.skc_dport);

    // 尝试检测 L7 协议
    // 实际实现需要通过 msghdr 获取数据

    return 0;
}

// 用于在用户态检测 L7 协议的辅助函数
// 实际的协议检测在用户态完成，因为 eBPF 难以直接访问用户空间数据

char LICENSE[] SEC("license") = "GPL";
