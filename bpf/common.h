// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CloudFlow Team

#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>
#include <linux/ptrace.h>

#define TASK_COMM_LEN 16
#define EVENT_LEN     64
#define ARGS_LEN      128
#define FILENAME_LEN  128
#define HOST_LEN      64
#define URL_LEN       128
#define METHOD_LEN    8
#define DATA_LEN      256
#define TLS_DATA_LEN  512

// 事件类型枚举
enum event_type {
    EVENT_TYPE_FLOW = 1,
    EVENT_TYPE_HTTP = 2,
    EVENT_TYPE_DNS = 3,
    EVENT_TYPE_EXEC = 4,
    EVENT_TYPE_EXIT = 5,
    EVENT_TYPE_FILE_OPEN = 6,
    EVENT_TYPE_TCP_CONNECT = 7,
    EVENT_TYPE_SYSCALL = 8,
    EVENT_TYPE_DISK_IO = 9,
    EVENT_TYPE_MYSQL = 10,
    EVENT_TYPE_REDIS = 11,
    EVENT_TYPE_SCHED_SWITCH = 12,
    EVENT_TYPE_SCHED_WAKEUP = 13,
    EVENT_TYPE_KMALLOC = 14,
    EVENT_TYPE_KFREE = 15,
    EVENT_TYPE_BLOCK_ISSUE = 16,
    EVENT_TYPE_BLOCK_COMPLETE = 17,
    EVENT_TYPE_CAP_CAPABLE = 18,
    EVENT_TYPE_SECURITY_FILE_OPEN = 19,
    EVENT_TYPE_LOAD_MODULE = 20,
    // HTTPS/HTTP2 新增事件类型
    EVENT_TYPE_TLS_HANDSHAKE = 30,
    EVENT_TYPE_TLS_DATA = 31,
    EVENT_TYPE_HTTP2_FRAME = 32,
    EVENT_TYPE_LOG_COLLECT = 33,
    EVENT_TYPE_MAX = 34,
};

// 通用事件结构体
struct event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  padding[7];
    __u64 bytes;
    __u64 packets;
    __u64 latency_ns;
    __u64 count;
    char  comm[TASK_COMM_LEN];
    char  data[DATA_LEN];
};

// TLS 事件结构体
struct tls_event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  ssl_version;      // TLS 版本: 0x0301=TLS1.0, 0x0303=TLS1.3
    __u8  event_type;       // 0=handshake, 1=read, 2=write
    __u32 data_len;
    __u64 latency_ns;
    char  comm[TASK_COMM_LEN];
    char  sni[HOST_LEN];    // Server Name Indication
    char  data[TLS_DATA_LEN];
};

// HTTP/2 帧结构体
struct http2_frame {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  frame_type;       // 0=DATA, 1=HEADERS, 2=PRIORITY, 3=RST_STREAM, ...
    __u8  flags;
    __u32 stream_id;
    __u32 payload_len;
    char  comm[TASK_COMM_LEN];
    char  data[DATA_LEN];
};

// L7 协议嗅探事件结构体
struct l7_event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;         // 1=HTTP, 2=MySQL, 3=Redis, 4=Kafka, 5=Dubbo
    __u8  direction;        // 0=request, 1=response
    __u32 data_len;
    __u64 latency_ns;
    char  comm[TASK_COMM_LEN];
    char  data[DATA_LEN];
};

// 日志采集事件结构体
struct log_event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 fd;               // 文件描述符
    __u32 data_len;
    char  comm[TASK_COMM_LEN];
    char  data[DATA_LEN];
};

// BPF 常量
#define MAX_ENTRIES 10240
#define RINGBUF_SIZE (1 << 20)  // 1MB

// 辅助宏
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

// 获取当前进程 PID/TGID
static __always_inline __u64 get_pid_tgid(void) {
    return bpf_get_current_pid_tgid();
}

// 获取当前时间戳
static __always_inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

// 获取当前进程名
static __always_inline void get_comm(char *comm) {
    bpf_get_current_comm(comm, TASK_COMM_LEN);
}

#endif /* __COMMON_H__ */
