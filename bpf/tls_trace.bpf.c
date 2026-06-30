// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CloudFlow Team

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义 TLS 连接信息结构体
struct tls_conn_info {
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;          // SSL* 指针
    __u64 fd;               // 文件描述符
    __u64 read_bytes;       // 读取的字节数
    __u64 write_bytes;      // 写入的字节数
};

// 定义 map 用于跟踪 SSL 连接
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);         // SSL* 指针
    __type(value, struct tls_conn_info);
} ssl_connections SEC(".maps");

// 定义 ring buffer 用于输出事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// OpenSSL SSL_read uprobe 参数偏移量
// int SSL_read(SSL *ssl, void *buf, int num)
#define SSL_READ_SSL_OFFSET 0
#define SSL_READ_BUF_OFFSET 1
#define SSL_READ_NUM_OFFSET 2

// OpenSSL SSL_write uprobe 参数偏移量
// int SSL_write(SSL *ssl, const void *buf, int num)
#define SSL_WRITE_SSL_OFFSET 0
#define SSL_WRITE_BUF_OFFSET 1
#define SSL_WRITE_NUM_OFFSET 2

// OpenSSL SSL_get_fd uprobe 参数偏移量
// int SSL_get_fd(SSL *ssl)
#define SSL_GET_FD_SSL_OFFSET 0

// 从 SSL 结构体中读取 FD (简化版本，实际需要根据 OpenSSL 版本调整)
static __always_inline __u64 get_ssl_fd(void *ssl_ptr) {
    __u64 fd = 0;
    // 注意：实际实现需要根据 OpenSSL 版本确定 fd 在 SSL 结构体中的偏移量
    // 这里简化处理，通过 fd map 获取
    return fd;
}

// SSL_read uprobe 处理函数
SEC("uprobe/ssl_read")
int BPF_UPROBE(trace_ssl_read, void *ssl, void *buf, int num) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    // 获取 SSL 指针作为 key
    __u64 ssl_ptr = (__u64)ssl;

    // 记录 SSL 连接信息
    struct tls_conn_info info = {};
    info.pid = pid;
    info.tid = tid;
    info.ssl_ptr = ssl_ptr;
    
    bpf_map_update_elem(&ssl_connections, &ssl_ptr, &info, BPF_ANY);

    return 0;
}

// SSL_read kprobe 处理函数（用于获取返回值）
SEC("kprobe/ssl_read_ret")
int BPF_KPROBE(trace_ssl_read_ret, int ret) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 如果读取失败，忽略
    if (ret <= 0) {
        return 0;
    }

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 1;  // read
    e.data_len = ret;
    get_comm(e.comm);

    // 尝试从 buf 读取数据（需要用户态配合）
    // 这里只记录数据长度，实际数据在用户态读取

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// SSL_write uprobe 处理函数
SEC("uprobe/ssl_write")
int BPF_UPROBE(trace_ssl_write, void *ssl, const void *buf, int num) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 2;  // write
    e.data_len = num;
    get_comm(e.comm);

    // 尝试从 buf 读取数据
    if (buf && num > 0) {
        int len = num < TLS_DATA_LEN ? num : TLS_DATA_LEN;
        bpf_probe_read_user(e.data, len, buf);
    }

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// SSL_do_handshake uprobe 处理函数
SEC("uprobe/ssl_do_handshake")
int BPF_UPROBE(trace_ssl_do_handshake, void *ssl) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 握手事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_HANDSHAKE;
    e.pid = pid;
    e.event_type = 0;  // handshake
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// SSL_get_servername uprobe 处理函数（获取 SNI）
SEC("uprobe/ssl_get_servername")
int BPF_UPROBE(trace_ssl_get_servername, void *ssl) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 握手事件（带 SNI）
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_HANDSHAKE;
    e.pid = pid;
    e.event_type = 0;  // handshake
    get_comm(e.comm);

    // SNI 需要用户态配合读取

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// BoringSSL SSL_read uprobe
SEC("uprobe/boring_ssl_read")
int BPF_UPROBE(trace_boring_ssl_read, void *ssl, void *buf, int num) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 1;  // read
    e.data_len = num;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// BoringSSL SSL_write uprobe
SEC("uprobe/boring_ssl_write")
int BPF_UPROBE(trace_boring_ssl_write, void *ssl, const void *buf, int num) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 2;  // write
    e.data_len = num;
    get_comm(e.comm);

    // 尝试从 buf 读取数据
    if (buf && num > 0) {
        int len = num < TLS_DATA_LEN ? num : TLS_DATA_LEN;
        bpf_probe_read_user(e.data, len, buf);
    }

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// GnuTLS gnutls_record_send uprobe
SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(trace_gnutls_record_send, void *session, const void *data, size_t sizeofdata) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 2;  // write
    e.data_len = sizeofdata;
    get_comm(e.comm);

    // 尝试从 data 读取
    if (data && sizeofdata > 0) {
        int len = sizeofdata < TLS_DATA_LEN ? sizeofdata : TLS_DATA_LEN;
        bpf_probe_read_user(e.data, len, data);
    }

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// GnuTLS gnutls_record_recv uprobe
SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(trace_gnutls_record_recv, void *session, void *data, size_t sizeofdata) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 TLS 事件
    struct tls_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_TLS_DATA;
    e.pid = pid;
    e.event_type = 1;  // read
    e.data_len = sizeofdata;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
