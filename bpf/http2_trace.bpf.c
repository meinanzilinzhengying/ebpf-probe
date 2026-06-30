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

// HTTP/2 帧类型
#define HTTP2_FRAME_DATA          0x0
#define HTTP2_FRAME_HEADERS       0x1
#define HTTP2_FRAME_PRIORITY      0x2
#define HTTP2_FRAME_RST_STREAM    0x3
#define HTTP2_FRAME_SETTINGS      0x4
#define HTTP2_FRAME_PUSH_PROMISE  0x5
#define HTTP2_FRAME_PING          0x6
#define HTTP2_FRAME_GOAWAY        0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION  0x9

// HTTP/2 帧标志
#define HTTP2_FLAG_END_STREAM  0x1
#define HTTP2_FLAG_END_HEADERS 0x4
#define HTTP2_FLAG_PADDED      0x8
#define HTTP2_FLAG_PRIORITY    0x20

// Go HTTP/2 运行时函数偏移量（需要根据 Go 版本调整）
// go.opencensus.io/plugin/ochttp 内部使用
// net/http/h2 包的函数

// HTTP/2 Server operateHeaders 偏移量
// func (sc *serverConn) operateHeaders(frame *MetaFrame) error
#define HTTP2_SERVER_OPERATE_HEADERS_FRAME_OFFSET 0

// HTTP/2 Client readLoop handleResponse 偏移量
// func (rl *readLoop) handleResponse(cs *clientStream, res *Response, err error) error
#define HTTP2_CLIENT_HANDLE_RESPONSE_STREAM_OFFSET 0

// HTTP/2 帧解析结构
struct http2_header_state {
    __u32 stream_id;
    __u8  frame_type;
    __u8  flags;
    __u32 payload_len;
};

// 挂载 Go HTTP/2 Server operateHeaders
// 需要根据实际的 Go 程序调整偏移量
SEC("uprobe/go_http2_server_operate_headers")
int BPF_UPROBE(go_http2_server_operate_headers, void *frame) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_HEADERS;
    get_comm(e.comm);

    // 尝试从 frame 结构体读取信息
    // 实际实现需要根据 Go 版本和结构体布局调整
    
    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Client readLoop handleResponse
SEC("uprobe/go_http2_client_read_loop_handle_response")
int BPF_UPROBE(go_http2_client_read_loop_handle_response, void *cs, void *res) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_HEADERS;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Server processHeaders
SEC("uprobe/go_http2_server_process_headers")
int BPF_UPROBE(go_http2_server_process_headers, void *frame) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_HEADERS;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Client writeHeaders
SEC("uprobe/go_http2_client_write_headers")
int BPF_UPROBE(go_http2_client_write_headers, void *cc, void *headers) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_HEADERS;
    e.flags = HTTP2_FLAG_END_HEADERS;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Client writeData
SEC("uprobe/go_http2_client_write_data")
int BPF_UPROBE(go_http2_client_write_data, void *cc, __u32 stream_id, void *data, int len) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 DATA 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_DATA;
    e.stream_id = stream_id;
    e.payload_len = len;
    get_comm(e.comm);

    // 尝试读取数据
    if (data && len > 0) {
        int copy_len = len < DATA_LEN ? len : DATA_LEN;
        bpf_probe_read_user(e.data, copy_len, data);
    }

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Client readData
SEC("uprobe/go_http2_client_read_data")
int BPF_UPROBE(go_http2_client_read_data, void *cs, void *frame) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 DATA 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    e.frame_type = HTTP2_FRAME_DATA;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Server writeFrame
SEC("uprobe/go_http2_server_write_frame")
int BPF_UPROBE(go_http2_server_write_frame, void *sc, void *frame) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// 挂载 Go HTTP/2 Client readFrame
SEC("uprobe/go_http2_client_read_frame")
int BPF_UPROBE(go_http2_client_read_frame, void *cc) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 创建 HTTP/2 帧事件
    struct http2_frame e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_HTTP2_FRAME;
    e.pid = pid;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

    return 0;
}

// HPACK 头部解压相关（用户态实现）
// HPACK 使用动态表和静态表进行头部压缩
// 静态表定义了 61 个常见的头部键值对
// 动态表在连接生命周期内维护

// HPACK 整数编码
static __always_inline int hpack_decode_int(void *data, int prefix, int *value) {
    unsigned char *p = (unsigned char *)data;
    int result = *p & ((1 << prefix) - 1);
    
    if (result < ((1 << prefix) - 1)) {
        *value = result;
        return 1;
    }
    
    int shift = 0;
    int i = 1;
    while (1) {
        int byte = p[i];
        result += (byte & 0x7f) << shift;
        shift += 7;
        i++;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    
    *value = result;
    return i;
}

char LICENSE[] SEC("license") = "GPL";
