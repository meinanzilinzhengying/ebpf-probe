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

// 定义 map 用于跟踪 write 系统调用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);     // pid_tgid
    __type(value, __u32);   // fd
} write_args SEC(".maps");

// write 系统调用参数
// ssize_t write(int fd, const void *buf, size_t count)
#define WRITE_FD_OFFSET 0
#define WRITE_BUF_OFFSET 1
#define WRITE_COUNT_OFFSET 2

// writev 系统调用参数
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
#define WRITEV_FD_OFFSET 0
#define WRITEV_IOV_OFFSET 1
#define WRITEV_IOVCNT_OFFSET 2

// 标准输出文件描述符
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

// 检查是否是标准输出/错误
static __always_inline int is_stdout_stderr(__u32 fd) {
    return fd == STDOUT_FILENO || fd == STDERR_FILENO;
}

// 检查文件描述符是否指向终端
static __always_inline int is_tty_fd(__u32 fd) {
    // 通过 /proc/self/fd/<fd> 检查是否是 tty
    // 简化处理：假设 fd 0,1,2 都是 tty
    return fd <= 2;
}

// write 系统调用 enter 处理函数
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取参数
    __u32 fd = (__u32)ctx->args[0];
    const void *buf = (const void *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    // 只捕获标准输出和错误输出
    if (!is_stdout_stderr(fd)) {
        return 0;
    }

    // 保存 fd 到 map
    bpf_map_update_elem(&write_args, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

// write 系统调用 exit 处理函数
SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取返回值
    long ret = ctx->ret;

    // 检查是否成功写入
    if (ret <= 0) {
        return 0;
    }

    // 从 map 获取 fd
    __u32 *fd_ptr = bpf_map_lookup_elem(&write_args, &pid_tgid);
    if (!fd_ptr) {
        return 0;
    }

    __u32 fd = *fd_ptr;

    // 确保是标准输出/错误
    if (!is_stdout_stderr(fd)) {
        goto cleanup;
    }

    // 创建日志事件
    struct log_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_LOG_COLLECT;
    e.pid = pid;
    e.fd = fd;
    e.data_len = ret;
    get_comm(e.comm);

    // 注意：实际读取 buf 内容需要通过 msghdr 获取，这里简化处理
    // 实际实现需要在 enter 阶段保存 buf 指针

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

cleanup:
    // 清理 map
    bpf_map_delete_elem(&write_args, &pid_tgid);

    return 0;
}

// writev 系统调用 enter 处理函数
SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取参数
    __u32 fd = (__u32)ctx->args[0];

    // 只捕获标准输出和错误输出
    if (!is_stdout_stderr(fd)) {
        return 0;
    }

    // 保存 fd 到 map
    bpf_map_update_elem(&write_args, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

// writev 系统调用 exit 处理函数
SEC("tracepoint/syscalls/sys_exit_writev")
int trace_sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = get_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取返回值
    long ret = ctx->ret;

    // 检查是否成功写入
    if (ret <= 0) {
        return 0;
    }

    // 从 map 获取 fd
    __u32 *fd_ptr = bpf_map_lookup_elem(&write_args, &pid_tgid);
    if (!fd_ptr) {
        return 0;
    }

    __u32 fd = *fd_ptr;

    // 确保是标准输出/错误
    if (!is_stdout_stderr(fd)) {
        goto cleanup;
    }

    // 创建日志事件
    struct log_event e = {};
    e.timestamp_ns = get_timestamp();
    e.type = EVENT_TYPE_LOG_COLLECT;
    e.pid = pid;
    e.fd = fd;
    e.data_len = ret;
    get_comm(e.comm);

    // 提交事件到 ring buffer
    bpf_ringbuf_submit(&e, 0);

cleanup:
    // 清理 map
    bpf_map_delete_elem(&write_args, &pid_tgid);

    return 0;
}

// 用于捕获 printf/fprintf 等 C 库函数输出
// 这些函数最终会调用 write 系统调用

// 用于捕获 Go 的 fmt.Print/fmt.Println 等函数输出
// Go 的标准输出最终会调用 write 系统调用

// 用于捕获 Java 的 System.out/System.err 输出
// Java 的标准输出最终会调用 write 系统调用

// 用于捕获 Node.js 的 console.log/console.error 输出
// Node.js 的标准输出最终会调用 write 系统调用

char LICENSE[] SEC("license") = "GPL";
