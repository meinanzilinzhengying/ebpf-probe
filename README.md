# CloudFlow eBPF Probe

通用 eBPF 数据采集探针框架，支持 x86_64 与 ARM32 双架构。

## 功能特性

### 核心采集器
- **network_flow**: 网络流量采集 (TC/XDP)
- **tcp_connect**: TCP 连接追踪
- **process_exec**: 进程创建/退出追踪
- **host_metrics**: 主机指标 (CPU/内存/磁盘/网络)

### 协议解析
- **http_trace**: HTTP 请求/响应解析
- **dns_trace**: DNS 查询/响应解析
- **tls_trace**: HTTPS/TLS 明文捕获 (OpenSSL/BoringSSL/GnuTLS)
- **http2_trace**: HTTP/2 帧级解析 + HPACK 解压
- **db_trace**: MySQL/Redis/Kafka/Dubbo 协议自动识别

### 性能分析
- **on_cpu**: CPU 调度分析
- **mem_trace**: 内存分配追踪
- **block_trace**: 块设备 I/O 追踪
- **syscall_trace**: 系统调用追踪

### 安全监控
- **security_trace**: 安全事件采集
- **log_collect**: 应用日志采集 (零侵入, 拦截 write/writev)

### 平台集成
- **kubernetes**: K8s 元数据关联 (DaemonSet 部署)
- **cloud_metadata**: 阿里云/华为云/AWS/GCP/Azure 元数据采集
- **vtap**: 流量镜像 (pcap 存储 + UDP 转发)
- **pingtrace**: 网络路径追踪 (类 traceroute)

## 快速开始

### 环境要求
- Linux 内核 >= 4.15
- Go >= 1.22
- Clang >= 12 (编译 BPF 程序)
- root 权限

### 构建

```bash
# 全部编译
make all

# 仅编译 BPF 程序
make bpf

# 仅编译 Go 二进制
make build

# ARM32 交叉编译
make arm32
```

### 安装

```bash
# 安装到 /usr/local/bin/
sudo make install
```

### 运行

```bash
# 默认模式
sudo ./build/ebpf-probe

# 指定配置
sudo ./build/ebpf-probe -config config/config.yaml

# 环境变量覆盖
EDGE_ADDR=192.168.1.100:9102 sudo -E ./build/ebpf-probe
```

## 配置

编辑 `config/config.yaml`:

```yaml
probe_id: "node-probe"
interface: "eth0"

# 采集器开关
collectors:
  network_flow: true
  tcp_connect: true
  host_metrics: true
  http_trace: true
  dns_trace: true
  tls_trace: true
  http2_trace: true
  l7_sniffer: true
  log_collect: false
  syscall: true

# HTTPS 配置
tls:
  enabled: true
  libraries: [openssl, boringssl, gnutls]

# L7 协议嗅探
sniffer:
  enabled: true
  protocols: [mysql, redis, kafka, dubbo]
  port_override:
    3306: mysql
    6379: redis
    9092: kafka
    20880: dubbo

# Kubernetes 配置
kubernetes:
  enabled: true
  mode: "incluster"
  enrich_events: true

# vTap 流量镜像
vtap:
  enabled: false
  mode: "capture"          # capture | receiver
  interface: any
  target_ip: 172.30.1.238
  target_port: 9800
  write_enabled: true
  write_path: /data/pcap
  write_expires: 72h

# 数据输出
edge_addr: "localhost:9102"
clickhouse_addr: "localhost"
```

## K8s 部署

```bash
# 创建命名空间
kubectl create namespace cloudflow-system

# 应用 DaemonSet
kubectl apply -f deploy/k8s/daemonset.yaml

# 验证部署
kubectl get pods -n cloudflow-system -l app=cloudflow-ebpf-probe
kubectl logs -n cloudflow-system -l app=cloudflow-ebpf-probe -f
```

## vTap 流量镜像

vTap 支持两种模式:

**Capture 模式** (被监控节点):
```yaml
vtap:
  mode: capture
  interface: eth0
  target_ip: 172.30.1.238
  target_port: 9800
```

**Receiver 模式** (汇聚节点):
```yaml
vtap:
  mode: receiver
  ip: 0.0.0.0
  port: 9800
  out_interface: Eth3      # 输出到网卡, none=不输出
  write_enabled: true
  write_path: /data/pcap
```

## 内核兼容性

| 能力 | 最低内核 |
|------|---------|
| BTF/CO-RE | 5.8 |
| Ring Buffer | 5.8 |
| Kprobe | 4.1 |
| Tracepoint | 4.7 |
| Perf Event | 4.15 |
| TC (cls_bpf) | 4.1 |
| XDP | 4.8 |

支持的内核版本:
- CentOS 7 (3.10.x)
- Ubuntu 18.04 (4.15.x)
- Ubuntu 20.04 (5.4.x)
- Ubuntu 22.04 (5.15.x)
- Debian 11 (5.10.x)

## 项目结构

```
ebpf-probe/
├── bpf/                          # 内核态 eBPF 程序
│   ├── common.h                  # 公共定义
│   ├── tls_trace.bpf.c           # HTTPS/SSL uprobe
│   ├── http2_trace.bpf.c         # HTTP/2 帧级探针
│   ├── l7_sniffer.bpf.c          # L7 协议嗅探
│   └── log_collect.bpf.c         # 日志采集
├── cmd/probe/main.go             # 主入口
├── internal/
│   ├── collector/                # 采集器实现
│   │   ├── manager.go            # 生命周期管理
│   │   ├── tls_trace.go          # HTTPS 采集器
│   │   ├── http2_trace.go        # HTTP/2 采集器
│   │   ├── log_collect.go        # 日志采集
│   │   ├── vtap.go               # 流量镜像
│   │   ├── pingtrace.go          # 网络路径追踪
│   │   ├── cloud_metadata.go     # 云平台元数据
│   │   └── docker.go             # 容器映射
│   ├── kernel/detector.go        # 内核能力检测
│   ├── k8s/                      # Kubernetes 集成
│   │   ├── client.go             # API 客户端
│   │   └── enricher.go           # 事件增强
│   └── output/                   # 数据输出
│       ├── edge.go               # Edge HTTP 上报
│       ├── clickhouse.go         # ClickHouse 直写
│       └── multi.go              # 多输出聚合
├── pkg/
│   ├── protocol/                 # 协议解析器
│   │   ├── sniffer.go            # L7 嗅探框架
│   │   ├── https.go              # TLS 解析
│   │   ├── http2.go              # HTTP/2 + HPACK
│   │   ├── mysql.go              # MySQL
│   │   ├── redis.go              # Redis
│   │   ├── kafka.go              # Kafka
│   │   └── dubbo.go              # Dubbo
│   ├── perf/analyzer.go          # 性能分析器
│   └── offset/                   # 内核偏移量
│       ├── detector.go           # BTF/预编译/手动
│       └── offsets/              # 预编译偏移量表
├── config/config.yaml            # 配置文件
├── deploy/k8s/daemonset.yaml     # K8s 部署
├── Makefile
└── go.mod
```

## 许可证

MIT License
