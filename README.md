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
- **db_trace**: MySQL/Redis/Kafka/Dubbo 协议解析

### 性能分析
- **on_cpu**: CPU 调度分析
- **mem_trace**: 内存分配追踪
- **block_trace**: 块设备 I/O 追踪
- **syscall_trace**: 系统调用追踪

### 安全监控
- **security_trace**: 安全事件采集
- **log_collect**: 应用日志采集 (零侵入)

### 平台集成
- **kubernetes**: K8s 元数据关联 (DaemonSet)
- **cloud_metadata**: 阿里云/华为云/AWS/GCP/Azure 元数据采集
- **vtap**: 流量镜像/转发
- **pingtrace**: 网络路径追踪

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

collectors:
  network_flow: true
  tcp_connect: true
  http_trace: true
  tls_trace: true
  http2_trace: true
  l7_sniffer: true

kubernetes:
  enabled: true
  mode: "incluster"
  enrich_events: true

edge_addr: "localhost:9102"
clickhouse_addr: "localhost"
```

## K8s 部署

```bash
# 创建命名空间
kubectl create namespace cloudflow-system

# 应用 RBAC
kubectl apply -f deploy/k8s/daemonset.yaml

# 验证部署
kubectl get pods -n cloudflow-system
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
├── bpf/                    # 内核态 eBPF 程序
├── cmd/probe/              # 主入口
├── internal/
│   ├── collector/          # 采集器实现
│   ├── kernel/             # 内核能力检测
│   ├── k8s/                # Kubernetes 集成
│   └── output/             # 数据输出
├── pkg/
│   ├── offset/             # 内核偏移量
│   ├── perf/               # 性能分析器
│   └── protocol/           # 协议解析器
├── config/                 # 配置文件
└── deploy/                 # 部署配置
```

## 许可证

MIT License
