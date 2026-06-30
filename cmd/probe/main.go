package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"ebpf-probe/internal/collector"
	"ebpf-probe/internal/kernel"
	"ebpf-probe/internal/k8s"
	"ebpf-probe/internal/output"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

type Config struct {
	ProbeID   string `yaml:"probe_id"`
	Interface string `yaml:"interface"`
	APIPort   string `yaml:"api_port"`

	ClickhouseAddr     string `yaml:"clickhouse_addr"`
	ClickhouseUser     string `yaml:"clickhouse_user"`
	ClickhousePassword string `yaml:"clickhouse_password"`
	ClickhouseDatabase string `yaml:"clickhouse_database"`

	EdgeAddr string `yaml:"edge_addr"`

	Collectors collector.CollectorConfig `yaml:"collectors"`

	TLS struct {
		Enabled          bool     `yaml:"enabled"`
		Libraries        []string `yaml:"libraries"`
		CaptureHandshake bool     `yaml:"capture_handshake"`
	} `yaml:"tls"`

	HTTP2 struct {
		Enabled    bool `yaml:"enabled"`
		DecodeHPACK bool `yaml:"decode_hpack"`
	} `yaml:"http2"`

	Sniffer struct {
		Enabled     bool            `yaml:"enabled"`
		Protocols   []string        `yaml:"protocols"`
		PortOverride map[uint16]string `yaml:"port_override"`
	} `yaml:"sniffer"`

	LogCollect struct {
		Enabled        bool     `yaml:"enabled"`
		BufferSize     int      `yaml:"buffer_size"`
		MaxLineLength  int      `yaml:"max_line_length"`
		FilterPatterns []string `yaml:"filter_patterns"`
	} `yaml:"log_collect"`

	Kubernetes struct {
		Enabled           bool   `yaml:"enabled"`
		Mode              string `yaml:"mode"`
		APIServer         string `yaml:"api_server"`
		TokenPath         string `yaml:"token_path"`
		NamespaceFilter   string `yaml:"namespace_filter"`
		PodLabelSelector  string `yaml:"pod_label_selector"`
		NodeName          string `yaml:"node_name"`
		EnrichEvents      bool   `yaml:"enrich_events"`
	} `yaml:"kubernetes"`

	Offsets struct {
		Mode       string `yaml:"mode"`
		ManualPath string `yaml:"manual_path"`
	} `yaml:"offsets"`

	LogLevel string `yaml:"log_level"`
}

func main() {
	configPath := flag.String("config", "config/config.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "显示版本信息")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ebpf-probe %s (built %s)\n", version, buildDate)
		os.Exit(0)
	}

	// 加载配置
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// 检测内核能力
	cap, err := kernel.DetectCapabilities()
	if err != nil {
		log.Fatalf("detect capabilities: %v", err)
	}
	log.Printf("kernel: %s, capabilities: %v", cap.Version, cap.AvailableHooks)

	// 初始化偏移量
	offsetDetector := kernel.NewOffsetDetector(cfg.Offsets.Mode, cfg.Offsets.ManualPath)
	offsets, err := offsetDetector.Detect()
	if err != nil {
		log.Printf("warning: offset detection failed: %v", err)
	} else {
		log.Printf("detected kernel offsets for %s", offsets.KernelVersion)
	}
	_ = offsets

	// 创建输出管道
	var writers []output.Writer

	// Edge 输出
	if cfg.EdgeAddr != "" {
		edgeClient := output.NewEdgeClient(cfg.EdgeAddr, cfg.ProbeID)
		edgeClient.Start()
		writers = append(writers, edgeClient)
	}

	// ClickHouse 输出
	if cfg.ClickhouseAddr != "" {
		chWriter, err := output.NewClickHouseWriter(
			cfg.ClickhouseAddr, cfg.ClickhouseUser,
			cfg.ClickhousePassword, cfg.ClickhouseDatabase,
		)
		if err != nil {
			log.Printf("warning: clickhouse connect failed: %v", err)
		} else {
			writers = append(writers, chWriter)
		}
	}

	// 创建 multi-writer
	out := output.NewMultiWriter(writers...)

	// 创建采集器管理器
	mgr := collector.NewManager(cap, out, cfg.ProbeID)
	if err := mgr.InitFromConfig(cfg.Collectors); err != nil {
		log.Fatalf("init collectors: %v", err)
	}

	// Kubernetes 集成
	var k8sEnricher *k8s.EventEnricher
	if cfg.Kubernetes.Enabled {
		k8sClient, err := k8s.NewK8sClient(
			cfg.Kubernetes.APIServer,
			cfg.Kubernetes.TokenPath,
			cfg.Kubernetes.NodeName,
			cfg.Kubernetes.NamespaceFilter,
		)
		if err != nil {
			log.Printf("warning: k8s client init failed: %v", err)
		} else {
			ctx := context.Background()
			if err := k8sClient.Start(ctx); err != nil {
				log.Printf("warning: k8s client start failed: %v", err)
			} else {
				k8sEnricher, _ = k8s.NewEventEnricher(k8sClient)
				if k8sEnricher != nil {
					k8sEnricher.Start(ctx)
				}
				log.Printf("kubernetes integration enabled, node: %s", cfg.Kubernetes.NodeName)
			}
		}
	}
	_ = k8sEnricher

	// 启动所有采集器
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.StartAll(ctx); err != nil {
		log.Fatalf("start collectors: %v", err)
	}

	// 启动 API 服务器
	if cfg.APIPort != "" {
		go startAPIServer(cfg.APIPort, mgr)
	}

	log.Printf("ebpf-probe started (probe_id=%s)", cfg.ProbeID)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("shutting down...")
	mgr.StopAll()
	out.Close()
	log.Printf("ebpf-probe stopped")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 环境变量覆盖
	if v := os.Getenv("EDGE_ADDR"); v != "" {
		cfg.EdgeAddr = v
	}
	if v := os.Getenv("PROBE_ID"); v != "" {
		cfg.ProbeID = v
	}
	if v := os.Getenv("INTERFACE"); v != "" {
		cfg.Interface = v
	}
	if v := os.Getenv("CLICKHOUSE_ADDR"); v != "" {
		cfg.ClickhouseAddr = v
	}
	if v := os.Getenv("NODE_NAME"); v != "" {
		cfg.Kubernetes.NodeName = v
	}

	return cfg, nil
}

func startAPIServer(port string, mgr *collector.Manager) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := mgr.Status()
		w.Header().Set("Content-Type", "application/json")
		// 简单 JSON 输出
		w.Write([]byte(`{"collectors":{}`))
		_ = status
	})

	addr := ":" + port
	log.Printf("API server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("API server error: %v", err)
	}
}
