package kernel

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Capabilities 内核能力
type Capabilities struct {
	Version          string
	HasBTF           bool
	HasCO_RE         bool
	HasBPFLSM        bool
	HasBPFTracing    bool
	HasBPFKprobe     bool
	HasBPFTracepoint bool
	HasBPFXDP        bool
	HasBPFTC         bool
	HasBPFPerfEvent  bool
	AvailableHooks   []string
}

// DetectCapabilities 检测内核能力
func DetectCapabilities() (*Capabilities, error) {
	cap := &Capabilities{}

	// 获取内核版本
	ver, err := getKernelVersion()
	if err != nil {
		return nil, err
	}
	cap.Version = ver

	// 检测 BTF
	cap.HasBTF = fileExists("/sys/kernel/btf/vmlinux")
	cap.HasCO_RE = cap.HasBTF

	// 检测 BPF LSM
	cap.HasBPFLSM = checkBPFLSM()

	// 检测 kprobe
	cap.HasBPFKprobe = checkKprobe()

	// 检测 tracepoint
	cap.HasBPFTracepoint = checkTracepoint()

	// 检测 XDP
	cap.HasBPFXDP = checkXDP()

	// 检测 TC
	cap.HasBPFTC = checkTC()

	// 检测 perf event
	cap.HasBPFPerfEvent = checkPerfEvent()

	// 收集可用钩子
	cap.AvailableHooks = collectHooks(cap)

	return cap, nil
}

func getKernelVersion() (string, error) {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkBPFLSM() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "bpf")
}

func checkKprobe() bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "kprobe_dispatcher") {
			return true
		}
	}
	return false
}

func checkTracepoint() bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "bpf_trace_run") {
			return true
		}
	}
	return false
}

func checkXDP() bool {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "eth") || strings.Contains(string(data), "ens")
}

func checkTC() bool {
	_, err := exec.Command("tc", "qdisc", "show").Output()
	return err == nil
}

func checkPerfEvent() bool {
	_, err := os.Stat("/sys/kernel/debug/tracing")
	return err == nil
}

func collectHooks(cap *Capabilities) []string {
	var hooks []string
	if cap.HasBPFKprobe {
		hooks = append(hooks, "kprobe")
	}
	if cap.HasBPFTracepoint {
		hooks = append(hooks, "tracepoint")
	}
	if cap.HasBPFXDP {
		hooks = append(hooks, "xdp")
	}
	if cap.HasBPFTC {
		hooks = append(hooks, "tc")
	}
	if cap.HasBPFPerfEvent {
		hooks = append(hooks, "perf_event")
	}
	return hooks
}
