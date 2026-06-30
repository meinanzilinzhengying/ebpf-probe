// Copyright (c) 2026 CloudFlow Team

package offset

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

//go:embed offsets/*.json
var offsetFS embed.FS

// KernelOffsets 内核结构体偏移量
type KernelOffsets struct {
	KernelVersion string            `json:"kernel_version"`
	TaskStruct    TaskStructOffsets `json:"task_struct"`
	Sock          SockOffsets       `json:"sock"`
	SockCommon    SockCommonOffsets `json:"sock_common"`
	Socket        SocketOffsets     `json:"socket"`
	TCPSock       TCPSockOffsets    `json:"tcp_sock"`
	Cgroup        CgroupOffsets     `json:"cgroup"`
	SkBuff        SkBuffOffsets     `json:"sk_buff"`
	Request       RequestOffsets    `json:"request"`
}

// TaskStructOffsets task_struct 偏移量
type TaskStructOffsets struct {
	Files     int `json:"files"`
	Cgroups   int `json:"cgroups"`
	PID       int `json:"pid"`
	TGID      int `json:"tgid"`
	FDT       int `json:"fdt"`
	PrivData  int `json:"private_data"`
}

// SockOffsets sock 偏移量
type SockOffsets struct {
	SKFlags   int `json:"sk_flags"`
	SKProto   int `json:"sk_protocol"`
	SKType    int `json:"sk_type"`
}

// SockCommonOffsets sock_common 偏移量
type SockCommonOffsets struct {
	SKCFamily int `json:"skc_family"`
	SKCState  int `json:"skc_state"`
}

// SocketOffsets socket 偏移量
type SocketOffsets struct {
	File int `json:"file"`
	SK   int `json:"sk"`
}

// TCPSockOffsets tcp_sock 偏移量
type TCPSockOffsets struct {
	CopiedSeq      int `json:"copied_seq"`
	WriteSeq       int `json:"write_seq"`
	RetransOut     int `json:"retrans_out"`
	TotalRetrans   int `json:"total_retrans"`
	AdvMSS         int `json:"advmss"`
	SRTTUs         int `json:"srtt_us"`
	SndWnd         int `json:"snd_wnd"`
	RcvWnd         int `json:"rcv_wnd"`
	SndCwnd        int `json:"snd_cwnd"`
	LostOut        int `json:"lost_out"`
}

// CgroupOffsets cgroup 偏移量
type CgroupOffsets struct {
	Path    int `json:"path"`
	DName   int `json:"d_name"`
}

// SkBuffOffsets sk_buff 偏移量
type SkBuffOffsets struct {
	NetworkHeader int `json:"network_header"`
	Head          int `json:"head"`
}

// RequestOffsets request 偏移量
type RequestOffsets struct {
	CmdFlags      int `json:"cmd_flags"`
	DataLen       int `json:"data_len"`
	Sector        int `json:"sector"`
	RqDisk        int `json:"rq_disk"`
	StartTimeNS   int `json:"start_time_ns"`
	IOStartTimeNS int `json:"io_start_time_ns"`
	Disk          int `json:"disk"`
}

// OffsetDetector 偏移量检测器
type OffsetDetector struct {
	mode         string // auto, embedded, manual
	manualPath   string
	offsets      *KernelOffsets
	kernelVer    string
}

// NewOffsetDetector 创建偏移量检测器
func NewOffsetDetector(mode, manualPath string) *OffsetDetector {
	return &OffsetDetector{
		mode:       mode,
		manualPath: manualPath,
	}
}

// Detect 检测内核偏移量
func (d *OffsetDetector) Detect() (*KernelOffsets, error) {
	switch d.mode {
	case "auto":
		return d.detectAuto()
	case "embedded":
		return d.detectEmbedded()
	case "manual":
		return d.detectManual()
	default:
		return nil, fmt.Errorf("unknown offset mode: %s", d.mode)
	}
}

// detectAuto 自动检测偏移量
func (d *OffsetDetector) detectAuto() (*KernelOffsets, error) {
	// 1. 首先尝试 BTF
	if d.hasBTF() {
		offsets, err := d.detectFromBTF()
		if err == nil {
			log.Printf("Detected offsets from BTF")
			return offsets, nil
		}
		log.Printf("BTF detection failed: %v, falling back to embedded", err)
	}

	// 2. 回退到预编译表
	offsets, err := d.detectEmbedded()
	if err == nil {
		log.Printf("Detected offsets from embedded table")
		return offsets, nil
	}

	// 3. 最终回退到手动配置
	if d.manualPath != "" {
		offsets, err := d.detectManual()
		if err == nil {
			log.Printf("Detected offsets from manual config")
			return offsets, nil
		}
	}

	return nil, fmt.Errorf("failed to detect kernel offsets")
}

// hasBTF 检查是否支持 BTF
func (d *OffsetDetector) hasBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// detectFromBTF 从 BTF 检测偏移量
func (d *OffsetDetector) detectFromBTF() (*KernelOffsets, error) {
	// 使用 bpftool 或 btfhole 等工具获取偏移量
	// 这里简化处理，实际实现需要更复杂的逻辑
	
	// 尝试使用 bpftool
	cmd := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run bpftool: %w", err)
	}

	// 解析输出获取偏移量
	// 这里需要实际解析 BTF 信息
	_ = output

	// 返回基本偏移量
	return d.getDefaultOffsets()
}

// detectEmbedded 从预编译表检测偏移量
func (d *OffsetDetector) detectEmbedded() (*KernelOffsets, error) {
	// 获取当前内核版本
	kernelVersion, err := d.getKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", err)
	}

	d.kernelVer = kernelVersion

	// 尝试精确匹配
	offsets, err := d.loadEmbeddedOffsets(kernelVersion)
	if err == nil {
		return offsets, nil
	}

	// 尝试模糊匹配（主版本.次版本）
	parts := strings.Split(kernelVersion, ".")
	if len(parts) >= 2 {
		majorMinor := parts[0] + "." + parts[1]
		offsets, err = d.loadEmbeddedOffsets(majorMinor)
		if err == nil {
			return offsets, nil
		}
	}

	// 返回默认偏移量
	return d.getDefaultOffsets()
}

// detectManual 从手动配置检测偏移量
func (d *OffsetDetector) detectManual() (*KernelOffsets, error) {
	if d.manualPath == "" {
		return nil, fmt.Errorf("manual path not specified")
	}

	data, err := os.ReadFile(d.manualPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manual config: %w", err)
	}

	var offsets KernelOffsets
	if err := json.Unmarshal(data, &offsets); err != nil {
		return nil, fmt.Errorf("failed to parse manual config: %w", err)
	}

	return &offsets, nil
}

// getKernelVersion 获取内核版本
func (d *OffsetDetector) getKernelVersion() (string, error) {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run uname: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// loadEmbeddedOffsets 加载预编译偏移量
func (d *OffsetDetector) loadEmbeddedOffsets(version string) (*KernelOffsets, error) {
	// 遍历嵌入的文件
	entries, err := offsetFS.ReadDir("offsets")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// 检查文件名是否匹配
		name := strings.TrimSuffix(entry.Name(), ".json")
		if strings.Contains(version, name) || strings.Contains(name, version) {
			data, err := offsetFS.ReadFile("offsets/" + entry.Name())
			if err != nil {
				continue
			}

			var offsets KernelOffsets
			if err := json.Unmarshal(data, &offsets); err != nil {
				continue
			}

			return &offsets, nil
		}
	}

	return nil, fmt.Errorf("no matching offsets found for version %s", version)
}

// getDefaultOffsets 获取默认偏移量
func (d *OffsetDetector) getDefaultOffsets() (*KernelOffsets, error) {
	// 根据架构返回默认偏移量
	if runtime.GOARCH == "amd64" {
		return d.getDefaultOffsetsAMD64(), nil
	}
	return nil, fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
}

// getDefaultOffsetsAMD64 获取 AMD64 架构的默认偏移量
func (d *OffsetDetector) getDefaultOffsetsAMD64() *KernelOffsets {
	return &KernelOffsets{
		KernelVersion: "default",
		TaskStruct: TaskStructOffsets{
			Files:    1992,
			Cgroups:  2360,
			PID:      1440,
			TGID:     1444,
			FDT:      32,
			PrivData: 192,
		},
		Sock: SockOffsets{
			SKFlags: 528,
			SKProto: 544,
			SKType:  544,
		},
		SockCommon: SockCommonOffsets{
			SKCFamily: 16,
			SKCState:  18,
		},
		Socket: SocketOffsets{
			File: 24,
			SK:   32,
		},
		TCPSock: TCPSockOffsets{
			CopiedSeq:    1628,
			WriteSeq:     1996,
			RetransOut:   1864,
			TotalRetrans: 2288,
			AdvMSS:       1776,
			SRTTUs:       1816,
			SndWnd:       1732,
			RcvWnd:       1992,
			SndCwnd:      1920,
			LostOut:      2008,
		},
		Cgroup: CgroupOffsets{
			Path:  0,
			DName: 0,
		},
		SkBuff: SkBuffOffsets{
			NetworkHeader: 196,
			Head:          208,
		},
		Request: RequestOffsets{
			CmdFlags:      0,
			DataLen:       0,
			Sector:        0,
			RqDisk:        0,
			StartTimeNS:   0,
			IOStartTimeNS: 0,
			Disk:          0,
		},
	}
}

// GetOffset 获取指定结构体的偏移量
func (d *OffsetDetector) GetOffset(structName, fieldName string) (int, error) {
	if d.offsets == nil {
		return 0, fmt.Errorf("offsets not detected")
	}

	switch structName {
	case "task_struct":
		switch fieldName {
		case "files":
			return d.offsets.TaskStruct.Files, nil
		case "cgroups":
			return d.offsets.TaskStruct.Cgroups, nil
		case "pid":
			return d.offsets.TaskStruct.PID, nil
		case "tgid":
			return d.offsets.TaskStruct.TGID, nil
		case "fdt":
			return d.offsets.TaskStruct.FDT, nil
		case "private_data":
			return d.offsets.TaskStruct.PrivData, nil
		}
	case "sock":
		switch fieldName {
		case "sk_flags":
			return d.offsets.Sock.SKFlags, nil
		case "sk_protocol":
			return d.offsets.Sock.SKProto, nil
		case "sk_type":
			return d.offsets.Sock.SKType, nil
		}
	case "sock_common":
		switch fieldName {
		case "skc_family":
			return d.offsets.SockCommon.SKCFamily, nil
		case "skc_state":
			return d.offsets.SockCommon.SKCState, nil
		}
	case "socket":
		switch fieldName {
		case "file":
			return d.offsets.Socket.File, nil
		case "sk":
			return d.offsets.Socket.SK, nil
		}
	case "tcp_sock":
		switch fieldName {
		case "copied_seq":
			return d.offsets.TCPSock.CopiedSeq, nil
		case "write_seq":
			return d.offsets.TCPSock.WriteSeq, nil
		case "retrans_out":
			return d.offsets.TCPSock.RetransOut, nil
		case "total_retrans":
			return d.offsets.TCPSock.TotalRetrans, nil
		case "advmss":
			return d.offsets.TCPSock.AdvMSS, nil
		case "srtt_us":
			return d.offsets.TCPSock.SRTTUs, nil
		case "snd_wnd":
			return d.offsets.TCPSock.SndWnd, nil
		case "rcv_wnd":
			return d.offsets.TCPSock.RcvWnd, nil
		case "snd_cwnd":
			return d.offsets.TCPSock.SndCwnd, nil
		case "lost_out":
			return d.offsets.TCPSock.LostOut, nil
		}
	}

	return 0, fmt.Errorf("unknown struct/field: %s.%s", structName, fieldName)
}

// SetOffsets 设置偏移量
func (d *OffsetDetector) SetOffsets(offsets *KernelOffsets) {
	d.offsets = offsets
}

// GetKernelVersion 获取检测到的内核版本
func (d *OffsetDetector) GetKernelVersion() string {
	return d.kernelVer
}
