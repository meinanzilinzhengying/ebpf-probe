package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ContainerInfo 容器信息
type ContainerInfo struct {
	ContainerID string
	Name        string
	Image       string
	Labels      map[string]string
}

// DockerMapper Docker PID 到容器映射
type DockerMapper struct {
	pidToContainer map[uint32]*ContainerInfo
	mu             sync.RWMutex
	stopCh         chan struct{}
}

// NewDockerMapper 创建 Docker 映射器
func NewDockerMapper() *DockerMapper {
	return &DockerMapper{
		pidToContainer: make(map[uint32]*ContainerInfo),
		stopCh:         make(chan struct{}),
	}
}

// Start 启动映射器
func (d *DockerMapper) Start() {
	go d.refreshLoop()
}

func (d *DockerMapper) refreshLoop() {
	// 初始加载
	d.refresh()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.refresh()
		}
	}
}

func (d *DockerMapper) refresh() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	newMap := make(map[uint32]*ContainerInfo)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		info := d.getContainerByPID(pid)
		if info != nil {
			newMap[pid] = info
		}
	}

	d.mu.Lock()
	d.pidToContainer = newMap
	d.mu.Unlock()
}

func (d *DockerMapper) getContainerByPID(pid uint32) *ContainerInfo {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}

		cgroupPath := parts[2]
		containerID := d.extractContainerID(cgroupPath)
		if containerID != "" {
			return &ContainerInfo{
				ContainerID: containerID,
			}
		}
	}

	return nil
}

func (d *DockerMapper) extractContainerID(cgroupPath string) string {
	// Docker cgroup 路径格式:
	// /system.slice/docker-<containerID>.scope
	// /docker/<containerID>/
	// /kubepods/<pod-uid>/docker/<containerID>

	if strings.Contains(cgroupPath, "docker") {
		// 提取容器 ID
		segments := strings.Split(cgroupPath, "/")
		for _, seg := range segments {
			// docker-xxx.scope
			if strings.HasPrefix(seg, "docker-") && strings.HasSuffix(seg, ".scope") {
				id := strings.TrimPrefix(seg, "docker-")
				id = strings.TrimSuffix(id, ".scope")
				if len(id) >= 12 {
					return id
				}
			}
			// 直接容器 ID
			if len(seg) == 64 || len(seg) == 12 {
				return seg
			}
			// docker/xxx
			if seg == "docker" {
				continue
			}
		}

		// 尝试从路径中提取 64 位 ID
		for _, seg := range segments {
			if len(seg) == 64 {
				return seg
			}
		}
	}

	// containerd cgroup 路径
	if strings.Contains(cgroupPath, "containerd") {
		segments := strings.Split(cgroupPath, "/")
		for _, seg := range segments {
			if len(seg) == 64 {
				return seg
			}
		}
	}

	return ""
}

// GetContainerByPID 根据 PID 获取容器信息
func (d *DockerMapper) GetContainerByPID(pid uint32) *ContainerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.pidToContainer[pid]
}

// Stop 停止映射器
func (d *DockerMapper) Stop() {
	close(d.stopCh)
}

// GetContainerID 获取容器 ID (包级函数)
func GetContainerID(pid uint32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}

		cgroupPath := parts[2]
		// 简化: 直接检查是否包含 Docker 特征
		if strings.Contains(cgroupPath, "docker") || strings.Contains(cgroupPath, "containerd") {
			segments := strings.Split(cgroupPath, "/")
			for _, seg := range segments {
				if len(seg) == 64 {
					return seg
				}
			}
		}
	}

	return ""
}

// GetContainerIDFromCgroup 从 cgroup 路径提取容器 ID
func GetContainerIDFromCgroup(cgroupPath string) string {
	// Docker scope 模式
	if strings.Contains(cgroupPath, "docker-") {
		start := strings.Index(cgroupPath, "docker-") + 7
		end := strings.Index(cgroupPath[start:], ".scope")
		if end > 0 {
			return cgroupPath[start : start+end]
		}
	}

	// 通用 64 位 ID 模式
	segments := strings.Split(cgroupPath, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if len(seg) == 64 {
			return seg
		}
	}

	return ""
}
