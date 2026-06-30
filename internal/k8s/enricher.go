// Copyright (c) 2026 CloudFlow Team

package k8s

import (
	"log"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// EventEnricher 事件增强器
type EventEnricher struct {
	client   *K8sClient
	podCache *lru.Cache[string, *PodInfo]
	mu       sync.RWMutex
	running  bool
	stopCh   chan struct{}
}

// EnrichedEvent 增强后的事件
type EnrichedEvent struct {
	// 原始事件字段
	TimestampNS uint64
	PID         uint32
	EventType   string
	Protocol    string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Bytes       uint64
	LatencyNS   uint64
	Comm        string
	Data        string

	// K8s 增强字段
	PodName      string
	PodNamespace string
	PodUID       string
	NodeName     string
	Labels       map[string]string
	ContainerName string
}

// NewEventEnricher 创建事件增强器
func NewEventEnricher(client *K8sClient) (*EventEnricher, error) {
	// 创建 LRU 缓存
	cache, err := lru.New[string, *PodInfo](10000)
	if err != nil {
		return nil, err
	}

	return &EventEnricher{
		client:   client,
		podCache: cache,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start 启动事件增强器
func (e *EventEnricher) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	// 启动缓存清理协程
	go e.cleanupLoop(ctx)

	e.running = true
	log.Printf("Event enricher started")

	return nil
}

// Stop 停止事件增强器
func (e *EventEnricher) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}

	close(e.stopCh)
	e.running = false
	log.Printf("Event enricher stopped")
}

// Enrich 增强事件
func (e *EventEnricher) Enrich(pid uint32, event *EnrichedEvent) *EnrichedEvent {
	if event == nil {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.client == nil {
		return event
	}

	// 尝试从缓存获取 Pod 信息
	podInfo := e.getPodFromCache(pid)
	if podInfo == nil {
		// 从 K8s 客户端获取
		podInfo = e.client.GetPodByPID(pid)
		if podInfo != nil {
			// 添加到缓存
			e.addToCache(pid, podInfo)
		}
	}

	// 增强事件
	if podInfo != nil {
		event.PodName = podInfo.Name
		event.PodNamespace = podInfo.Namespace
		event.PodUID = podInfo.UID
		event.NodeName = podInfo.NodeName
		event.Labels = podInfo.Labels

		// 获取容器名称
		if len(podInfo.Containers) > 0 {
			event.ContainerName = podInfo.Containers[0].Name
		}
	} else {
		// 尝试从进程名推断
		event.NodeName = e.client.nodeName
	}

	return event
}

// getPodFromCache 从缓存获取 Pod 信息
func (e *EventEnricher) getPodFromCache(pid uint32) *PodInfo {
	// 使用 PID 作为缓存 key
	key := formatPID(pid)
	
	podInfo, ok := e.podCache.Get(key)
	if ok {
		return podInfo
	}

	return nil
}

// addToCache 添加到缓存
func (e *EventEnricher) addToCache(pid uint32, podInfo *PodInfo) {
	key := formatPID(pid)
	e.podCache.Add(key, podInfo)
}

// cleanupLoop 缓存清理循环
func (e *EventEnricher) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// LRU 缓存会自动清理过期条目
			// 这里可以添加其他清理逻辑
		}
	}
}

// formatPID 格式化 PID 为缓存 key
func formatPID(pid uint32) string {
	return string(rune(pid))
}

// GetCacheStats 获取缓存统计信息
func (e *EventEnricher) GetCacheStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"cache_size": e.podCache.Len(),
		"running":    e.running,
	}
}

// InvalidateCache 使缓存失效
func (e *EventEnricher) InvalidateCache(pid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := formatPID(pid)
	e.podCache.Remove(key)
}

// InvalidateAllCache 使所有缓存失效
func (e *EventEnricher) InvalidateAllCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.podCache.Purge()
}
