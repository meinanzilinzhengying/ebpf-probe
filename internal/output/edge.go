package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// EdgeClient Edge 数据上报客户端
type EdgeClient struct {
	addr       string
	probeID    string
	client     *http.Client
	batch      []*Event
	mu         sync.Mutex
	batchSize  int
	flushTimer *time.Ticker
	stopCh     chan struct{}
	retryCount int
}

// NewEdgeClient 创建 Edge 客户端
func NewEdgeClient(addr, probeID string) *EdgeClient {
	return &EdgeClient{
		addr:    addr,
		probeID: probeID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		batch:     make([]*Event, 0, 2000),
		batchSize: 2000,
		stopCh:    make(chan struct{}),
	}
}

// Start 启动上报协程
func (e *EdgeClient) Start() {
	e.flushTimer = time.NewTicker(5 * time.Second)
	go e.flushLoop()
}

func (e *EdgeClient) flushLoop() {
	for {
		select {
		case <-e.stopCh:
			return
		case <-e.flushTimer.C:
			e.Flush()
		}
	}
}

// WriteEvent 写入单个事件
func (e *EdgeClient) WriteEvent(ev *Event) error {
	e.mu.Lock()
	e.batch = append(e.batch, ev)
	needFlush := len(e.batch) >= e.batchSize
	e.mu.Unlock()

	if needFlush {
		return e.Flush()
	}
	return nil
}

// WriteBatch 批量写入
func (e *EdgeClient) WriteBatch(events []*Event) error {
	e.mu.Lock()
	e.batch = append(e.batch, events...)
	e.mu.Unlock()
	return e.Flush()
}

// Flush 刷新缓冲区并上报
func (e *EdgeClient) Flush() error {
	e.mu.Lock()
	if len(e.batch) == 0 {
		e.mu.Unlock()
		return nil
	}
	events := e.batch
	e.batch = make([]*Event, 0, e.batchSize)
	e.mu.Unlock()

	data, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	url := fmt.Sprintf("http://%s/api/v1/ingest", e.addr)
	resp, err := e.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		e.retry(events)
		return fmt.Errorf("post to edge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		e.retry(events)
		return fmt.Errorf("edge returned %d: %s", resp.StatusCode, string(body))
	}

	e.retryCount = 0
	return nil
}

func (e *EdgeClient) retry(events []*Event) {
	e.retryCount++
	if e.retryCount > 100 {
		log.Printf("edge: dropped %d events after 100 retries", len(events))
		e.retryCount = 0
		return
	}
	// 指数退避: 1s, 2s, 4s ... 最大 60s
	backoff := time.Second * time.Duration(1<<uint(e.retryCount-1))
	if backoff > 60*time.Second {
		backoff = 60 * time.Second
	}
	time.Sleep(backoff)

	e.mu.Lock()
	e.batch = append(e.batch, events...)
	e.mu.Unlock()
}

// WriteMetrics 写入指标
func (e *EdgeClient) WriteMetrics(probeID string, cpu, mem, disk float64, netRx, netTx, diskRead, diskWrite uint64) error {
	ev := &Event{
		Timestamp: time.Now(),
		ProbeID:   probeID,
		Category:  "metrics",
		EventType: "host_metrics",
		Details:   fmt.Sprintf(`{"cpu":%.2f,"mem":%.2f,"disk":%.2f,"net_rx":%d,"net_tx":%d,"disk_read":%d,"disk_write":%d}`, cpu, mem, disk, netRx, netTx, diskRead, diskWrite),
	}
	return e.WriteEvent(ev)
}

// WriteProcessEvent 写入进程事件
func (e *EdgeClient) WriteProcessEvent(ts time.Time, probeID string, pid uint32, comm, exe, args, eventType string) error {
	ev := &Event{
		Timestamp: ts,
		ProbeID:   probeID,
		Category:  "process",
		EventType: eventType,
		Details:   fmt.Sprintf(`{"pid":%d,"comm":"%s","exe":"%s","args":"%s"}`, pid, comm, exe, args),
	}
	return e.WriteEvent(ev)
}

// WriteFileEvent 写入文件事件
func (e *EdgeClient) WriteFileEvent(ts time.Time, probeID string, pid uint32, comm, filename, operation string, result int32) error {
	ev := &Event{
		Timestamp: ts,
		ProbeID:   probeID,
		Category:  "file",
		EventType: "file_open",
		Details:   fmt.Sprintf(`{"pid":%d,"comm":"%s","filename":"%s","operation":"%s","result":%d}`, pid, comm, filename, operation, result),
	}
	return e.WriteEvent(ev)
}

// WriteSyscallEvent 写入系统调用事件
func (e *EdgeClient) WriteSyscallEvent(ts time.Time, probeID string, pid uint32, comm string, syscallNr, latencyNs, count uint64) error {
	ev := &Event{
		Timestamp: ts,
		ProbeID:   probeID,
		Category:  "syscall",
		EventType: "syscall",
		Details:   fmt.Sprintf(`{"pid":%d,"comm":"%s","syscall":%d,"latency_ns":%d,"count":%d}`, pid, comm, syscallNr, latencyNs, count),
	}
	return e.WriteEvent(ev)
}

// Stop 停止客户端
func (e *EdgeClient) Stop() {
	close(e.stopCh)
	e.flushTimer.Stop()
	e.Flush()
}

// Close 关闭客户端
func (e *EdgeClient) Close() error {
	e.Stop()
	return nil
}
