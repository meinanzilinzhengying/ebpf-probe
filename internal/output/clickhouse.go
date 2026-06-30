package output

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
)

// ClickHouseWriter ClickHouse 输出
type ClickHouseWriter struct {
	db        *sql.DB
	batch     []*Event
	mu        sync.Mutex
	batchSize int
	flushCh   chan struct{}
	stopCh    chan struct{}
}

// NewClickHouseWriter 创建 ClickHouse 写入器
func NewClickHouseWriter(addr, user, password, database string) (*ClickHouseWriter, error) {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s/%s", user, password, addr, database)
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	w := &ClickHouseWriter{
		db:        db,
		batch:     make([]*Event, 0, 2000),
		batchSize: 2000,
		flushCh:   make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}

	if err := w.createTables(); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}

	go w.flushLoop()
	return w, nil
}

func (w *ClickHouseWriter) createTables() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS cloudflow.ebpf_events (
			timestamp DateTime64(9),
			probe_id String,
			category String,
			event_type String,
			src_ip String,
			dst_ip String,
			src_port UInt16,
			dst_port UInt16,
			protocol String,
			bytes UInt64,
			packets UInt64,
			latency_ms Float64,
			service String,
			details String,
			pod_name String,
			namespace String,
			node_name String
		) ENGINE = MergeTree()
		ORDER BY (timestamp, probe_id, category)
		TTL timestamp + INTERVAL 30 DAY`,
		`CREATE TABLE IF NOT EXISTS cloudflow.host_metrics (
			timestamp DateTime,
			probe_id String,
			cpu Float64,
			mem Float64,
			disk Float64,
			net_rx UInt64,
			net_tx UInt64,
			disk_read UInt64,
			disk_write UInt64
		) ENGINE = MergeTree()
		ORDER BY (timestamp, probe_id)`,
		`CREATE TABLE IF NOT EXISTS cloudflow.process_events (
			timestamp DateTime,
			probe_id String,
			pid UInt32,
			comm String,
			exe String,
			args String,
			event_type String
		) ENGINE = MergeTree()
		ORDER BY (timestamp, probe_id, pid)`,
		`CREATE TABLE IF NOT EXISTS cloudflow.file_events (
			timestamp DateTime,
			probe_id String,
			pid UInt32,
			comm String,
			filename String,
			operation String,
			result Int32
		) ENGINE = MergeTree()
		ORDER BY (timestamp, probe_id, pid)`,
		`CREATE TABLE IF NOT EXISTS cloudflow.syscall_events (
			timestamp DateTime,
			probe_id String,
			pid UInt32,
			comm String,
			syscall UInt64,
			latency_ns UInt64,
			count UInt64
		) ENGINE = MergeTree()
		ORDER BY (timestamp, probe_id, pid)`,
	}

	for _, ddl := range tables {
		if _, err := w.db.Exec(ddl); err != nil {
			log.Printf("clickhouse: create table warning: %v", err)
		}
	}
	return nil
}

func (w *ClickHouseWriter) flushLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.Flush()
		case <-w.flushCh:
			w.Flush()
		}
	}
}

// WriteEvent 写入事件
func (w *ClickHouseWriter) WriteEvent(ev *Event) error {
	w.mu.Lock()
	w.batch = append(w.batch, ev)
	needFlush := len(w.batch) >= w.batchSize
	w.mu.Unlock()

	if needFlush {
		w.Flush()
	}
	return nil
}

// WriteBatch 批量写入
func (w *ClickHouseWriter) WriteBatch(events []*Event) error {
	w.mu.Lock()
	w.batch = append(w.batch, events...)
	w.mu.Unlock()
	w.Flush()
	return nil
}

// Flush 刷新到 ClickHouse
func (w *ClickHouseWriter) Flush() error {
	w.mu.Lock()
	if len(w.batch) == 0 {
		w.mu.Unlock()
		return nil
	}
	events := w.batch
	w.batch = make([]*Event, 0, w.batchSize)
	w.mu.Unlock()

	tx, err := w.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT INTO cloudflow.ebpf_events 
		(timestamp, probe_id, category, event_type, src_ip, dst_ip, src_port, dst_port, 
		 protocol, bytes, packets, latency_ms, service, details, pod_name, namespace, node_name) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		_, err := stmt.Exec(ev.Timestamp, ev.ProbeID, ev.Category, ev.EventType,
			ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.Protocol,
			ev.Bytes, ev.Packets, ev.LatencyMs, ev.Service, ev.Details,
			ev.PodName, ev.Namespace, ev.NodeName)
		if err != nil {
			log.Printf("clickhouse: insert event: %v", err)
		}
	}

	return tx.Commit()
}

// WriteMetrics 写入主机指标
func (w *ClickHouseWriter) WriteMetrics(probeID string, cpu, mem, disk float64, netRx, netTx, diskRead, diskWrite uint64) error {
	_, err := w.db.Exec(`INSERT INTO cloudflow.host_metrics 
		(timestamp, probe_id, cpu, mem, disk, net_rx, net_tx, disk_read, disk_write)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now(), probeID, cpu, mem, disk, netRx, netTx, diskRead, diskWrite)
	return err
}

// WriteProcessEvent 写入进程事件
func (w *ClickHouseWriter) WriteProcessEvent(ts time.Time, probeID string, pid uint32, comm, exe, args, eventType string) error {
	_, err := w.db.Exec(`INSERT INTO cloudflow.process_events 
		(timestamp, probe_id, pid, comm, exe, args, event_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts, probeID, pid, comm, exe, args, eventType)
	return err
}

// WriteFileEvent 写入文件事件
func (w *ClickHouseWriter) WriteFileEvent(ts time.Time, probeID string, pid uint32, comm, filename, operation string, result int32) error {
	_, err := w.db.Exec(`INSERT INTO cloudflow.file_events 
		(timestamp, probe_id, pid, comm, filename, operation, result) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts, probeID, pid, comm, filename, operation, result)
	return err
}

// WriteSyscallEvent 写入系统调用事件
func (w *ClickHouseWriter) WriteSyscallEvent(ts time.Time, probeID string, pid uint32, comm string, syscallNr, latencyNs, count uint64) error {
	_, err := w.db.Exec(`INSERT INTO cloudflow.syscall_events 
		(timestamp, probe_id, pid, comm, syscall, latency_ns, count) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts, probeID, pid, comm, syscallNr, latencyNs, count)
	return err
}

// Stop 停止写入器
func (w *ClickHouseWriter) Stop() {
	close(w.stopCh)
	w.Flush()
}

// Close 关闭连接
func (w *ClickHouseWriter) Close() error {
	w.Stop()
	return w.db.Close()
}
