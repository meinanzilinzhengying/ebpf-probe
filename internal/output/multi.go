package output

import (
	"log"
	"time"
)

// MultiWriter 多输出写入器
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter 创建多输出写入器
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (m *MultiWriter) WriteEvent(ev *Event) error {
	for _, w := range m.writers {
		if err := w.WriteEvent(ev); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) WriteBatch(events []*Event) error {
	for _, w := range m.writers {
		if err := w.WriteBatch(events); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) WriteMetrics(probeID string, cpu, mem, disk float64, netRx, netTx, diskRead, diskWrite uint64) error {
	for _, w := range m.writers {
		if err := w.WriteMetrics(probeID, cpu, mem, disk, netRx, netTx, diskRead, diskWrite); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) WriteProcessEvent(ts time.Time, probeID string, pid uint32, comm, exe, args, eventType string) error {
	for _, w := range m.writers {
		if err := w.WriteProcessEvent(ts, probeID, pid, comm, exe, args, eventType); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) WriteFileEvent(ts time.Time, probeID string, pid uint32, comm, filename, operation string, result int32) error {
	for _, w := range m.writers {
		if err := w.WriteFileEvent(ts, probeID, pid, comm, filename, operation, result); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) WriteSyscallEvent(ts time.Time, probeID string, pid uint32, comm string, syscallNr, latencyNs, count uint64) error {
	for _, w := range m.writers {
		if err := w.WriteSyscallEvent(ts, probeID, pid, comm, syscallNr, latencyNs, count); err != nil {
			log.Printf("multi-writer: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) Close() error {
	for _, w := range m.writers {
		if err := w.Close(); err != nil {
			log.Printf("multi-writer close: %v", err)
		}
	}
	return nil
}

func (m *MultiWriter) Flush() {
	for _, w := range m.writers {
		w.Flush()
	}
}
