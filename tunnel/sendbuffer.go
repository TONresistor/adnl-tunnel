package tunnel

import (
	"errors"
	"sync"
	"time"
)

var errBufferFull = errors.New("send buffer full")

const (
	sendBufferMinRTO     = 200 * time.Millisecond
	sendBufferMaxRetries = 5
)

// BufferedCell holds an unacknowledged cell in the send buffer.
type BufferedCell struct {
	Seqno   uint64
	Data    []byte // encrypted cell, ready to resend
	SentAt  time.Time
	Retries int
	Acked   bool
}

// SendBuffer is a per-connection send buffer for end-to-end Selective Repeat ACK.
// It stores unacknowledged cells for the timer-based retransmission loop.
//
// Lifecycle:
//   - Enqueue adds a cell with a fresh seqno.
//   - ProcessAck marks cells acked and updates RTT (Karn's algorithm).
//     It does NOT schedule retransmissions — the timer is the sole scheduler.
//   - GetRetransmissions is called periodically by a timer and returns
//     cells whose RTO has expired. It is the only function that increments
//     Retries and updates SentAt.
type SendBuffer struct {
	mu         sync.Mutex
	cells      []BufferedCell // ring buffer, indexed by seqno % cap
	baseSeqno  uint64         // oldest unacknowledged seqno
	nextSeqno  uint64         // next seqno to assign
	maxCells   int            // capacity (default 320)
	srtt       time.Duration  // smoothed RTT (Jacobson/Karels)
	rttvar     time.Duration  // RTT variance
	initialRTT bool           // true until first RTT sample
}

// NewSendBuffer creates a send buffer with the given capacity.
func NewSendBuffer(maxCells int) *SendBuffer {
	return &SendBuffer{
		cells:      make([]BufferedCell, maxCells),
		maxCells:   maxCells,
		srtt:       500 * time.Millisecond,
		rttvar:     250 * time.Millisecond,
		initialRTT: true,
	}
}

// Enqueue assigns the next seqno to data and stores it in the buffer.
// Returns errBufferFull if there is no room (back-pressure).
func (sb *SendBuffer) Enqueue(data []byte) (uint64, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.nextSeqno-sb.baseSeqno >= uint64(sb.maxCells) {
		return 0, errBufferFull
	}

	seqno := sb.nextSeqno
	idx := seqno % uint64(sb.maxCells)

	cp := make([]byte, len(data))
	copy(cp, data)

	sb.cells[idx] = BufferedCell{
		Seqno:  seqno,
		Data:   cp,
		SentAt: time.Now(),
	}

	sb.nextSeqno++
	return seqno, nil
}

// ProcessAck marks cells as acknowledged based on ackSeqno and bitmap,
// advances baseSeqno past contiguous acked cells, and updates the RTT
// estimate using Karn's algorithm (first-transmission samples only).
//
// ProcessAck does NOT schedule retransmissions — per RFC 9002 §6,
// loss detection and retransmission scheduling are the job of the timer
// (GetRetransmissions).
func (sb *SendBuffer) ProcessAck(ackSeqno uint64, bitmap uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()

	// Mark ackSeqno as acked if it falls within our window.
	if ackSeqno >= sb.baseSeqno && ackSeqno < sb.nextSeqno {
		idx := ackSeqno % uint64(sb.maxCells)
		c := &sb.cells[idx]
		if c.Seqno == ackSeqno && !c.Acked {
			c.Acked = true
			// Karn's algorithm: only sample RTT from first transmissions.
			if c.Retries == 0 {
				sb.updateRTTLocked(now.Sub(c.SentAt))
			}
		}
	}

	// Mark bitmap entries. Bit i corresponds to ackSeqno+1+i.
	for i := 0; i < 64; i++ {
		if bitmap&(1<<uint(i)) != 0 {
			s := ackSeqno + 1 + uint64(i)
			if s >= sb.baseSeqno && s < sb.nextSeqno {
				idx := s % uint64(sb.maxCells)
				c := &sb.cells[idx]
				if c.Seqno == s && !c.Acked {
					c.Acked = true
					if c.Retries == 0 {
						sb.updateRTTLocked(now.Sub(c.SentAt))
					}
				}
			}
		}
	}

	// Advance baseSeqno past contiguous acked cells.
	for sb.baseSeqno < sb.nextSeqno {
		idx := sb.baseSeqno % uint64(sb.maxCells)
		if !sb.cells[idx].Acked || sb.cells[idx].Seqno != sb.baseSeqno {
			break
		}
		sb.cells[idx] = BufferedCell{} // release data for GC
		sb.baseSeqno++
	}
}

// GetRetransmissions returns cells whose RTO has expired, incrementing
// their Retries count and updating SentAt. This is the sole retransmission
// scheduler — called periodically by the retransmit timer.
//
// fatal is set to true if any unacknowledged cell has exceeded
// sendBufferMaxRetries; the caller should tear down the connection.
func (sb *SendBuffer) GetRetransmissions() (cells []BufferedCell, fatal bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()
	baseRTO := sb.rtoLocked()

	for s := sb.baseSeqno; s < sb.nextSeqno; s++ {
		idx := s % uint64(sb.maxCells)
		c := &sb.cells[idx]
		if c.Acked || c.Seqno != s {
			continue
		}
		if c.Retries >= sendBufferMaxRetries {
			fatal = true
			return
		}

		// RFC 9002-style PTO: baseRTO * 2^retries (exponential backoff).
		timeout := baseRTO * (1 << uint(c.Retries))
		if now.Sub(c.SentAt) < timeout {
			continue
		}

		c.Retries++
		c.SentAt = now
		cells = append(cells, *c)
	}

	return cells, false
}

// IsFull returns true when the buffer has no room for more cells.
func (sb *SendBuffer) IsFull() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.nextSeqno-sb.baseSeqno >= uint64(sb.maxCells)
}

func (sb *SendBuffer) updateRTTLocked(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if sb.initialRTT {
		sb.srtt = sample
		sb.rttvar = sample / 2
		sb.initialRTT = false
		return
	}
	// Jacobson/Karels EWMA: alpha = 1/8, beta = 1/4.
	diff := sample - sb.srtt
	if diff < 0 {
		diff = -diff
	}
	sb.rttvar = sb.rttvar*3/4 + diff/4
	sb.srtt = sb.srtt*7/8 + sample/8
}

// rtoLocked returns the retransmission timeout per RFC 9002 §6.2.1:
// max(smoothed_rtt + 4*rttvar, sendBufferMinRTO).
func (sb *SendBuffer) rtoLocked() time.Duration {
	rto := sb.srtt + 4*sb.rttvar
	if rto < sendBufferMinRTO {
		rto = sendBufferMinRTO
	}
	return rto
}
