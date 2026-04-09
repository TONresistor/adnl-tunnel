package tunnel

import "sync"

// HopBuffer stores recently forwarded encrypted packets per section.
// 64-slot ring buffer indexed by seqno % 64.

type HopCell struct {
	Seqno   uint32
	Payload []byte // full serialized EncryptedMessageCached
	Valid   bool
}

type HopBuffer struct {
	mu   sync.Mutex
	ring [64]HopCell
}

// NewHopBuffer returns an initialized HopBuffer.
func NewHopBuffer() *HopBuffer {
	return &HopBuffer{}
}

// Store saves payload at slot seqno % 64, overwriting any existing entry.
func (h *HopBuffer) Store(seqno uint32, payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	idx := seqno % 64
	h.ring[idx] = HopCell{
		Seqno:   seqno,
		Payload: append([]byte(nil), payload...), // defensive copy
		Valid:   true,
	}
}

// Get returns the payload for a given seqno if the slot contains a matching entry.
func (h *HopBuffer) Get(seqno uint32) ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	idx := seqno % 64
	cell := &h.ring[idx]
	if cell.Valid && cell.Seqno == seqno {
		return cell.Payload, true
	}
	return nil, false
}
