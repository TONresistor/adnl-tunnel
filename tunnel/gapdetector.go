package tunnel

import (
	"sync"
	"time"
)

// GapDetector tracks expected sequence numbers and reports gaps
// after a configurable delay (to avoid NACKing reordered packets).
//
// Usage:
//   detector.Observe(seqno)           // updates internal state on every packet
//   gaps := detector.ExpiredGaps()    // collects gaps ready to be NACKed
//
// Splitting Observe and ExpiredGaps lets the caller gate NACK emission on
// external conditions (rate limiting, backoff) without losing pending gaps.
type GapDetector struct {
	mu        sync.Mutex
	expected  uint32               // next expected seqno
	pending   map[uint32]time.Time // seqno -> time gap first detected
	received  map[uint32]struct{}  // out-of-order seqnos received ahead of expected
	nackDelay time.Duration        // how long to wait before reporting (default 25ms)
	started   bool                 // false until first packet
}

const defaultNackDelay = 25 * time.Millisecond

// wrapThreshold defines the boundary for detecting uint32 wraparound.
const wrapThreshold = 1 << 31

// maxGap caps the number of seqnos recorded per burst to avoid allocation
// bombs on corrupted or adversarial input.
const maxGap = uint32(256)

// NewGapDetector creates a GapDetector with the given NACK delay.
func NewGapDetector(nackDelay time.Duration) *GapDetector {
	if nackDelay <= 0 {
		nackDelay = defaultNackDelay
	}
	return &GapDetector{
		pending:   make(map[uint32]time.Time),
		received:  make(map[uint32]struct{}),
		nackDelay: nackDelay,
	}
}

// Observe is called on every received packet. It updates the expected
// seqno and records gaps. It does NOT return expired gaps — use
// ExpiredGaps for that.
func (g *GapDetector) Observe(seqno uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// First packet bootstraps expected.
	if !g.started {
		g.started = true
		g.expected = seqno + 1
		return
	}

	// Remove this seqno from pending if present (it arrived).
	delete(g.pending, seqno)

	// Stale/duplicate: behind expected but not a wraparound. Ignore.
	if seqno < g.expected {
		diff := g.expected - seqno
		if diff < wrapThreshold {
			return
		}
		// Wraparound: fall through to gap recording.
	}

	if seqno == g.expected {
		g.expected = seqno + 1
		g.advanceThroughReceivedLocked()
		return
	}

	// seqno > expected (or wraparound ahead): record gaps and mark received.
	if seqno > g.expected || (seqno < g.expected && (g.expected-seqno) >= wrapThreshold) {
		g.received[seqno] = struct{}{}

		var gap uint32
		if seqno > g.expected {
			gap = seqno - g.expected
		} else {
			gap = (^uint32(0) - g.expected) + seqno + 1
		}

		if gap <= maxGap {
			now := time.Now()
			for s := g.expected; s != seqno; s++ {
				if _, exists := g.pending[s]; !exists {
					g.pending[s] = now
				}
			}
		}
		g.expected = seqno + 1
		g.advanceThroughReceivedLocked()
	}
}

// advanceThroughReceivedLocked skips expected forward past any seqnos
// that were received out of order. Caller must hold g.mu.
func (g *GapDetector) advanceThroughReceivedLocked() {
	for {
		if _, ok := g.received[g.expected]; !ok {
			return
		}
		delete(g.received, g.expected)
		delete(g.pending, g.expected)
		g.expected++
	}
}

// ExpiredGaps returns seqnos that have been pending longer than nackDelay
// and removes them from the pending map. Call this only when you intend
// to actually send a NACK — gaps returned here are considered "consumed"
// and will not be reported again unless a new gap forms for the same seqno.
func (g *GapDetector) ExpiredGaps() []uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	var expired []uint32
	for seq, t := range g.pending {
		if now.Sub(t) >= g.nackDelay {
			expired = append(expired, seq)
			delete(g.pending, seq)
		}
	}
	return expired
}
