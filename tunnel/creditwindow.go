package tunnel

import (
	"context"
	"sync"
)

// CreditWindow implements credit-based flow control for the tunnel.
// The sender can only transmit when it has credits > 0.
// The receiver grants credits after delivering cells.
type CreditWindow struct {
	mu             sync.Mutex
	credits        int32
	deliveredSince int32
	initialCredits int32
	creditIncrement int32
	maxCredits     int32
	creditCh       chan struct{}
}

// NewCreditWindow creates a CreditWindow with initial credits=100,
// increment=50, max=200, and a buffered signaling channel (cap 1).
func NewCreditWindow() *CreditWindow {
	return &CreditWindow{
		credits:         100,
		initialCredits:  100,
		creditIncrement: 50,
		maxCredits:      200,
		creditCh:        make(chan struct{}, 1),
	}
}

// Consume decrements credits by 1. Returns false if credits <= 0
// (sender must wait). Returns true if credits were > 0.
func (cw *CreditWindow) Consume() bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.credits <= 0 {
		return false
	}
	cw.credits--
	return true
}

// WaitForCredit blocks until credits > 0 or the context is cancelled.
func (cw *CreditWindow) WaitForCredit(ctx context.Context) error {
	for {
		cw.mu.Lock()
		if cw.credits > 0 {
			cw.mu.Unlock()
			return nil
		}
		cw.mu.Unlock()

		select {
		case <-cw.creditCh:
			// Credits may have become available; loop to re-check.
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// GrantCredits adds n credits under lock, capped at maxCredits.
// Signals creditCh if credits were 0 and are now > 0.
//
// Negative or zero grants are silently ignored: a malicious peer could
// otherwise send a SendMePayload with a large uint32 value that wraps to
// a negative int32, draining credits below zero and deadlocking the
// sender permanently. The caller is also expected to validate the wire
// value against a protocol cap before calling.
func (cw *CreditWindow) GrantCredits(n int32) {
	if n <= 0 {
		return
	}
	cw.mu.Lock()
	was := cw.credits
	cw.credits += n
	if cw.credits > cw.maxCredits {
		cw.credits = cw.maxCredits
	}
	now := cw.credits
	cw.mu.Unlock()

	if was <= 0 && now > 0 {
		select {
		case cw.creditCh <- struct{}{}:
		default:
		}
	}
}

// MaxCreditGrant returns the maximum legitimate single-grant value.
// Callers that parse SendMe messages from the wire must reject any value
// above this cap before passing to GrantCredits.
func (cw *CreditWindow) MaxCreditGrant() int32 {
	return cw.creditIncrement
}

// RecordDelivery increments deliveredSince. When it reaches creditIncrement,
// resets to 0 and returns (true, creditIncrement). Otherwise returns (false, 0).
func (cw *CreditWindow) RecordDelivery() (shouldSend bool, amount int32) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.deliveredSince++
	if cw.deliveredSince >= cw.creditIncrement {
		cw.deliveredSince = 0
		return true, cw.creditIncrement
	}
	return false, 0
}
