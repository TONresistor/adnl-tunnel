package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/xssnick/tonutils-go/tl"
)

var tcpCellPool = sync.Pool{
	New: func() any { return make([]byte, tcpCellSize) },
}

const (
	tcpStateOpen       = int32(iota)
	tcpStateHalfClosed
	tcpStateClosed
)

type tcpConn struct {
	id        uint32
	conn      net.Conn
	state     int32  // atomic
	sendSeqno uint64 // atomic, per-connection seqno for ordered delivery
	sendBuf   *SendBuffer
	credits   *CreditWindow // flow control: credits granted by receiver
	ctx       context.Context
	cancel    func()
}

type TCPOut struct {
	gw          *Gateway
	inboundPeer *Peer
	closer      context.Context
	closerClose func()

	InboundADNL         []byte
	PayloadCipherKey    []byte
	PayloadCipherKeyCRC uint64
	InboundSectionKey   []byte
	Instructions        []byte

	conns          map[uint32]*tcpConn
	maxConns       int
	inFlightConns  atomic.Int32
	portPolicy     map[int]bool
	ipBlacklist    []*net.IPNet

	PricePerChunk *big.Int // reserved for future payment enforcement

	backSeqno uint32
	mx        sync.RWMutex
	log       zerolog.Logger
}

func defaultClearnetBlacklist() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128",
		"169.254.0.0/16", "fe80::/10",
		"fc00::/7",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"198.18.0.0/15",
		"192.0.0.0/24",
		"224.0.0.0/3",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("invalid hardcoded CIDR: " + c)
		}
		nets = append(nets, n)
	}
	return nets
}

func defaultClearnetPorts() map[int]bool {
	return map[int]bool{443: true}
}

func (t *TCPOut) isBlacklisted(ip net.IP) bool {
	for _, cidr := range t.ipBlacklist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

const tcpCellSize = 1024 // Fixed cell size for traffic analysis resistance (Tor model)

func (t *TCPOut) sendBack(obj tl.Serializable, isPayload bool) error {
	pl, err := tl.Serialize(obj, true)
	if err != nil {
		return fmt.Errorf("serialize payload failed: %w", err)
	}

	// Pad to fixed cell size to prevent traffic fingerprinting.
	// TL header encodes the real data length, so the receiver parses
	// correctly and ignores the padding after decryption.
	if len(pl) < tcpCellSize {
		padded := tcpCellPool.Get().([]byte)
		copy(padded, pl)
		for i := len(pl); i < tcpCellSize; i++ {
			padded[i] = byte(rand.Uint32())
		}
		pl = padded
		defer tcpCellPool.Put(padded)
	}

	// Snapshot mutable fields under brief RLock, then release before
	// encrypt + network send to avoid holding the lock during I/O.
	t.mx.RLock()
	cipherKeyCRC := t.PayloadCipherKeyCRC
	cipherKey := t.PayloadCipherKey
	sectionKey := t.InboundSectionKey
	instructions := t.Instructions
	peer := t.inboundPeer
	t.mx.RUnlock()

	pl, err = encryptStream(cipherKeyCRC, cipherKey, pl)
	if err != nil {
		return fmt.Errorf("encrypt payload failed: %w", err)
	}

	var msg tl.Serializable
	if isPayload {
		msg = EncryptedMessageCached{
			SectionPubKey: sectionKey,
			Seqno:         atomic.AddUint32(&t.backSeqno, 1),
			Payload:       pl,
		}
	} else {
		msg = EncryptedMessage{
			SectionPubKey: sectionKey,
			Instructions:  instructions,
			Payload:       pl,
		}
	}

	if err = peer.SendCustomMessage(t.closer, msg); err != nil {
		return fmt.Errorf("send message to inbound tunnel failed: %w", err)
	}
	return nil
}

func (t *TCPOut) Send(payload []byte) error {
	t.log.Trace().Int("payload_len", len(payload)).Msg("tcp out send")

	t.mx.RLock()
	cipherKeyCRC := t.PayloadCipherKeyCRC
	cipherKey := t.PayloadCipherKey
	t.mx.RUnlock()

	data, err := decryptStream(cipherKeyCRC, cipherKey, payload)
	if err != nil {
		t.log.Error().Err(err).Msg("TCPOut.Send decrypt failed")
		return fmt.Errorf("decrypt payload failed: %w", err)
	}

	if len(data) < 4 {
		return fmt.Errorf("tcp payload too short")
	}

	op := binary.LittleEndian.Uint32(data)
	switch op {
	case opTCPConnect:
		var p TCPConnectPayload
		if _, err = tl.Parse(&p, data, true); err != nil {
			return fmt.Errorf("parse tcp connect payload failed: %w", err)
		}
		t.HandleConnect(p)
	case opTCPData:
		var p TCPDataPayload
		if _, err = tl.Parse(&p, data, true); err != nil {
			return fmt.Errorf("parse tcp data payload failed: %w", err)
		}
		t.HandleData(p)
	case opTCPClose:
		var p TCPClosePayload
		if _, err = tl.Parse(&p, data, true); err != nil {
			return fmt.Errorf("parse tcp close payload failed: %w", err)
		}
		t.HandleClose(p)
	case opTCPAck:
		var p TCPAckPayload
		_, err = tl.Parse(&p, data, true)
		if err != nil {
			return fmt.Errorf("parse tcp ack failed: %w", err)
		}
		t.HandleAck(p)
	case opSendMe:
		var p SendMePayload
		if _, err = tl.Parse(&p, data, true); err != nil {
			return fmt.Errorf("parse sendme failed: %w", err)
		}
		t.HandleSendMe(p)
	default:
		return fmt.Errorf("unknown tcp payload opcode: %d", op)
	}

	return nil
}

func (t *TCPOut) HandleConnect(payload TCPConnectPayload) {
	// Privacy: do NOT log the destination host. Exit operators must be able
	// to truthfully claim "no logs of user activity". Only log the connection
	// id at trace level for diagnostics.
	t.log.Trace().Uint32("connId", payload.ConnId).Msg("tcp connect requested")

	// Limit in-flight connect goroutines to prevent fan-out under load
	if int(t.inFlightConns.Load()) >= t.maxConns {
		if err := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPCloseLimit}, true); err != nil {
			t.log.Trace().Err(err).Uint32("conn_id", payload.ConnId).Msg("send back close limit (in-flight) failed")
		}
		return
	}
	t.inFlightConns.Add(1)

	// Run connect in a goroutine to avoid blocking message dispatch
	go t.handleConnectAsync(payload)
}

func (t *TCPOut) handleConnectAsync(payload TCPConnectPayload) {
	defer t.inFlightConns.Add(-1)

	select {
	case <-t.closer.Done():
		return
	default:
	}

	t.mx.Lock()
	if len(t.conns) >= t.maxConns {
		t.mx.Unlock()
		if err := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPCloseLimit}, true); err != nil {
			t.log.Trace().Err(err).Uint32("conn_id", payload.ConnId).Msg("send back close limit failed")
		}
		return
	}
	if !t.portPolicy[int(payload.Port)] {
		t.mx.Unlock()
		if err := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPClosePolicy}, true); err != nil {
			t.log.Trace().Err(err).Uint32("conn_id", payload.ConnId).Msg("send back close policy failed")
		}
		return
	}
	if payload.Port == 25 { // defense-in-depth: block SMTP even if portPolicy is misconfigured
		t.mx.Unlock()
		if err := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPClosePolicy}, true); err != nil {
			t.log.Trace().Err(err).Uint32("conn_id", payload.ConnId).Msg("send back close policy (port 25) failed")
		}
		return
	}
	t.mx.Unlock()

	// DNS resolve and dial outside the lock — force IPv4
	resolved, err := net.ResolveIPAddr("ip4", string(payload.Host))
	if err != nil {
		// Privacy: do NOT log the host on resolve failure. Just signal the
		// failure category.
		t.log.Trace().Uint32("conn_id", payload.ConnId).Msg("dns resolve failed")
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPCloseRefused}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close refused failed")
		}
		return
	}

	if t.isBlacklisted(resolved.IP) {
		// Privacy: do NOT log the resolved IP. Operators don't need to know
		// which user-requested IP hit the blacklist; the metric is enough.
		t.log.Trace().Uint32("conn_id", payload.ConnId).Msg("resolved IP is blacklisted")
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPClosePolicy}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close policy (blacklist) failed")
		}
		return
	}

	// Dial using resolved IP (not hostname) to prevent DNS rebinding
	dialAddr := net.JoinHostPort(resolved.IP.String(), fmt.Sprint(payload.Port))
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp4", dialAddr)
	dialCancel()
	if err != nil {
		reason := uint32(TCPCloseRefused)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			reason = TCPCloseTimeout
		}
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: reason}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close dial error failed")
		}
		return
	}

	ctx, cancel := context.WithCancel(t.closer)
	tc := &tcpConn{
		id:      payload.ConnId,
		conn:    conn,
		state:   tcpStateOpen,
		sendBuf: NewSendBuffer(320),
		credits: NewCreditWindow(),
		ctx:     ctx,
		cancel:  cancel,
	}

	t.mx.Lock()
	if t.conns == nil {
		t.mx.Unlock()
		cancel()
		conn.Close()
		return
	}
	// Re-check limit after dial
	if len(t.conns) >= t.maxConns {
		t.mx.Unlock()
		cancel()
		conn.Close()
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPCloseLimit}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close limit (post-dial) failed")
		}
		return
	}
	// Reject duplicate ConnId to prevent connection hijacking
	if existing := t.conns[payload.ConnId]; existing != nil {
		t.mx.Unlock()
		cancel()
		conn.Close()
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPClosePolicy}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close duplicate connid failed")
		}
		return
	}
	t.conns[payload.ConnId] = tc
	t.mx.Unlock()

	if err = t.sendBack(TCPConnectedPayload{ConnId: payload.ConnId}, true); err != nil {
		t.log.Warn().Err(err).Uint32("conn_id", payload.ConnId).Msg("send back connected failed")
	}

	// Start reading AFTER TCPConnectedPayload is sent to avoid race where
	// TCPDataPayload arrives at proxy before TCPConnectedPayload
	go t.readFromTCP(payload.ConnId)
}

func (t *TCPOut) HandleData(payload TCPDataPayload) {
	t.mx.RLock()
	tc := t.conns[payload.ConnId]
	t.mx.RUnlock()

	if tc == nil {
		return
	}

	if len(payload.Data) > 65535 {
		return
	}

	if payload.Fin {
		oldState := atomic.LoadInt32(&tc.state)
		if oldState == tcpStateOpen {
			atomic.CompareAndSwapInt32(&tc.state, tcpStateOpen, tcpStateHalfClosed)
			if tcpConn, ok := tc.conn.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			}
		} else if oldState == tcpStateHalfClosed {
			// Both sides done — full close
			atomic.StoreInt32(&tc.state, tcpStateClosed)
			tc.cancel()
			tc.conn.Close()
			t.mx.Lock()
			delete(t.conns, payload.ConnId)
			t.mx.Unlock()
		}
		return
	}

	_ = tc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := tc.conn.Write(payload.Data); err != nil {
		t.log.Trace().Err(err).Uint32("conn_id", payload.ConnId).Msg("tcp write failed")
	}
}

func (t *TCPOut) HandleClose(payload TCPClosePayload) {
	t.mx.Lock()
	tc := t.conns[payload.ConnId]
	delete(t.conns, payload.ConnId)
	t.mx.Unlock()

	if tc != nil {
		tc.cancel()
		tc.conn.Close()
	}
}

// maxTCPDataPerCell is the maximum number of TCP-stream bytes that can be
// carried in a single TCPDataPayload while keeping the serialized cell at
// or below tcpCellSize (1024 bytes). The TL framing of TCPDataPayload is:
//
//	opcode(4) + seqno(8) + connId(4) + bytes-len-prefix(4) + data(N) + pad(0..3) + Fin(4)
//
// = 24 + N + pad. To always fit in 1024, N must be ≤ 996 (with worst-case
// 3-byte padding). We use 990 to leave a small safety margin in case the
// TL framing ever changes.
const maxTCPDataPerCell = 990

func (t *TCPOut) readFromTCP(connId uint32) {
	t.mx.RLock()
	tc := t.conns[connId]
	t.mx.RUnlock()

	if tc == nil {
		return
	}

	buf := make([]byte, 16384) // match TLS record max size to minimize syscalls
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
		}

		_ = tc.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := tc.conn.Read(buf)
		if n > 0 {
			// Chunk the read into fixed-size cells. This is the canonical
			// Tor-style traffic-analysis-resistance: every cell on the wire
			// is exactly tcpCellSize bytes after padding, regardless of how
			// much data the application read in one shot. A 16 KB TLS
			// record becomes ~17 cells of 1024 bytes each.
			data := buf[:n]
			for offset := 0; offset < len(data); offset += maxTCPDataPerCell {
				end := offset + maxTCPDataPerCell
				if end > len(data) {
					end = len(data)
				}
				if !t.sendTCPDataChunk(tc, connId, data[offset:end], false) {
					// Connection closed during send (context cancelled).
					return
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				// Send FIN as its own cell (no data, padded to tcpCellSize).
				t.sendTCPDataChunk(tc, connId, nil, true)
				oldState := atomic.LoadInt32(&tc.state)
				if oldState == tcpStateOpen {
					atomic.CompareAndSwapInt32(&tc.state, tcpStateOpen, tcpStateHalfClosed)
				} else if oldState == tcpStateHalfClosed {
					atomic.StoreInt32(&tc.state, tcpStateClosed)
				}
			} else {
				if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: connId, Reason: TCPCloseError}, true); sendErr != nil {
					t.log.Trace().Err(sendErr).Uint32("conn_id", connId).Msg("send back tcp close error failed")
				}
			}

			// Cleanup: close connection and cancel context to prevent leaks
			tc.cancel()
			tc.conn.Close()
			t.mx.Lock()
			delete(t.conns, connId)
			t.mx.Unlock()
			return
		}
	}
}

// sendTCPDataChunk emits a single TCPDataPayload cell containing at most
// maxTCPDataPerCell bytes of TCP-stream data. The cell is gated by flow
// control credits, buffered for retransmission, and sent through the
// inbound tunnel.
//
// Returns false if the connection context was cancelled during the call.
func (t *TCPOut) sendTCPDataChunk(tc *tcpConn, connId uint32, chunk []byte, fin bool) bool {
	// Flow control: block until a credit is available.
	for !tc.credits.Consume() {
		if waitErr := tc.credits.WaitForCredit(tc.ctx); waitErr != nil {
			return false
		}
	}

	seqno := atomic.AddUint64(&tc.sendSeqno, 1)
	payload := TCPDataPayload{Seqno: seqno, ConnId: connId, Data: chunk, Fin: fin}

	padded, padErr := serializeAndPad(payload)
	if padErr != nil {
		t.log.Trace().Err(padErr).Uint32("conn_id", connId).Msg("serialize tcp data failed")
		return true
	}

	if err := t.enqueueWithBackpressure(tc, padded); err != nil {
		return false
	}

	if sendErr := t.sendBack(payload, true); sendErr != nil {
		t.log.Trace().Err(sendErr).Uint32("conn_id", connId).Msg("send back tcp data failed")
	}
	return true
}

// enqueueWithBackpressure tries to store padded into tc.sendBuf, applying
// backpressure by polling if the buffer is full. Returns nil on success,
// or ctx.Err() if the connection context is cancelled while waiting.
func (t *TCPOut) enqueueWithBackpressure(tc *tcpConn, padded []byte) error {
	for {
		if _, err := tc.sendBuf.Enqueue(padded); err == nil {
			return nil
		}
		// Buffer full: wait for the retransmit loop or ACKs to free space.
		select {
		case <-tc.ctx.Done():
			return tc.ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// sendBackRaw sends a pre-serialized, padded payload (before encryption).
// Used for retransmitting buffered cells without re-serializing.
func (t *TCPOut) sendBackRaw(padded []byte) error {
	t.mx.RLock()
	cipherKeyCRC := t.PayloadCipherKeyCRC
	cipherKey := t.PayloadCipherKey
	sectionKey := t.InboundSectionKey
	peer := t.inboundPeer
	t.mx.RUnlock()

	pl, err := encryptStream(cipherKeyCRC, cipherKey, padded)
	if err != nil {
		return fmt.Errorf("encrypt payload failed: %w", err)
	}

	msg := EncryptedMessageCached{
		SectionPubKey: sectionKey,
		Seqno:         atomic.AddUint32(&t.backSeqno, 1),
		Payload:       pl,
	}

	if err = peer.SendCustomMessage(t.closer, msg); err != nil {
		return fmt.Errorf("send message to inbound tunnel failed: %w", err)
	}
	return nil
}

// serializeAndPad serializes a TL object and pads to tcpCellSize.
// Returns the padded buffer (caller must not hold pool references across calls).
func serializeAndPad(obj tl.Serializable) ([]byte, error) {
	pl, err := tl.Serialize(obj, true)
	if err != nil {
		return nil, fmt.Errorf("serialize payload failed: %w", err)
	}

	if len(pl) < tcpCellSize {
		padded := make([]byte, tcpCellSize)
		copy(padded, pl)
		for i := len(pl); i < tcpCellSize; i++ {
			padded[i] = byte(rand.Uint32())
		}
		return padded, nil
	}
	return pl, nil
}

// HandleAck processes an incoming end-to-end ACK from the client.
// Only marks cells acked and updates RTT; retransmission is the
// exclusive job of retransmitLoop.
func (t *TCPOut) HandleAck(p TCPAckPayload) {
	t.mx.RLock()
	tc := t.conns[p.ConnId]
	t.mx.RUnlock()
	if tc == nil {
		return
	}
	tc.sendBuf.ProcessAck(p.AckSeqno, p.AckBitmap)
}

// HandleSendMe processes an incoming SendMe (credit grant) from the client.
func (t *TCPOut) HandleSendMe(p SendMePayload) {
	t.mx.RLock()
	tc := t.conns[p.ConnId]
	t.mx.RUnlock()
	if tc == nil {
		return
	}
	// Bounds-check the wire value before casting uint32 → int32. A
	// malicious peer could otherwise send Credit > 2^31, wrap to a
	// negative int32, and drain credits below zero (deadlocking the
	// sender forever via WaitForCredit).
	maxGrant := tc.credits.MaxCreditGrant()
	if p.Credit == 0 || p.Credit > uint32(maxGrant) {
		return
	}
	tc.credits.GrantCredits(int32(p.Credit))
}

// retransmitLoop runs periodically to retransmit unacknowledged cells.
func (t *TCPOut) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.closer.Done():
			return
		case <-ticker.C:
		}

		t.mx.RLock()
		conns := make(map[uint32]*tcpConn, len(t.conns))
		for id, tc := range t.conns {
			conns[id] = tc
		}
		t.mx.RUnlock()

		for connId, tc := range conns {
			cells, fatal := tc.sendBuf.GetRetransmissions()
			if fatal {
				t.log.Warn().Uint32("conn_id", connId).Msg("retransmit limit exceeded, closing connection")
				tc.cancel()
				tc.conn.Close()
				t.mx.Lock()
				delete(t.conns, connId)
				t.mx.Unlock()
				continue
			}
			for _, cell := range cells {
				if err := t.sendBackRaw(cell.Data); err != nil {
					t.log.Trace().Err(err).Uint32("conn_id", connId).Uint64("seqno", cell.Seqno).Msg("retransmit failed")
				}
			}
		}
	}
}

func (t *TCPOut) Close() {
	t.closerClose()

	t.mx.Lock()
	for _, tc := range t.conns {
		tc.conn.Close()
	}
	t.conns = nil
	t.mx.Unlock()

	t.inboundPeer.Dereference()
	t.log.Debug().Msg("closing tcp out")
}
