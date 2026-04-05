package tunnel

import (
	"context"
	cRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/xssnick/tonutils-go/tl"
)

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

	conns       map[uint32]*tcpConn
	maxConns    int
	portPolicy  map[int]bool
	ipBlacklist []*net.IPNet

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
		padded := make([]byte, tcpCellSize)
		copy(padded, pl)
		cRand.Read(padded[len(pl):])
		pl = padded
	}

	t.mx.RLock()
	defer t.mx.RUnlock()

	pl, err = encryptStream(t.PayloadCipherKeyCRC, t.PayloadCipherKey, pl)
	if err != nil {
		return fmt.Errorf("encrypt payload failed: %w", err)
	}

	var msg tl.Serializable
	if isPayload {
		msg = EncryptedMessageCached{
			SectionPubKey: t.InboundSectionKey,
			Seqno:         atomic.AddUint32(&t.backSeqno, 1),
			Payload:       pl,
		}
	} else {
		msg = EncryptedMessage{
			SectionPubKey: t.InboundSectionKey,
			Instructions:  t.Instructions,
			Payload:       pl,
		}
	}

	if err = t.inboundPeer.SendCustomMessage(t.closer, msg); err != nil {
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
	default:
		return fmt.Errorf("unknown tcp payload opcode: %d", op)
	}

	return nil
}

func (t *TCPOut) HandleConnect(payload TCPConnectPayload) {
	t.log.Debug().Uint32("connId", payload.ConnId).Str("host", string(payload.Host)).Uint32("port", payload.Port).Msg("tcp connect requested")

	// Run connect in a goroutine to avoid blocking message dispatch
	go t.handleConnectAsync(payload)
}

func (t *TCPOut) handleConnectAsync(payload TCPConnectPayload) {
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
		t.log.Debug().Err(err).Str("host", string(payload.Host)).Msg("dns resolve failed")
		if sendErr := t.sendBack(TCPCloseResponsePayload{ConnId: payload.ConnId, Reason: TCPCloseRefused}, true); sendErr != nil {
			t.log.Trace().Err(sendErr).Uint32("conn_id", payload.ConnId).Msg("send back close refused failed")
		}
		return
	}

	if t.isBlacklisted(resolved.IP) {
		t.log.Debug().Str("ip", resolved.IP.String()).Msg("resolved IP is blacklisted")
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
		id:     payload.ConnId,
		conn:   conn,
		state:  tcpStateOpen,
		ctx:    ctx,
		cancel: cancel,
	}

	t.mx.Lock()
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

func (t *TCPOut) readFromTCP(connId uint32) {
	t.mx.RLock()
	tc := t.conns[connId]
	t.mx.RUnlock()

	if tc == nil {
		return
	}

	buf := make([]byte, 1024)
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
		}

		_ = tc.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := tc.conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			seqno := atomic.AddUint64(&tc.sendSeqno, 1)
			if sendErr := t.sendBack(TCPDataPayload{Seqno: seqno, ConnId: connId, Data: data, Fin: false}, true); sendErr != nil {
				t.log.Trace().Err(sendErr).Uint32("conn_id", connId).Msg("send back tcp data failed")
			}
		}
		if err != nil {
			if err == io.EOF {
				// Send FIN to client
				finSeqno := atomic.AddUint64(&tc.sendSeqno, 1)
				if sendErr := t.sendBack(TCPDataPayload{Seqno: finSeqno, ConnId: connId, Fin: true}, true); sendErr != nil {
					t.log.Trace().Err(sendErr).Uint32("conn_id", connId).Msg("send back tcp fin failed")
				}
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
