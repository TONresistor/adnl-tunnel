package tunnel

import (
	"net"
	"testing"

	"github.com/xssnick/tonutils-go/tl"
)

func TestDefaultClearnetBlacklist(t *testing.T) {
	bl := defaultClearnetBlacklist()
	if len(bl) == 0 {
		t.Fatal("blacklist is empty")
	}

	blocked := []string{
		"127.0.0.1",       // loopback
		"10.0.0.1",        // RFC 1918
		"172.16.0.1",      // RFC 1918
		"192.168.1.1",     // RFC 1918
		"169.254.169.254", // cloud metadata
		"100.64.0.1",      // CGN
		"0.0.0.1",         // "this network"
		"224.0.0.1",       // multicast
		"192.0.0.192",     // Oracle metadata
		"::1",             // IPv6 loopback
	}

	for _, ip := range blocked {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("failed to parse %s", ip)
		}
		found := false
		for _, cidr := range bl {
			if cidr.Contains(parsed) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IP %s should be blacklisted but is not", ip)
		}
	}

	allowed := []string{
		"93.184.216.34",  // example.com
		"1.1.1.1",        // Cloudflare DNS
		"8.8.8.8",        // Google DNS
		"104.16.132.229", // Cloudflare
	}

	for _, ip := range allowed {
		parsed := net.ParseIP(ip)
		found := false
		for _, cidr := range bl {
			if cidr.Contains(parsed) {
				found = true
				break
			}
		}
		if found {
			t.Errorf("IP %s should be allowed but is blacklisted", ip)
		}
	}
}

func TestDefaultClearnetPorts(t *testing.T) {
	ports := defaultClearnetPorts()

	if !ports[443] {
		t.Error("port 443 should be allowed")
	}
	if ports[80] {
		t.Error("port 80 should not be allowed in v1")
	}
	if ports[25] {
		t.Error("port 25 should never be allowed")
	}
	if ports[22] {
		t.Error("port 22 should not be allowed")
	}
}

func TestClearnetOverlayKeyDistinct(t *testing.T) {
	zero := make([]byte, 32)

	overlayHash, err := tl.Hash(OverlayKey{PaymentNode: zero})
	if err != nil {
		t.Fatal(err)
	}

	clearnetHash, err := tl.Hash(ClearnetOverlayKey{PaymentNode: zero})
	if err != nil {
		t.Fatal(err)
	}

	if string(overlayHash) == string(clearnetHash) {
		t.Fatal("OverlayKey and ClearnetOverlayKey must produce distinct DHT hashes")
	}
}

func TestTCPCloseReasons(t *testing.T) {
	if TCPCloseDone != 0 {
		t.Error("TCPCloseDone should be 0")
	}
	if TCPCloseRefused != 1 {
		t.Error("TCPCloseRefused should be 1")
	}
	if TCPClosePolicy != 3 {
		t.Error("TCPClosePolicy should be 3")
	}
	if TCPCloseLimit != 5 {
		t.Error("TCPCloseLimit should be 5")
	}
}
