package dnsclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startUDPTestServer(t *testing.T, handler func(*dns.Msg) *dns.Msg) (string, <-chan struct{}) {
	t.Helper()
	return startUDPTestServerAt(t, "127.0.0.1:0", handler)
}

func startUDPTestServerAt(t *testing.T, address string, handler func(*dns.Msg) *dns.Msg) (string, <-chan struct{}) {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("listen for UDP test server: %v", err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	received := make(chan struct{}, 1)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, readErr := packetConn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			var request dns.Msg
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
			select {
			case received <- struct{}{}:
			default:
			}
			response := handler(&request)
			if response == nil {
				continue
			}
			wire, packErr := response.Pack()
			if packErr == nil {
				_, _ = packetConn.WriteTo(wire, addr)
			}
		}
	}()
	return packetConn.LocalAddr().String(), received
}

func startTCPTestServerAt(t *testing.T, address string, handler func(*dns.Msg) *dns.Msg) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen for TCP test server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &dns.Server{
		Listener: listener,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			if response := handler(request); response != nil {
				_ = w.WriteMsg(response)
			}
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
}

func unusedLocalAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestQueryUDPReturnsDNSResponse(t *testing.T) {
	answer, err := dns.NewRR("example.test. 60 IN A 192.0.2.10")
	if err != nil {
		t.Fatalf("create test answer: %v", err)
	}
	server, _ := startUDPTestServer(t, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, answer)
		return response
	})
	response, rtt, err := New(time.Second).Query(context.Background(), server, "example.test", dns.TypeA)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("unexpected DNS response: %v", response)
	}
	if !strings.Contains(response.Answer[0].String(), "192.0.2.10") {
		t.Fatalf("answer = %q, want address 192.0.2.10", response.Answer[0])
	}
	if rtt < 0 {
		t.Fatalf("round-trip time = %s, want non-negative duration", rtt)
	}
}

func TestQueryDoesNotUseTCPWhenUDPResponseIsComplete(t *testing.T) {
	var tcpRequests atomic.Int32
	address := unusedLocalAddress(t)
	startTCPTestServerAt(t, address, func(request *dns.Msg) *dns.Msg {
		tcpRequests.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		return response
	})
	udpAddress, _ := startUDPTestServerAt(t, address, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		return response
	})
	response, _, err := New(time.Second).Query(context.Background(), udpAddress, "complete.test", dns.TypeA)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if response.Truncated {
		t.Fatal("response is truncated, want complete UDP response")
	}
	if got := tcpRequests.Load(); got != 0 {
		t.Fatalf("TCP requests = %d, want 0", got)
	}
}

func TestQueryFallsBackToTCPWhenUDPResponseIsTruncated(t *testing.T) {
	answer, err := dns.NewRR("large.test. 60 IN A 192.0.2.20")
	if err != nil {
		t.Fatalf("create test answer: %v", err)
	}
	address := unusedLocalAddress(t)
	startTCPTestServerAt(t, address, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, answer)
		return response
	})
	udpAddress, _ := startUDPTestServerAt(t, address, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Truncated = true
		return response
	})
	response, _, err := New(time.Second).Query(context.Background(), udpAddress, "large.test", dns.TypeA)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if response.Truncated || len(response.Answer) != 1 {
		t.Fatalf("expected complete TCP response, got %v", response)
	}
	if !strings.Contains(response.Answer[0].String(), "192.0.2.20") {
		t.Fatalf("TCP answer = %q, want address 192.0.2.20", response.Answer[0])
	}
}

func TestQueryTimeout(t *testing.T) {
	server, _ := startUDPTestServer(t, func(*dns.Msg) *dns.Msg { return nil })
	started := time.Now()
	_, _, err := New(40 * time.Millisecond).Query(context.Background(), server, "timeout.test", dns.TypeA)
	if err == nil {
		t.Fatal("Query() error = nil, want timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("query took too long after timeout: %s", time.Since(started))
	}
}

func TestQueryContextCancellation(t *testing.T) {
	server, received := startUDPTestServer(t, func(*dns.Msg) *dns.Msg { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-received
		cancel()
	}()
	_, _, err := New(2 * time.Second).Query(ctx, server, "cancel.test", dns.TypeA)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Query() error = %v, want context.Canceled", err)
	}
}

func TestQueryRejectsInvalidInput(t *testing.T) {
	client := New(time.Second)
	tests := []struct {
		name   string
		server string
		domain string
		qtype  uint16
	}{
		{name: "empty resolver", server: "", domain: "example.test", qtype: dns.TypeA},
		{name: "invalid resolver port", server: "127.0.0.1:70000", domain: "example.test", qtype: dns.TypeA},
		{name: "empty domain", server: "127.0.0.1:53", domain: "", qtype: dns.TypeA},
		{name: "invalid domain", server: "127.0.0.1:53", domain: "bad domain", qtype: dns.TypeA},
		{name: "zero question type", server: "127.0.0.1:53", domain: "example.test", qtype: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := client.Query(context.Background(), test.server, test.domain, test.qtype)
			if err == nil {
				t.Fatal("Query() error = nil, want validation error")
			}
		})
	}
}

func TestNewUsesDefaultTimeout(t *testing.T) {
	if client := New(0); client.timeout != defaultTimeout {
		t.Fatalf("timeout = %s, want %s", client.timeout, defaultTimeout)
	}
}

func TestNormalizeServerAddsStandardPortWhenOmitted(t *testing.T) {
	got, err := normalizeServer("192.0.2.53")
	if err != nil {
		t.Fatalf("normalizeServer() error = %v", err)
	}
	if got != "192.0.2.53:53" {
		t.Fatalf("normalizeServer() = %q, want %q", got, "192.0.2.53:53")
	}
}
