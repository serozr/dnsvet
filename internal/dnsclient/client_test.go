package dnsclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startUDPTestServer(t *testing.T, handler func(*dns.Msg) *dns.Msg) (string, <-chan struct{}) {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for UDP test server: %v", err)
	}
	t.Cleanup(func() {
		_ = packetConn.Close()
	})

	received := make(chan struct{}, 1)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, readErr := packetConn.ReadFrom(buffer)
			if readErr != nil {
				return
			}

			var request dns.Msg
			if unpackErr := request.Unpack(buffer[:n]); unpackErr != nil {
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
			if packErr != nil {
				continue
			}
			_, _ = packetConn.WriteTo(wire, addr)
		}
	}()

	return packetConn.LocalAddr().String(), received
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

	client := New(time.Second)
	response, rtt, err := client.Query(context.Background(), server, "example.test", dns.TypeA)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response Rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(response.Answer))
	}
	if got := response.Answer[0].String(); !strings.Contains(got, "192.0.2.10") {
		t.Fatalf("answer = %q, want address 192.0.2.10", got)
	}
	if rtt < 0 {
		t.Fatalf("round-trip time = %s, want non-negative duration", rtt)
	}
}

func TestQueryAddsStandardPortWhenOmitted(t *testing.T) {
	server, _ := startUDPTestServer(t, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		return response
	})

	host, _, err := net.SplitHostPort(server)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}

	_, _, err = New(time.Second).Query(context.Background(), host, "example.test", dns.TypeA)
	if err != nil {
		t.Fatalf("Query() with implicit port failed: %v", err)
	}
}

func TestQueryTimeout(t *testing.T) {
	server, _ := startUDPTestServer(t, func(*dns.Msg) *dns.Msg {
		return nil
	})

	started := time.Now()
	_, _, err := New(40*time.Millisecond).Query(context.Background(), server, "timeout.test", dns.TypeA)
	if err == nil {
		t.Fatal("Query() error = nil, want timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("query took too long after timeout: %s", time.Since(started))
	}
}

func TestQueryContextCancellation(t *testing.T) {
	server, received := startUDPTestServer(t, func(*dns.Msg) *dns.Msg {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-received
		cancel()
	}()

	_, _, err := New(2*time.Second).Query(ctx, server, "cancel.test", dns.TypeA)
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
	client := New(0)
	if client.timeout != defaultTimeout {
		t.Fatalf("timeout = %s, want %s", client.timeout, defaultTimeout)
	}
}
