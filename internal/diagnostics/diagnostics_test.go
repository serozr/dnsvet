package diagnostics

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/serozr/dnsvet/internal/dnsclient"
)

func startLocalDNSServer(t *testing.T, handler dns.Handler) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(): %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	addr := pc.LocalAddr().String()
	cleanup := func() {
		_ = server.Shutdown()
	}
	return addr, cleanup
}

func TestCompareResolversConsistent(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(msg)
	})

	srv1, cleanup1 := startLocalDNSServer(t, handler)
	defer cleanup1()
	srv2, cleanup2 := startLocalDNSServer(t, handler)
	defer cleanup2()

	client := dnsclient.New(2 * time.Second)
	res, err := CompareResolvers(context.Background(), client, []string{srv1, srv2}, "example.com", dns.TypeA, false)
	if err != nil {
		t.Fatalf("CompareResolvers() error = %v", err)
	}

	if !res.Consistent || res.Classification != "consistent" {
		t.Fatalf("expected consistent result, got classification: %s, discrepancies: %v", res.Classification, res.Discrepancies)
	}
	if len(res.Responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(res.Responses))
	}
}

func TestCompareResolversInconsistent(t *testing.T) {
	handler1 := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(msg)
	})

	handler2 := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(msg)
	})

	srv1, cleanup1 := startLocalDNSServer(t, handler1)
	defer cleanup1()
	srv2, cleanup2 := startLocalDNSServer(t, handler2)
	defer cleanup2()

	client := dnsclient.New(2 * time.Second)
	res, err := CompareResolvers(context.Background(), client, []string{srv1, srv2}, "example.com", dns.TypeA, false)
	if err != nil {
		t.Fatalf("CompareResolvers() error = %v", err)
	}

	if res.Consistent || res.Classification != "inconsistent" {
		t.Fatal("expected inconsistent result between answering server and NXDOMAIN server")
	}
	if len(res.Discrepancies) == 0 {
		t.Fatal("expected recorded discrepancies")
	}
}

func TestCompareResolversGeoDNSHeuristic(t *testing.T) {
	handler1 := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(msg)
	})

	handler2 := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP("198.51.100.1"),
		})
		_ = w.WriteMsg(msg)
	})

	srv1, cleanup1 := startLocalDNSServer(t, handler1)
	defer cleanup1()
	srv2, cleanup2 := startLocalDNSServer(t, handler2)
	defer cleanup2()

	client := dnsclient.New(2 * time.Second)
	// Default (strict=false): should classify as likely_geo_or_load_balanced and Consistent=true
	resNonStrict, err := CompareResolvers(context.Background(), client, []string{srv1, srv2}, "cdn.example.test", dns.TypeA, false)
	if err != nil {
		t.Fatalf("CompareResolvers() error = %v", err)
	}
	if !resNonStrict.Consistent || resNonStrict.Classification != "likely_geo_or_load_balanced" {
		t.Fatalf("expected likely_geo_or_load_balanced, got classification=%s, consistent=%v", resNonStrict.Classification, resNonStrict.Consistent)
	}

	// Strict mode (strict=true): should classify as inconsistent and Consistent=false
	resStrict, err := CompareResolvers(context.Background(), client, []string{srv1, srv2}, "cdn.example.test", dns.TypeA, true)
	if err != nil {
		t.Fatalf("CompareResolvers() strict error = %v", err)
	}
	if resStrict.Consistent || resStrict.Classification != "inconsistent" {
		t.Fatalf("expected inconsistent with strict=true, got classification=%s, consistent=%v", resStrict.Classification, resStrict.Consistent)
	}
}

func TestBenchmarkResolver(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(msg)
	})

	srv, cleanup := startLocalDNSServer(t, handler)
	defer cleanup()

	client := dnsclient.New(2 * time.Second)
	stats, err := BenchmarkResolver(context.Background(), client, srv, "example.com", dns.TypeA, 5)
	if err != nil {
		t.Fatalf("BenchmarkResolver() error = %v", err)
	}

	if stats.Samples != 5 || stats.Successes != 5 || stats.Failures != 0 {
		t.Fatalf("unexpected benchmark counts: %+v", stats)
	}
	if stats.MinMS < 0 || stats.MeanMS < 0 {
		t.Fatalf("expected non-negative timings, got min=%f, mean=%f", stats.MinMS, stats.MeanMS)
	}
}

func TestDetectHijackingBenignNXDOMAIN(t *testing.T) {
	// Compliant DNS server returning NXDOMAIN for .invalid
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(msg)
	})

	srv, cleanup := startLocalDNSServer(t, handler)
	defer cleanup()

	client := dnsclient.New(2 * time.Second)
	res, err := DetectHijackingAndLeaks(context.Background(), client, srv)
	if err != nil {
		t.Fatalf("DetectHijackingAndLeaks() error = %v", err)
	}

	if res.NXDOMAINRewriting {
		t.Fatal("compliant NXDOMAIN server falsely detected as rewriting")
	}
	if res.Confidence != ConfidenceNone {
		t.Fatalf("expected ConfidenceNone, got %s", res.Confidence)
	}
}

func TestDetectHijackingTamperingServer(t *testing.T) {
	// Hijacking DNS server returning A records for .invalid names
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.10"), // ISP advertising portal
		})
		_ = w.WriteMsg(msg)
	})

	srv, cleanup := startLocalDNSServer(t, handler)
	defer cleanup()

	client := dnsclient.New(2 * time.Second)
	res, err := DetectHijackingAndLeaks(context.Background(), client, srv)
	if err != nil {
		t.Fatalf("DetectHijackingAndLeaks() error = %v", err)
	}

	if !res.NXDOMAINRewriting {
		t.Fatal("expected NXDOMAIN rewriting to be detected")
	}
	if res.Confidence != ConfidenceConfirmed {
		t.Fatalf("expected ConfidenceConfirmed, got %s", res.Confidence)
	}
	if len(res.Indicators) == 0 {
		t.Fatal("expected indicators to be recorded")
	}
}
