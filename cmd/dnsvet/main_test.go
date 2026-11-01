package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help output does not contain Usage: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "dnsvet dev") {
		t.Fatalf("version output missing application version: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Platform:") {
		t.Fatalf("version output missing platform: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"not-a-command"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("error output missing unknown command message: %q", stderr.String())
	}
}

func TestParseQueryOptions(t *testing.T) {
	options, err := parseQueryOptions([]string{"example.com", "--server", "9.9.9.9", "--type=AAAA", "--timeout", "1500ms"})
	if err != nil {
		t.Fatalf("parseQueryOptions() error = %v", err)
	}
	if options.domain != "example.com" || options.server != "9.9.9.9" || options.qtype != dns.TypeAAAA || options.timeout != 1500*time.Millisecond {
		t.Fatalf("unexpected parsed options: %+v", options)
	}
}

func TestParseQueryOptionsDefaults(t *testing.T) {
	options, err := parseQueryOptions([]string{"example.com"})
	if err != nil {
		t.Fatalf("parseQueryOptions() error = %v", err)
	}
	if options.server != "1.1.1.1" || options.qtype != dns.TypeA || options.timeout != 3*time.Second {
		t.Fatalf("unexpected defaults: %+v", options)
	}
}

func TestParseQueryOptionsRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing domain", args: []string{"--server", "1.1.1.1"}},
		{name: "multiple domains", args: []string{"example.com", "example.org"}},
		{name: "missing server value", args: []string{"example.com", "--server"}},
		{name: "unknown option", args: []string{"example.com", "--unknown"}},
		{name: "unknown record type", args: []string{"example.com", "--type", "INVALID"}},
		{name: "zone transfer type is not allowed", args: []string{"example.com", "--type", "AXFR"}},
		{name: "invalid timeout", args: []string{"example.com", "--timeout", "0s"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseQueryOptions(test.args); err == nil {
				t.Fatal("parseQueryOptions() error = nil, want validation error")
			}
		})
	}
}

func TestFormatAnswer(t *testing.T) {
	rr, err := dns.NewRR("example.test. 60 IN A 192.0.2.25")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}
	got := formatAnswer(rr)
	for _, expected := range []string{"example.test.", "60", "A", "192.0.2.25"} {
		if !strings.Contains(got, expected) {
			t.Errorf("formatAnswer() = %q, want it to contain %q", got, expected)
		}
	}
}

func TestRunQueryHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"query", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage: dnsvet query") {
		t.Fatalf("query help output = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunQueryPrintsDNSAnswer(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DNS test server: %v", err)
	}
	defer packetConn.Close()
	answer, err := dns.NewRR("example.test. 60 IN A 192.0.2.25")
	if err != nil {
		t.Fatalf("create test answer: %v", err)
	}
	server := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, answer)
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	var stdout, stderr bytes.Buffer
	code := run([]string{"query", "example.test", "--server", packetConn.LocalAddr().String()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	for _, expected := range []string{"Resolver: " + packetConn.LocalAddr().String(), "example.test. A", "NOERROR", "Elapsed:", "192.0.2.25"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("query output %q does not contain %q", stdout.String(), expected)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestRunQueryReportsDNSClientErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"query", "", "--server", "127.0.0.1:1"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "DNS query failed") {
		t.Fatalf("error output = %q, want DNS query failure", stderr.String())
	}
}

func TestParseQueryOptionsRejectsTimeoutOverOneMinute(t *testing.T) {
	if _, err := parseQueryOptions([]string{"example.com", "--timeout", "61s"}); err == nil {
		t.Fatal("parseQueryOptions() error = nil, want timeout upper-bound error")
	}
	if _, err := parseQueryOptions([]string{"example.com", "--timeout", "60s"}); err != nil {
		t.Fatalf("parseQueryOptions() with 60s error = %v, want nil", err)
	}
}
