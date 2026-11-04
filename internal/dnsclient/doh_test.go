package dnsclient

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQueryDoHSuccess(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "bad dns wire", http.StatusBadRequest)
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		})

		respWire, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respWire)
	}))
	defer ts.Close()

	client := New(2 * time.Second)
	client.SetTLSConfig(&tls.Config{
		RootCAs:            ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		InsecureSkipVerify: false,
	})

	resp, elapsed, err := client.QueryTransport(context.Background(), ts.URL, "example.com", dns.TypeA, TransportHTTPS, false)
	if err != nil {
		t.Fatalf("QueryTransport(DoH) error = %v", err)
	}
	if elapsed <= 0 {
		t.Fatalf("expected positive elapsed duration, got %v", elapsed)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Answer))
	}
}

func TestQueryDoHReportsHTTPError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := New(2 * time.Second)
	client.SetTLSConfig(&tls.Config{
		RootCAs:            ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		InsecureSkipVerify: false,
	})

	_, _, err := client.QueryTransport(context.Background(), ts.URL, "example.com", dns.TypeA, TransportHTTPS, false)
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}
