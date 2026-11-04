package dnsclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func generateTestCertificate(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(): %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"dnsvet test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(): %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(): %v", err)
	}
	certPool.AddCert(parsedCert)

	return cert, certPool
}

func TestNormalizeDoTServer(t *testing.T) {
	tests := []struct {
		input       string
		wantAddr    string
		wantSNI     string
		expectError bool
	}{
		{"1.1.1.1", "1.1.1.1:853", "1.1.1.1", false},
		{"8.8.8.8:853", "8.8.8.8:853", "8.8.8.8", false},
		{"dns.google", "dns.google:853", "dns.google", false},
		{"dns.quad9.net:853", "dns.quad9.net:853", "dns.quad9.net", false},
		{"", "", "", true},
		{"dns.google:invalid", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			addr, sni, err := NormalizeDoTServer(tt.input)
			if tt.expectError && err == nil {
				t.Fatalf("expected error for %q, got nil", tt.input)
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if addr != tt.wantAddr || sni != tt.wantSNI {
				t.Fatalf("NormalizeDoTServer(%q) = (%q, %q), want (%q, %q)", tt.input, addr, sni, tt.wantAddr, tt.wantSNI)
			}
		})
	}
}

func TestQueryDoTSuccess(t *testing.T) {
	cert, pool := generateTestCertificate(t, "127.0.0.1")

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(msg)
	})

	server := &dns.Server{
		Net:       "tcp-tls",
		TLSConfig: serverTLS,
		Handler:   handler,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen(): %v", err)
	}
	server.Listener = listener

	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	client := New(2 * time.Second)
	client.SetTLSConfig(&tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: false,
	})

	addr := listener.Addr().String()
	resp, elapsed, err := client.QueryTransport(context.Background(), addr, "example.com", dns.TypeA, TransportTLS, false)
	if err != nil {
		t.Fatalf("QueryTransport(DoT) error = %v", err)
	}
	if elapsed <= 0 {
		t.Fatalf("elapsed duration must be positive, got %v", elapsed)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Answer))
	}
}
