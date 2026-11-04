package dnsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// NormalizeDoTServer normalizes a DoT server address to host:port, defaulting to port 853.
// It returns the normalized address and the hostname for TLS SNI.
func NormalizeDoTServer(server string) (string, string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", "", fmt.Errorf("DoT resolver address must not be empty")
	}

	if ip := net.ParseIP(server); ip != nil {
		return net.JoinHostPort(server, "853"), server, nil
	}

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		if strings.Contains(server, ":") {
			return "", "", fmt.Errorf("invalid DoT resolver address %q: use host:port or bracketed IPv6 with a port", server)
		}
		return net.JoinHostPort(server, "853"), server, nil
	}

	if host == "" {
		return "", "", fmt.Errorf("DoT resolver host must not be empty")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid DoT resolver port %q", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), host, nil
}

func (c *Client) exchangeDoT(ctx context.Context, address string, serverName string, message *dns.Msg) (*dns.Msg, error) {
	var tlsConfig *tls.Config
	if c.tlsConfig != nil {
		tlsConfig = c.tlsConfig.Clone()
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	if tlsConfig.ServerName == "" && serverName != "" && net.ParseIP(serverName) == nil {
		tlsConfig.ServerName = serverName
	}

	dnsClient := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   c.timeout,
	}

	conn, err := dnsClient.DialContext(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	stopCancellation := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stopCancellation:
		}
	}()

	response, _, exchangeErr := dnsClient.ExchangeWithConnContext(ctx, message, conn)
	close(stopCancellation)
	<-watcherDone
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if exchangeErr != nil {
		return nil, exchangeErr
	}
	return response, nil
}
