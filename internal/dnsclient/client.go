package dnsclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultTimeout = 3 * time.Second

// Client sends DNS queries over UDP.
type Client struct {
	timeout time.Duration
}

// New creates a UDP DNS client. A non-positive timeout uses the default.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &Client{timeout: timeout}
}

// Query sends one DNS question to server and returns the response and round-trip time.
// If server omits a port, the standard DNS port 53 is used.
func (c *Client) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	if ctx == nil {
		return nil, 0, fmt.Errorf("query context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	resolver, err := normalizeServer(server)
	if err != nil {
		return nil, 0, err
	}

	name = strings.TrimSpace(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, 0, fmt.Errorf("invalid DNS name %q", name)
	}
	if qtype == 0 {
		return nil, 0, fmt.Errorf("DNS question type must not be zero")
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)

	dnsClient := &dns.Client{
		Net:     "udp",
		Timeout: c.timeout,
	}

	conn, err := dnsClient.DialContext(ctx, resolver)
	if err != nil {
		return nil, 0, fmt.Errorf("connect to DNS resolver %s: %w", resolver, err)
	}
	defer conn.Close()

	stopCancellation := make(chan struct{})
	cancellationWatcherDone := make(chan struct{})
	go func() {
		defer close(cancellationWatcherDone)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stopCancellation:
		}
	}()

	response, rtt, err := dnsClient.ExchangeWithConnContext(ctx, message, conn)
	close(stopCancellation)
	<-cancellationWatcherDone

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, rtt, ctxErr
	}
	if err != nil {
		return nil, rtt, fmt.Errorf("DNS UDP query to %s failed: %w", resolver, err)
	}
	if response == nil {
		return nil, rtt, fmt.Errorf("DNS UDP query to %s returned an empty response", resolver)
	}

	return response, rtt, nil
}

func normalizeServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("resolver address must not be empty")
	}

	if ip := net.ParseIP(server); ip != nil {
		return net.JoinHostPort(server, "53"), nil
	}

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		if strings.Contains(server, ":") {
			return "", fmt.Errorf("invalid resolver address %q: use host:port or bracketed IPv6 with a port", server)
		}
		return net.JoinHostPort(server, "53"), nil
	}
	if host == "" {
		return "", fmt.Errorf("resolver host must not be empty")
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid resolver port %q", port)
	}

	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}
