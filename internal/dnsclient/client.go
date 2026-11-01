package dnsclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const defaultTimeout = 3 * time.Second

// Client sends DNS queries over UDP and TCP.
type Client struct {
	timeout time.Duration
}

// New creates a DNS client. A non-positive timeout uses the default.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{timeout: timeout}
}

// Query sends one DNS question and retries over TCP if the UDP response is truncated.
func (c *Client) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	if ctx == nil {
		return nil, 0, fmt.Errorf("query context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	resolver, err := NormalizeServer(server)
	if err != nil {
		return nil, 0, err
	}
	name = strings.TrimSpace(name)
	asciiName, err := normalizeDNSName(name)
	if err != nil {
		return nil, 0, err
	}
	if qtype == 0 {
		return nil, 0, fmt.Errorf("DNS question type must not be zero")
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(asciiName), qtype)
	started := time.Now()

	response, err := c.exchange(ctx, resolver, message, "udp")
	if err != nil {
		return nil, time.Since(started), fmt.Errorf("DNS UDP query to %s failed: %w", resolver, err)
	}
	if response == nil {
		return nil, time.Since(started), fmt.Errorf("DNS UDP query to %s returned an empty response", resolver)
	}
	if response.Truncated {
		if err := ctx.Err(); err != nil {
			return nil, time.Since(started), err
		}
		response, err = c.exchange(ctx, resolver, message, "tcp")
		if err != nil {
			return nil, time.Since(started), fmt.Errorf("DNS TCP fallback to %s failed: %w", resolver, err)
		}
		if response == nil {
			return nil, time.Since(started), fmt.Errorf("DNS TCP fallback to %s returned an empty response", resolver)
		}
	}
	if err := validateResponseQuestion(response, message.Question[0]); err != nil {
		return nil, time.Since(started), err
	}
	return response, time.Since(started), nil
}

func (c *Client) exchange(ctx context.Context, resolver string, message *dns.Msg, network string) (*dns.Msg, error) {
	dnsClient := &dns.Client{Net: network, Timeout: c.timeout}
	conn, err := dnsClient.DialContext(ctx, resolver)
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

func validateResponseQuestion(response *dns.Msg, expected dns.Question) error {
	if response == nil {
		return fmt.Errorf("DNS response is nil")
	}
	if !response.Response {
		return fmt.Errorf("DNS message is not marked as a response")
	}
	if len(response.Question) == 0 {
		// Some error responses omit the echoed question. Preserve those responses
		// for diagnostics; a successful response must identify the question.
		if response.Rcode != dns.RcodeSuccess {
			return nil
		}
		return fmt.Errorf("successful DNS response contains no question")
	}
	if len(response.Question) != 1 {
		return fmt.Errorf("DNS response contains %d questions, want exactly 1", len(response.Question))
	}
	actual := response.Question[0]
	if !strings.EqualFold(actual.Name, expected.Name) ||
		actual.Qtype != expected.Qtype || actual.Qclass != expected.Qclass {
		return fmt.Errorf("DNS response question does not match request: got %s %s class %d, want %s %s class %d",
			actual.Name, dns.TypeToString[actual.Qtype], actual.Qclass,
			expected.Name, dns.TypeToString[expected.Qtype], expected.Qclass)
	}
	return nil
}

func validateDNSName(name string) error {
	_, err := normalizeDNSName(name)
	return err
}

// normalizeDNSName converts internationalized labels to their ASCII-compatible
// encoding while preserving ASCII service labels such as _sip and _tcp.
func normalizeDNSName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("invalid DNS name %q", name)
	}
	trailingDot := strings.HasSuffix(name, ".")
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return "", fmt.Errorf("invalid DNS name %q", name)
	}

	labels := strings.Split(trimmed, ".")
	for i, label := range labels {
		if label == "" {
			return "", fmt.Errorf("invalid DNS name %q: empty label", name)
		}
		ascii := true
		for _, character := range label {
			if character > 127 {
				ascii = false
				break
			}
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' || character == '_' {
				continue
			}
			return "", fmt.Errorf("invalid DNS name %q: unsupported character %q", name, character)
		}
		if !ascii {
			registrationProfile := idna.New(idna.ValidateForRegistration())
			encoded, err := registrationProfile.ToASCII(label)
			if err != nil {
				return "", fmt.Errorf("invalid internationalized DNS label %q: %w", label, err)
			}
			labels[i] = encoded
		}
	}
	normalized := strings.Join(labels, ".")
	if trailingDot {
		normalized += "."
	}
	if _, ok := dns.IsDomainName(normalized); !ok {
		return "", fmt.Errorf("invalid DNS name %q after IDNA conversion", name)
	}
	return normalized, nil
}

func NormalizeServer(server string) (string, error) {
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
