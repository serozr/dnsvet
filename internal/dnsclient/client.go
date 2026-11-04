package dnsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const defaultTimeout = 3 * time.Second

// Transport specifies the underlying network transport for DNS queries.
type Transport string

const (
	TransportUDP   Transport = "udp"
	TransportTCP   Transport = "tcp"
	TransportTLS   Transport = "tls"   // DoT (DNS over TLS)
	TransportHTTPS Transport = "https" // DoH (DNS over HTTPS)
)

// Client sends DNS queries over UDP, TCP, DoT, and DoH.
type Client struct {
	timeout   time.Duration
	tlsConfig *tls.Config
}

// New creates a DNS client. A non-positive timeout uses the default.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{timeout: timeout}
}

// SetTLSConfig sets a custom TLS configuration for DoT and DoH.
func (c *Client) SetTLSConfig(cfg *tls.Config) {
	c.tlsConfig = cfg
}

// Query sends one DNS question and retries over TCP if the UDP response is truncated.
func (c *Client) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	return c.QueryTransport(ctx, server, name, qtype, TransportUDP, false)
}

// QueryWithDNSSEC requests DNSSEC records by setting the EDNS DO bit.
// It does not validate DNSSEC signatures or the chain of trust.
func (c *Client) QueryWithDNSSEC(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, time.Duration, error) {
	return c.QueryTransport(ctx, server, name, qtype, TransportUDP, true)
}

// QueryTransport executes a query using the specified network transport.
func (c *Client) QueryTransport(
	ctx context.Context,
	server string,
	name string,
	qtype uint16,
	transport Transport,
	requestDNSSEC bool,
) (*dns.Msg, time.Duration, error) {
	if ctx == nil {
		return nil, 0, fmt.Errorf("query context must not be nil")
	}
	if err := ctx.Err(); err != nil {
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
	if requestDNSSEC {
		message.SetEdns0(1232, true)
	}
	started := time.Now()

	var response *dns.Msg
	switch transport {
	case TransportTLS:
		dotAddr, serverName, err := NormalizeDoTServer(server)
		if err != nil {
			return nil, 0, err
		}
		response, err = c.exchangeDoT(ctx, dotAddr, serverName, message)
		if err != nil {
			return nil, time.Since(started), fmt.Errorf("DoT query to %s failed: %w", dotAddr, err)
		}
	case TransportHTTPS:
		response, err = c.exchangeDoH(ctx, server, message)
		if err != nil {
			return nil, time.Since(started), fmt.Errorf("DoH query to %s failed: %w", server, err)
		}
	case TransportTCP:
		resolver, err := NormalizeServer(server)
		if err != nil {
			return nil, 0, err
		}
		response, err = c.exchange(ctx, resolver, message, "tcp")
		if err != nil {
			return nil, time.Since(started), fmt.Errorf("DNS TCP query to %s failed: %w", resolver, err)
		}
	default: // TransportUDP
		resolver, err := NormalizeServer(server)
		if err != nil {
			return nil, 0, err
		}
		response, err = c.exchange(ctx, resolver, message, "udp")
		if err != nil {
			return nil, time.Since(started), fmt.Errorf("DNS UDP query to %s failed: %w", resolver, err)
		}
		if response != nil && response.Truncated {
			if err := ctx.Err(); err != nil {
				return nil, time.Since(started), err
			}
			response, err = c.exchange(ctx, resolver, message, "tcp")
			if err != nil {
				return nil, time.Since(started), fmt.Errorf("DNS TCP fallback to %s failed: %w", resolver, err)
			}
		}
	}

	if response == nil {
		return nil, time.Since(started), fmt.Errorf("DNS query returned an empty response")
	}
	if response.Opcode != message.Opcode {
		return nil, time.Since(started), fmt.Errorf("DNS response opcode %d does not match request opcode %d", response.Opcode, message.Opcode)
	}
	if response.Truncated {
		return nil, time.Since(started), fmt.Errorf("DNS response from %s is still truncated after TCP fallback", server)
	}
	if err := validateResponseQuestion(response, message.Question[0]); err != nil {
		return nil, time.Since(started), err
	}
	return response, time.Since(started), nil
}

func (c *Client) query(ctx context.Context, server, name string, qtype uint16, requestDNSSEC bool) (*dns.Msg, time.Duration, error) {
	return c.QueryTransport(ctx, server, name, qtype, TransportUDP, requestDNSSEC)
}

// BoundClient wraps Client with a fixed resolver endpoint, implementing the
// Resolver interface needed by validation orchestrators.
type BoundClient struct {
	client    *Client
	resolver  string
	transport Transport
}

// Bound returns a BoundClient that directs all queries to the specified resolver and transport.
func (c *Client) Bound(resolver string, transport Transport) *BoundClient {
	return &BoundClient{
		client:    c,
		resolver:  resolver,
		transport: transport,
	}
}

// Query sends a DNSSEC-enabled query to the bound resolver.
func (b *BoundClient) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, _, err := b.client.QueryTransport(ctx, b.resolver, name, qtype, b.transport, true)
	return resp, err
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

// NormalizeDNSName validates a DNS name and converts internationalized labels
// to their ASCII-compatible encoding. The trailing root dot is preserved.
func NormalizeDNSName(name string) (string, error) {
	return normalizeDNSName(name)
}

func validateDNSName(name string) error {
	_, err := normalizeDNSName(name)
	return err
}

// normalizeDNSName converts internationalized labels to their ASCII-compatible
// encoding while preserving ASCII service labels such as _sip and _tcp.
func normalizeDNSName(name string) (string, error) {
	if name == "." {
		return ".", nil
	}
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
			for _, character := range label {
				if unicode.IsSymbol(character) {
					return "", fmt.Errorf("invalid internationalized DNS label %q: symbol characters are not permitted", label)
				}
			}
			encoded, err := idna.Lookup.ToASCII(label)
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
