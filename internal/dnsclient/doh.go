package dnsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

const maxHTTPResponseBytes = 65535

func (c *Client) exchangeDoH(ctx context.Context, dohURL string, message *dns.Msg) (*dns.Msg, error) {
	parsedURL, err := url.Parse(dohURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid DoH URL %q: must be a valid http(s) URL", dohURL)
	}

	wire, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	var tlsConfig *tls.Config
	if c.tlsConfig != nil {
		tlsConfig = c.tlsConfig.Clone()
	} else {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s failed: %w", dohURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request to %s returned HTTP status %d %s", dohURL, resp.StatusCode, resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/dns-message") {
		return nil, fmt.Errorf("unexpected Content-Type %q from DoH server; want application/dns-message", contentType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response body: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message from DoH response: %w", err)
	}
	return response, nil
}
