package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/serozr/dnsvet/internal/dnsclient"
)

// FlagScanner provides zero-dependency sequential argument reading
// supporting both --flag=value and --flag value forms.
type FlagScanner struct {
	args []string
	pos  int
}

// NewFlagScanner constructs a FlagScanner for args.
func NewFlagScanner(args []string) *FlagScanner {
	return &FlagScanner{args: args, pos: 0}
}

// Next reads the next argument. Returns ok=false when all arguments have been consumed.
func (s *FlagScanner) Next() (isOption bool, name string, value string, hasValue bool, ok bool) {
	if s.pos >= len(s.args) {
		return false, "", "", false, false
	}
	arg := s.args[s.pos]
	s.pos++
	if strings.HasPrefix(arg, "-") && arg != "-" {
		name, val, hasVal := strings.Cut(arg, "=")
		return true, name, val, hasVal, true
	}
	return false, "", arg, false, true
}

// ConsumeValue retrieves the value for a flag either from --flag=value
// or the next positional argument.
func (s *FlagScanner) ConsumeValue(name string, value string, hasValue bool) (string, error) {
	if hasValue {
		return value, nil
	}
	if s.pos >= len(s.args) {
		return "", fmt.Errorf("%s requires a value", name)
	}
	val := s.args[s.pos]
	s.pos++
	return val, nil
}

// ParseBoundedTimeout parses a duration and validates that it is positive and <= 60s.
func ParseBoundedTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > 60*time.Second {
		return 0, fmt.Errorf("invalid timeout %q: use a positive duration up to 60s, such as 2s", raw)
	}
	return d, nil
}

// ParseSupportedQType parses and validates a DNS record type name.
func ParseSupportedQType(raw string) (uint16, error) {
	t, ok := dns.StringToType[strings.ToUpper(raw)]
	if !ok || !IsSupportedQueryType(t) {
		return 0, fmt.Errorf("unsupported DNS record type %q", raw)
	}
	return t, nil
}

// ParseNormalizedServer validates and normalizes a resolver address.
func ParseNormalizedServer(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("resolver address must not be empty")
	}
	return dnsclient.NormalizeServer(trimmed)
}

// IsSupportedQueryType checks if a DNS record type is supported by dnsvet.
func IsSupportedQueryType(qtype uint16) bool {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS,
		dns.TypePTR, dns.TypeSOA, dns.TypeSRV, dns.TypeTXT, dns.TypeCAA,
		dns.TypeDS, dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	default:
		return false
	}
}

// JSONRequestedInArgs scans args to detect --json before full option parsing.
func JSONRequestedInArgs(args []string) bool {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--json" {
			return true
		}
	}
	return false
}
