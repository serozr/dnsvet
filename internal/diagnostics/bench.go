package diagnostics

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/serozr/dnsvet/internal/dnsclient"
)

// BenchmarkStats holds statistical latency and reliability metrics for a resolver.
type BenchmarkStats struct {
	Resolver    string    `json:"resolver"`
	Domain      string    `json:"domain"`
	Samples     int       `json:"samples"`
	Successes   int       `json:"successes"`
	Failures    int       `json:"failures"`
	LossPercent float64   `json:"loss_percent"`
	MinMS       float64   `json:"min_ms"`
	MedianMS    float64   `json:"median_ms"`
	P95MS       float64   `json:"p95_ms"`
	MaxMS       float64   `json:"max_ms"`
	MeanMS      float64   `json:"mean_ms"`
	StdDevMS    float64   `json:"stddev_ms"`
	Caveats     []string  `json:"caveats,omitempty"`
	TimingsMS   []float64 `json:"timings_ms,omitempty"`
}

// BenchmarkResolver executes count queries against resolver with bounded rate and computes distribution stats.
func BenchmarkResolver(
	ctx context.Context,
	client *dnsclient.Client,
	resolver string,
	domain string,
	qtype uint16,
	count int,
) (*BenchmarkStats, error) {
	if count <= 0 {
		count = 10
	}
	if count > 100 {
		count = 100 // Enforce safety bounds (ADR 0006)
	}
	if client == nil {
		client = dnsclient.New(3 * time.Second)
	}

	stats := &BenchmarkStats{
		Resolver: resolver,
		Domain:   domain,
		Samples:  count,
		Caveats: []string{
			"Results may vary depending on local network jitter and whether upstream cache is warm or cold.",
		},
	}

	var successfulLatencies []float64
	var sum float64

	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		_, elapsed, err := client.Query(ctx, resolver, domain, qtype)
		if err != nil {
			stats.Failures++
		} else {
			stats.Successes++
			ms := float64(elapsed) / float64(time.Millisecond)
			successfulLatencies = append(successfulLatencies, ms)
			sum += ms
		}

		// Rate pacing: small delay between samples to prevent flooding (max 20 QPS)
		if i < count-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	stats.LossPercent = float64(stats.Failures) / float64(count) * 100.0

	if len(successfulLatencies) == 0 {
		return stats, nil
	}

	sort.Float64s(successfulLatencies)
	stats.TimingsMS = successfulLatencies
	stats.MinMS = successfulLatencies[0]
	stats.MaxMS = successfulLatencies[len(successfulLatencies)-1]
	stats.MeanMS = sum / float64(len(successfulLatencies))

	// Median
	n := len(successfulLatencies)
	if n%2 == 1 {
		stats.MedianMS = successfulLatencies[n/2]
	} else {
		stats.MedianMS = (successfulLatencies[n/2-1] + successfulLatencies[n/2]) / 2.0
	}

	// P95
	p95Idx := int(math.Ceil(0.95*float64(n))) - 1
	if p95Idx < 0 {
		p95Idx = 0
	}
	if p95Idx >= n {
		p95Idx = n - 1
	}
	stats.P95MS = successfulLatencies[p95Idx]

	// Standard Deviation
	var varianceSum float64
	for _, lat := range successfulLatencies {
		diff := lat - stats.MeanMS
		varianceSum += diff * diff
	}
	stats.StdDevMS = math.Sqrt(varianceSum / float64(len(successfulLatencies)))

	return stats, nil
}
