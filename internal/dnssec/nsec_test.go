package dnssec

import "testing"

func TestNSECIntervalCovers(t *testing.T) {
	tests := []struct {
		name       string
		owner      string
		nextDomain string
		query      string
		want       bool
	}{
		{
			name: "name inside normal interval",
			owner: "a.example.", nextDomain: "z.example.",
			query: "m.example.", want: true,
		},
		{
			name: "owner endpoint excluded",
			owner: "a.example.", nextDomain: "z.example.",
			query: "a.example.", want: false,
		},
		{
			name: "next domain endpoint excluded",
			owner: "a.example.", nextDomain: "z.example.",
			query: "z.example.", want: false,
		},
		{
			name: "name outside normal interval",
			owner: "a.example.", nextDomain: "z.example.",
			query: "0.example.", want: false,
		},
		{
			name: "canonical ordering compares rootward labels first",
			owner: "example.", nextDomain: "z.example.",
			query: "a.example.", want: true,
		},
		{
			name: "wrap around covers name after owner",
			owner: "z.example.", nextDomain: "a.example.",
			query: "zz.example.", want: true,
		},
		{
			name: "wrap around covers name before next domain",
			owner: "z.example.", nextDomain: "a.example.",
			query: "0.example.", want: true,
		},
		{
			name: "wrap around excludes name between endpoints",
			owner: "z.example.", nextDomain: "a.example.",
			query: "m.example.", want: false,
		},
		{
			name: "case insensitive owner comparison",
			owner: "A.Example.", nextDomain: "Z.Example.",
			query: "a.example.", want: false,
		},
		{
			name: "case insensitive interval membership",
			owner: "A.Example.", nextDomain: "Z.Example.",
			query: "M.EXAMPLE.", want: true,
		},
		{
			name: "identical owner and next covers other names",
			owner: "example.", nextDomain: "EXAMPLE.",
			query: "other.invalid.", want: true,
		},
		{
			name: "identical owner and next excludes owner",
			owner: "example.", nextDomain: "example.",
			query: "EXAMPLE.", want: false,
		},
		{
			name: "invalid owner rejected",
			owner: "", nextDomain: "z.example.",
			query: "m.example.", want: false,
		},
		{
			name: "invalid next domain rejected",
			owner: "a.example.", nextDomain: "not a domain",
			query: "m.example.", want: false,
		},
		{
			name: "invalid query rejected",
			owner: "a.example.", nextDomain: "z.example.",
			query: "", want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NSECIntervalCovers(tt.owner, tt.nextDomain, tt.query); got != tt.want {
				t.Fatalf("NSECIntervalCovers(%q, %q, %q) = %t, want %t",
					tt.owner, tt.nextDomain, tt.query, got, tt.want)
			}
		})
	}
}
