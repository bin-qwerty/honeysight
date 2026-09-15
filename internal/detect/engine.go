package detect

import (
	"net/url"
	"strings"
)

// Fields are the request parts inspected by the engine.
type Fields struct {
	Path      string
	Query     string
	Body      string
	UserAgent string
}

// Detection is the outcome of analysing one request.
type Detection struct {
	Score      int
	Categories []string
	Matches    map[string]string
}

// IsMalicious reports whether any signature matched.
func (d Detection) IsMalicious() bool { return d.Score > 0 }

// expand returns the value plus up to two decoded forms joined by spaces,
// so single- and double-encoded payloads still match signatures.
func expand(s string, decode func(string) (string, error)) string {
	if s == "" {
		return ""
	}
	parts := []string{s}
	cur := s
	for i := 0; i < 2; i++ {
		dec, err := decode(cur)
		if err != nil || dec == cur {
			break
		}
		parts = append(parts, dec)
		cur = dec
	}
	return strings.Join(parts, " ")
}

// Analyze classifies one request against the rule set. The score is the sum
// of matched category weights (each category counted once), capped at 100.
// Pure and side-effect free.
func (e *Engine) Analyze(f Fields) Detection {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	haystack := strings.Join(
		[]string{
			expand(f.Path, url.PathUnescape),
			expand(f.Query, url.QueryUnescape),
			expand(f.Body, url.PathUnescape),
		}, " ",
	)
	d := Detection{Matches: map[string]string{}}
	seen := map[string]bool{}
	add := func(cat string, weight int, matched string) {
		if seen[cat] {
			return
		}
		seen[cat] = true
		d.Categories = append(d.Categories, cat)
		d.Matches[cat] = truncate(matched, 120)
		d.Score += weight
	}

	for _, r := range rules {
		if r.re != nil {
			if m := r.re.FindString(haystack); m != "" {
				add(r.Category, r.Weight, m)
			}
		}
	}
	if f.UserAgent != "" {
		for _, r := range rules {
			if r.uaRe != nil {
				if m := r.uaRe.FindString(f.UserAgent); m != "" {
					add(r.Category, r.Weight, m)
				}
			}
		}
	}
	if d.Score > 100 {
		d.Score = 100
	}
	return d
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
