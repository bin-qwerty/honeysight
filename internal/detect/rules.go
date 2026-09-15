// Package detect implements the signature-based detection engine: pure
// functions over request fields, rules in external YAML with hot reload.
package detect

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type ruleFile struct {
	Rules []rawRule `yaml:"rules"`
}

type rawRule struct {
	ID        string   `yaml:"id"`
	Category  string   `yaml:"category"`
	Weight    int      `yaml:"weight"`
	Patterns  []string `yaml:"patterns"`   // matched against path+query+body
	UserAgent string   `yaml:"user_agent"` // matched against the User-Agent header
}

type rule struct {
	rawRule
	re   *regexp.Regexp
	uaRe *regexp.Regexp
}

// Engine matches requests against a set of signature rules.
type Engine struct {
	mu    sync.RWMutex
	rules []*rule
	path  string
}

// Load compiles the rules from a YAML file.
func Load(path string) (*Engine, error) {
	e := &Engine{path: path}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload re-reads and recompiles the rules file without a restart.
func (e *Engine) Reload() error {
	data, err := os.ReadFile(e.path)
	if err != nil {
		return fmt.Errorf("read rules: %w", err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	compiled := make([]*rule, 0, len(rf.Rules))
	for i, r := range rf.Rules {
		cr := &rule{rawRule: r}
		if len(r.Patterns) > 0 {
			re, err := regexp.Compile("(?i)(" + strings.Join(r.Patterns, "|") + ")")
			if err != nil {
				return fmt.Errorf("rule %q (index %d): %w", r.ID, i, err)
			}
			cr.re = re
		}
		if r.UserAgent != "" {
			re, err := regexp.Compile("(?i)" + r.UserAgent)
			if err != nil {
				return fmt.Errorf("rule %q (index %d) user_agent: %w", r.ID, i, err)
			}
			cr.uaRe = re
		}
		if cr.re == nil && cr.uaRe == nil {
			return fmt.Errorf("rule %q (index %d): has no patterns", r.ID, i)
		}
		if cr.Weight <= 0 {
			return fmt.Errorf("rule %q (index %d): weight must be > 0", r.ID, i)
		}
		compiled = append(compiled, cr)
	}
	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()
	return nil
}
