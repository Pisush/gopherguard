// Package memory provides gopherguard's provenance-tagged session memory.
//
// Every value carries the origin it came from (user, a named tool, a named
// agent). M1 records provenance so it can be stamped onto spans as
// mem.provenance; M2's memory-poisoning hardening adds validation that a
// decision span never consumes a value whose provenance is untrusted.
package memory

import (
	"sort"
	"sync"
)

// Provenance labels where a remembered value originated.
type Provenance string

const (
	// FromUser is first-party user input (trusted).
	FromUser Provenance = "user"
	// FromTool marks tool-derived content; combine with the tool name, e.g.
	// Origin("tool:web_search"). Treated as untrusted.
	FromTool Provenance = "tool"
	// FromAgent marks another agent's output. Treated as untrusted.
	FromAgent Provenance = "agent"
	// Untrusted is a catch-all for content of external origin.
	Untrusted Provenance = "untrusted"
)

// Origin builds a namespaced provenance label such as "tool:web_search".
func Origin(kind Provenance, name string) string {
	if name == "" {
		return string(kind)
	}
	return string(kind) + ":" + name
}

// Entry is a remembered value together with its provenance.
type Entry struct {
	Value      string
	Provenance string
}

// IsTrusted reports whether the entry's provenance is first-party user input.
// Everything else (tool/agent/external) is untrusted and must be validated
// before a decision consumes it.
func (e Entry) IsTrusted() bool { return e.Provenance == string(FromUser) }

// Store is a concurrency-safe, provenance-tagged key/value session memory.
type Store struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// NewStore returns an empty provenance-tagged store.
func NewStore() *Store {
	return &Store{entries: make(map[string]Entry)}
}

// Write records a value under key with the given provenance label. Use Origin
// to construct namespaced labels.
func (s *Store) Write(key, value, provenance string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = Entry{Value: value, Provenance: provenance}
}

// Read returns the entry for key.
func (s *Store) Read(key string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	return e, ok
}

// Keys returns the stored keys in sorted order.
func (s *Store) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ks := make([]string, 0, len(s.entries))
	for k := range s.entries {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
