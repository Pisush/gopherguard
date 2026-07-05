package tools

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool/functiontool"
)

// DB is a tiny in-memory key/value store standing in for the dbagent's backing
// database (real MCP→Postgres wiring is out of scope for the hardened baseline).
// It is safe for concurrent use.
type DB struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewInMemoryDB returns an empty in-memory store seeded with a couple of rows
// so the dbagent has something to read in a demo.
func NewInMemoryDB() *DB {
	return &DB{data: map[string]string{
		"greeting": "hello from gopherguard",
		"owner":    "gophercon-eu",
	}}
}

func (d *DB) get(key string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.data[key]
	return v, ok
}

func (d *DB) set(key, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[key] = value
}

func (d *DB) keys() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	ks := make([]string, 0, len(d.data))
	for k := range d.data {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// DBQueryArgs is the input to db_query.
type DBQueryArgs struct {
	// Key is the record key to read. Empty lists all keys.
	Key string `json:"key" jsonschema:"record key to read; empty lists all keys"`
}

// DBQueryResult is the output of db_query.
type DBQueryResult struct {
	Key   string   `json:"key,omitempty"`
	Value string   `json:"value,omitempty"`
	Keys  []string `json:"keys,omitempty"`
	Found bool     `json:"found"`
}

// NewDBQuery builds the read-only database tool.
// Scope read:db, non-mutating, does not touch untrusted external input.
func NewDBQuery(db *DB) (ScopedTool, error) {
	t, err := functiontool.New(functiontool.Config{
		Name:        "db_query",
		Description: "Reads a record from the database by key, or lists all keys when key is empty.",
	}, func(_ agent.Context, args DBQueryArgs) (DBQueryResult, error) {
		if strings.TrimSpace(args.Key) == "" {
			return DBQueryResult{Keys: db.keys(), Found: true}, nil
		}
		v, ok := db.get(args.Key)
		return DBQueryResult{Key: args.Key, Value: v, Found: ok}, nil
	})
	if err != nil {
		return ScopedTool{}, fmt.Errorf("build db_query tool: %w", err)
	}
	return Scope(t, "read:db", false, false), nil
}

// DBWriteArgs is the input to db_write.
type DBWriteArgs struct {
	Key   string `json:"key" jsonschema:"record key to write"`
	Value string `json:"value" jsonschema:"value to store"`
}

// DBWriteResult is the output of db_write.
type DBWriteResult struct {
	Key     string `json:"key"`
	Written bool   `json:"written"`
}

// NewDBWrite builds the mutating database tool. Because it changes state it
// sets RequireConfirmation, so ADK gates it behind a human-in-the-loop
// confirmation before execution.
//
// Scope write:db, mutating (→ HITL), does not touch untrusted external input.
func NewDBWrite(db *DB) (ScopedTool, error) {
	t, err := functiontool.New(functiontool.Config{
		Name:                "db_write",
		Description:         "Writes a value to the database under a key. Mutating: requires human confirmation.",
		RequireConfirmation: true,
	}, func(_ agent.Context, args DBWriteArgs) (DBWriteResult, error) {
		if strings.TrimSpace(args.Key) == "" {
			return DBWriteResult{}, fmt.Errorf("db_write: key must not be empty")
		}
		db.set(args.Key, args.Value)
		return DBWriteResult{Key: args.Key, Written: true}, nil
	})
	if err != nil {
		return ScopedTool{}, fmt.Errorf("build db_write tool: %w", err)
	}
	return Scope(t, "write:db", true, false), nil
}
