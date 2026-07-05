package agents

import (
	"context"
	"testing"

	"github.com/Pisush/gopherguard/internal/telemetry"
	"github.com/Pisush/gopherguard/internal/tools"

	"go.opentelemetry.io/otel/attribute"
)

// TestClassifyRouting pins the deterministic, code-routed coordinator: routing
// is a Go switch on the request, not a model decision. These cases document the
// contract the graph edges depend on.
func TestClassifyRouting(t *testing.T) {
	cases := map[string]string{
		"Search for the latest Go news":     routeResearch,
		"please research quantum computing": routeResearch,
		"look up the weather":               routeResearch,
		"read key owner from the database":  routeData,
		"store this value in the db":        routeData,
		"save a record":                     routeData,
		"write a poem about gophers":        routeWrite,
		"hello there":                       routeWrite,
	}
	for input, want := range cases {
		if got := classify(input); got != want {
			t.Errorf("classify(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestTrustAttrs verifies each tool maps to the correct trust-boundary
// vocabulary — this is what makes stock ADK tool spans carry gopherguard's
// trust attributes, and what M3's detections will query.
func TestTrustAttrs(t *testing.T) {
	web, err := tools.NewWebSearch()
	if err != nil {
		t.Fatalf("NewWebSearch: %v", err)
	}
	got := attrMap(trustAttrs(web))
	if got[telemetry.KeyPrivilegeScope] != "read:web" {
		t.Errorf("web_search privilege_scope = %v, want read:web", got[telemetry.KeyPrivilegeScope])
	}
	if got[telemetry.KeyUntrusted] != true {
		t.Error("web_search must set trust.untrusted_input=true")
	}
	if got[telemetry.KeyEgress] != true {
		t.Error("web_search must set trust.egress=true")
	}
	if got[telemetry.KeyHITLRequired] != false {
		t.Error("web_search must set trust.hitl_required=false (non-mutating)")
	}

	write, err := tools.NewDBWrite(tools.NewInMemoryDB())
	if err != nil {
		t.Fatalf("NewDBWrite: %v", err)
	}
	got = attrMap(trustAttrs(write))
	if got[telemetry.KeyPrivilegeScope] != "write:db" {
		t.Errorf("db_write privilege_scope = %v, want write:db", got[telemetry.KeyPrivilegeScope])
	}
	if got[telemetry.KeyHITLRequired] != true {
		t.Error("db_write must set trust.hitl_required=true (mutating → HITL)")
	}
	if got[telemetry.KeyEgress] != false {
		t.Error("db_write must set trust.egress=false")
	}
}

func attrMap(kvs []attribute.KeyValue) map[attribute.Key]any {
	m := make(map[attribute.Key]any, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value.AsInterface()
	}
	return m
}

func TestContainsAny(t *testing.T) {
	if !containsAny("the latest news", "latest") {
		t.Error("should match 'latest'")
	}
	if containsAny("nothing here", "xyz", "abc") {
		t.Error("should not match")
	}
}

// TestBuildGraph verifies the full hardened graph assembles without error
// (keyless, local-default model) — least-privilege authorization, node wiring,
// and edges all succeed.
func TestBuildGraph(t *testing.T) {
	t.Setenv("GG_MODEL_MODE", "gemma")
	t.Setenv("GOOGLE_API_KEY", "")
	root, err := BuildGraph(context.Background())
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if root == nil {
		t.Fatal("BuildGraph returned nil agent")
	}
	if root.Name() != "gopherguard" {
		t.Errorf("root agent name = %q, want gopherguard", root.Name())
	}
}
