package security

import (
	"testing"

	"github.com/Pisush/gopherguard/internal/tools"
)

func TestPolicyAuthorizeGrantsInScope(t *testing.T) {
	web, err := tools.NewWebSearch()
	if err != nil {
		t.Fatalf("NewWebSearch: %v", err)
	}
	p := NewPolicy("researcher", "read:web")
	got, err := p.Authorize(web)
	if err != nil {
		t.Fatalf("Authorize in-scope tool failed: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d tools, want 1", len(got))
	}
}

// TestPolicyDeniesOutOfScope is the least-privilege guarantee: an over-scoped
// tool must never reach an agent. The researcher is granted only read:web, so a
// write:db tool must be rejected.
func TestPolicyDeniesOutOfScope(t *testing.T) {
	db := tools.NewInMemoryDB()
	write, err := tools.NewDBWrite(db)
	if err != nil {
		t.Fatalf("NewDBWrite: %v", err)
	}
	p := NewPolicy("researcher", "read:web")
	if _, err := p.Authorize(write); err == nil {
		t.Error("Authorize must reject a write:db tool for a read:web-only agent")
	}
}

func TestAllowAllArgs(t *testing.T) {
	ok, _ := AllowAll{}.AllowArgs("anything", map[string]any{"k": "v"})
	if !ok {
		t.Error("AllowAll must allow")
	}
}
