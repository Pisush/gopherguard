package tools

import "testing"

// TestRegistryReturnsRawTool is a regression guard for the ADK tool-contract
// gotcha: ADK type-asserts tools to internal interfaces (FunctionTool,
// RequestProcessor) whose methods live on the concrete tool. If the registry
// ever wraps the tool in something that only forwards the tool.Tool interface,
// those assertions fail at runtime with "does not implement RequestProcessor".
// This test asserts the registry returns the *identical* underlying tool.
func TestRegistryReturnsRawTool(t *testing.T) {
	clock, err := NewWorldClock()
	if err != nil {
		t.Fatalf("NewWorldClock: %v", err)
	}

	r := NewRegistry()
	if err := r.Register(clock); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := r.Tools()
	if len(got) != 1 {
		t.Fatalf("Tools() len = %d, want 1", len(got))
	}
	if got[0] != clock.Tool {
		t.Errorf("Tools()[0] is not the raw underlying tool — registry must not wrap/hide the tool")
	}
}

func TestWorldClockScope(t *testing.T) {
	clock, err := NewWorldClock()
	if err != nil {
		t.Fatalf("NewWorldClock: %v", err)
	}
	if clock.Name() != "world_clock" {
		t.Errorf("Name() = %q, want world_clock", clock.Name())
	}
	if clock.PrivilegeScope() != "read:time" {
		t.Errorf("PrivilegeScope() = %q, want read:time", clock.PrivilegeScope())
	}
	if clock.IsMutating() {
		t.Error("world_clock must not be mutating")
	}
	if clock.TouchesUntrusted() {
		t.Error("world_clock must not touch untrusted input")
	}
}

func TestScopeMetadata(t *testing.T) {
	clock, err := NewWorldClock()
	if err != nil {
		t.Fatalf("NewWorldClock: %v", err)
	}
	s := Scope(clock.Tool, "write:db", true, true)
	if s.PrivilegeScope() != "write:db" || !s.IsMutating() || !s.TouchesUntrusted() {
		t.Errorf("Scope metadata not carried through: %+v", s)
	}
}

func TestRegisterRejectsDuplicateName(t *testing.T) {
	clock, err := NewWorldClock()
	if err != nil {
		t.Fatalf("NewWorldClock: %v", err)
	}
	r := NewRegistry()
	if err := r.Register(clock); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(clock); err == nil {
		t.Error("Register accepted a duplicate tool name; want error (breaks name-keyed privilege attribution)")
	}
	if len(r.Tools()) != 1 {
		t.Errorf("registry has %d tools after duplicate, want 1", len(r.Tools()))
	}
}

func TestRegisterRejectsNilTool(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(ScopedTool{}); err == nil {
		t.Error("Register accepted a zero ScopedTool (nil underlying tool); want error")
	}
}
