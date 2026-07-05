package memory

import "testing"

func TestOrigin(t *testing.T) {
	if got := Origin(FromTool, "web_search"); got != "tool:web_search" {
		t.Errorf("Origin = %q, want tool:web_search", got)
	}
	if got := Origin(FromUser, ""); got != "user" {
		t.Errorf("Origin with no name = %q, want user", got)
	}
}

func TestStoreWriteReadProvenance(t *testing.T) {
	s := NewStore()
	s.Write("q", "hello", string(FromUser))
	s.Write("r", "external snippet", Origin(FromTool, "web_search"))

	u, ok := s.Read("q")
	if !ok || !u.IsTrusted() {
		t.Errorf("user-origin entry should be trusted: %+v", u)
	}

	e, ok := s.Read("r")
	if !ok || e.IsTrusted() {
		t.Errorf("tool-origin entry must NOT be trusted: %+v", e)
	}
	if e.Provenance != "tool:web_search" {
		t.Errorf("provenance = %q, want tool:web_search", e.Provenance)
	}

	if got := s.Keys(); len(got) != 2 || got[0] != "q" || got[1] != "r" {
		t.Errorf("Keys = %v, want [q r]", got)
	}
}
