package main

import "testing"

func TestClassifyIndicator(t *testing.T) {
	tests := []struct {
		input string
		kind  string
	}{
		{"44d88612fea8a8f36de82e1278abb02f", "hash"},
		{"8.8.8.8", "ip"},
		{"Example.COM", "domain"},
		{"https://example.com/a?b=c", "url"},
	}
	for _, test := range tests {
		kind, _, err := classifyIndicator(test.input)
		if err != nil {
			t.Fatalf("classifyIndicator(%q): %v", test.input, err)
		}
		if kind != test.kind {
			t.Fatalf("classifyIndicator(%q) kind = %q, want %q", test.input, kind, test.kind)
		}
	}
}

func TestClassifyIndicatorRejectsUnsupported(t *testing.T) {
	if _, _, err := classifyIndicator("not an indicator"); err == nil {
		t.Fatal("expected invalid indicator to be rejected")
	}
}
