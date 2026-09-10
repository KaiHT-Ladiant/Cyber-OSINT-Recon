package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDomainList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := `# comment
example.com
EXAMPLE.ORG
example.com
not a domain
https://foo.bar/
# trailing

`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	domains, err := loadDomainList(path)
	if err != nil {
		t.Fatalf("loadDomainList: %v", err)
	}
	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d: %#v", len(domains), domains)
	}
	if domains[0] != "example.com" || domains[1] != "example.org" || domains[2] != "foo.bar" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}

func TestResolveScanModeExplicit(t *testing.T) {
	mode, err := resolveScanMode("MULTI")
	if err != nil || mode != modeMulti {
		t.Fatalf("got %q err=%v", mode, err)
	}
	mode, err = resolveScanMode("single")
	if err != nil || mode != modeSingle {
		t.Fatalf("got %q err=%v", mode, err)
	}
	if _, err := resolveScanMode("nope"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestIsDomain(t *testing.T) {
	cases := map[string]bool{
		"example.com":     true,
		"sub.example.co.kr": true,
		"Example Corp":    false,
		"nodot":           false,
		"":                false,
	}
	for in, want := range cases {
		if got := isDomain(in); got != want {
			t.Fatalf("isDomain(%q)=%v want %v", in, got, want)
		}
	}
}
