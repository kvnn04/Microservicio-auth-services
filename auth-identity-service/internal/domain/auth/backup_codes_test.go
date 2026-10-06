package auth

import (
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	c, err := Canonicalize("k7q2-m9xd4p")
	if err != nil || c != "K7Q2M9XD4P" {
		t.Fatalf("got %q %v", c, err)
	}
	// Lower, espacios y guiones múltiples.
	c, err = Canonicalize("  k7q2 - m9xd4p ")
	if err != nil || c != "K7Q2M9XD4P" {
		t.Fatalf("got %q %v", c, err)
	}
	// Alfabeto rechaza 0/O/1/I.
	for _, bad := range []string{"K7Q2M9XD40", "K7Q2M9XDO", "K7Q2M9XD41", "K7Q2M9XD4", "K7Q2M9XD4PP", "ABC!EFGHIJ"} {
		if _, err := Canonicalize(bad); err == nil {
			t.Fatalf("%q debe fallar", bad)
		}
	}
}

func TestDisplay(t *testing.T) {
	if got := Display("K7Q2M9XD4P"); got != "K7Q2-M9XD4P" {
		t.Fatalf("got %q", got)
	}
}

func TestHashWithPepper(t *testing.T) {
	h1 := HashWithPepper("K7Q2M9XD4P", []byte("pepper-32bytes-1234567890123456"))
	h2 := HashWithPepper("K7Q2M9XD4P", nil)
	if h1 == h2 || len(h1) != 64 {
		t.Fatal("pepper debe cambiar el hash")
	}
	if HashWithPepper("K7Q2M9XD4P", []byte("pepper-32bytes-1234567890123456")) != h1 {
		t.Fatal("determinista")
	}
	if !strings.Contains(BackupAlphabet, "A") || strings.Contains(BackupAlphabet, "0") {
		t.Fatal("alfabeto Crockford sin 0/O/1")
	}
}
