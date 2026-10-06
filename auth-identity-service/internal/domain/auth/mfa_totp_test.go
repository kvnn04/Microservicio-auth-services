package auth

import (
	"testing"
	"time"
)

func TestNewCounterAndCandidates(t *testing.T) {
	// floor((t+5)/30): borde exacto 30s.
	c0 := NewCounter(time.Unix(0, 0).UTC())
	c1 := NewCounter(time.Unix(25, 0).UTC())
	c2 := NewCounter(time.Unix(30, 0).UTC())
	if c0 != 0 || c1 != 1 || c2 != 1 {
		t.Fatalf("counters %d %d %d", c0, c1, c2)
	}
	cs := Candidates(100)
	if len(cs) != 3 || cs[0] != 99 || cs[1] != 100 || cs[2] != 101 {
		t.Fatalf("ventana: %v", cs)
	}
}

func TestFormatCode(t *testing.T) {
	if FormatCode(42) != "000042" {
		t.Fatal("zero-pad")
	}
	if FormatCode(1000006) != "000006" {
		t.Fatal("mod 10^6")
	}
	if FormatCode(999999) != "999999" {
		t.Fatal("6 dígitos")
	}
}
