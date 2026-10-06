package auth

import (
	"errors"
	"testing"
)

func TestDistinctFromHashes(t *testing.T) {
	verify := func(plain, hash string) (bool, error) {
		return "v:" + plain == hash, nil
	}
	cases := []struct {
		name      string
		new       string
		current   string
		history   []string
		wantReuse bool
		wantHist  bool
	}{
		{"nueva ok", "nueva", "v:vieja", []string{"v:h1", "v:h2"}, false, false},
		{"igual actual", "vieja", "v:vieja", []string{"v:h1"}, true, false},
		{"en historial", "h2", "v:vieja", []string{"v:h1", "v:h2"}, false, true},
		{"actual prevalece", "x", "v:x", []string{"v:x"}, true, false},
		{"sin hash actual", "h1", "", []string{"v:h1"}, false, true},
		{"historial vacío", "nueva", "v:vieja", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reused, hist, dirty := DistinctFromHashes(tc.new, verify, tc.current, tc.history)
			if reused != tc.wantReuse || hist != tc.wantHist || dirty != 0 {
				t.Fatalf("got %v %v %d", reused, hist, dirty)
			}
		})
	}
}

func TestDistinctFromHashes_DirtyNoBloquea(t *testing.T) {
	verify := func(plain, hash string) (bool, error) {
		if hash == "roto" {
			return false, errors.New("argon2 decode")
		}
		return "v:"+plain == hash, nil
	}
	// Hash corrupto en historial se ignora (WARN en servicio), no bloquea.
	reused, hist, dirty := DistinctFromHashes("nueva", verify, "v:vieja", []string{"roto", "v:otra"})
	if reused || hist || dirty != 1 {
		t.Fatalf("got %v %v %d", reused, hist, dirty)
	}
	// Corrupto en actual también se cuenta como dirty (el servicio lo trata
	// como mismatch y sigue; el cambio solo falla si Verify da true).
	reused, _, dirty = DistinctFromHashes("nueva", verify, "roto", nil)
	if reused || dirty != 1 {
		t.Fatalf("got %v %d", reused, dirty)
	}
}

func TestChangeAccount_HasPassword(t *testing.T) {
	if (&ChangeAccount{Hash: "h"}).HasPassword() != true {
		t.Fatal("con hash")
	}
	if (&ChangeAccount{}).HasPassword() != false {
		t.Fatal("sin hash")
	}
	if (*ChangeAccount)(nil).HasPassword() != false {
		t.Fatal("nil")
	}
}

func TestSameHash_ConstantTime(t *testing.T) {
	if !SameHash("abc", "abc") {
		t.Fatal("iguales")
	}
	if SameHash("abc", "abd") {
		t.Fatal("distintos")
	}
	if SameHash("", "") {
		t.Fatal("vacíos no comparables")
	}
	if SameHash("ab", "abc") {
		t.Fatal("longitud")
	}
}

func TestPasswordHistoryConsts(t *testing.T) {
	if PasswordHistoryN != 5 || PwdChangeRatePerHour != 5 {
		t.Fatal("N=5, rate 5/h")
	}
}
