package auth

import "testing"

func boolP(b bool) *bool { return &b }

func TestOIDClaimsIsVerified(t *testing.T) {
	if (&OIDClaims{EmailVerified: boolP(true)}).IsVerified() != true {
		t.Fatal("true estricto → verified")
	}
	for _, c := range []*OIDClaims{
		{EmailVerified: boolP(false)},
		{EmailVerified: nil},
		{},
		nil,
	} {
		if c.IsVerified() {
			t.Fatalf("%+v debe ser no-verified", c)
		}
	}
}
