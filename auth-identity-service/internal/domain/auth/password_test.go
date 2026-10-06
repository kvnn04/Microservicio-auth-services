package auth

import (
	"strings"
	"testing"
)

func TestValidateSyntax(t *testing.T) {
	tests := []struct {
		name      string
		pw        string
		localPart string
		wantErr   error
	}{
		{name: "valida ok", pw: "Str0ng!Passw0rd-2026", localPart: "test"},
		{name: "unicode ok NFKC", pw: "Str0ng!Pässwörd-2026"},
		{name: "muy corta 11", pw: "Ab1!Ab1!Ab1", wantErr: ErrPasswordTooShort},
		{name: "minimo 12 ok", pw: "Ab1!Ab1!Ab1x"},
		{name: "sin mayuscula", pw: "str0ng!passw0rd-", wantErr: ErrPasswordMissingCls},
		{name: "sin minuscula", pw: "STR0NG!PASSW0RD-", wantErr: ErrPasswordMissingCls},
		{name: "sin digito", pw: "Strong!Password-", wantErr: ErrPasswordMissingCls},
		{name: "sin simbolo", pw: "Str0ngPassw0rd12", wantErr: ErrPasswordMissingCls},
		{name: "4 repetidos", pw: "Str0ng!aaaa2026", wantErr: ErrPasswordRepeating},
		{name: "3 repetidos ok", pw: "Str0ng!aaa2026x"},
		{name: "igual a local-part", pw: "Testuser01!x", localPart: "testuser01!x", wantErr: ErrPasswordEqualsMail},
		{name: "control rechazado", pw: "Str0ng!\x00Passw0rd", wantErr: ErrPasswordHasControl},
		{name: "muy larga", pw: strings.Repeat("A", 64) + strings.Repeat("a", 32) + strings.Repeat("1", 16) + strings.Repeat("!", 17), wantErr: ErrPasswordTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSyntax(tt.pw, tt.localPart)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}
