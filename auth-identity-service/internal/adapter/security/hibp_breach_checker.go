package security

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HIBPBreachChecker implementa auth.BreachChecker vía k-anonymity, timeout 800ms.
type HIBPBreachChecker struct {
	client *http.Client
}

func NewHIBPBreachChecker(timeout time.Duration) *HIBPBreachChecker {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	return &HIBPBreachChecker{client: &http.Client{Timeout: timeout}}
}

func (h *HIBPBreachChecker) IsCompromised(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]
	raw, err := h.FetchRange(ctx, prefix)
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		if idx := strings.Index(sc.Text(), ":"); idx > 0 {
			if strings.ToUpper(strings.TrimSpace(sc.Text()[:idx])) == suffix {
				return true, nil
			}
		}
	}
	return false, nil
}

// FetchRange devuelve el cuerpo crudo del rango HIBP (una llamada).
// Lo usa el decorador de caché para persistirlo sin re-preguntar.
func (h *HIBPBreachChecker) FetchRange(ctx context.Context, prefix string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "auth-identity-service/1.0")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("hibp request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hibp status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
