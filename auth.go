package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// AuthConfig holds credentials used only to authorize access to CRM.
type AuthConfig struct {
	Users map[string]string `yaml:"users" json:"users"`
}

// Validate rejects an explicitly configured but unusable authentication policy.
func (c *AuthConfig) Validate() error {
	if c == nil {
		return nil
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("auth.users must contain at least one account")
	}
	for username, password := range c.Users {
		if username == "" || password == "" || strings.Contains(username, ":") ||
			strings.IndexFunc(username+password, unicode.IsControl) >= 0 {
			return fmt.Errorf("auth.users requires nonempty credentials without control characters or colons in usernames")
		}
	}
	return nil
}

func (p *ProxyHandler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if p.auth == nil || isPublicRequest(r) {
		return true
	}
	header, challenge, status := "Authorization", "WWW-Authenticate", http.StatusUnauthorized
	forward := r.Method == http.MethodConnect || r.URL.IsAbs()
	if forward {
		header, challenge, status = "Proxy-Authorization", "Proxy-Authenticate", http.StatusProxyAuthRequired
	}
	values := r.Header.Values(header)
	authReq := &http.Request{Header: http.Header{"Authorization": values}}
	username, password, ok := authReq.BasicAuth()
	expected, exists := p.auth.Users[username]
	gotHash, wantHash := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(expected))
	match := subtle.ConstantTimeCompare(gotHash[:], wantHash[:])
	if len(values) != 1 || !ok || !exists || match != 1 {
		w.Header().Set(challenge, `Basic realm="CRM", charset="UTF-8"`)
		http.Error(w, "CRM authentication required", status)
		return false
	}
	// Proxy credentials belong to CRM; Authorization on a proxy request belongs to its target.
	r.Header.Del("Proxy-Authorization")
	if !forward {
		r.Header.Del("Authorization")
		r.URL.User = nil
	}
	return true
}

// isPublicRequest limits anonymous access to local, read-only informational endpoints.
func isPublicRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.IsAbs() || r.URL.Host != "" {
		return false
	}
	switch r.URL.EscapedPath() {
	case "/", "/healthz", "/metrics":
		return true
	default:
		return false
	}
}
