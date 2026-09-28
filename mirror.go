package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func (p *ProxyHandler) serveMirror(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "mirror is read-only", http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid mirror query", http.StatusBadRequest)
		return
	}
	host := "registry-1.docker.io"
	if ns, ok := query["ns"]; ok {
		if len(ns) != 1 {
			http.Error(w, "invalid mirror namespace", http.StatusBadRequest)
			return
		}
		namespace := strings.ToLower(ns[0])
		u, err := url.Parse("https://" + namespace)
		if err != nil || !mirrorHTTPSURL(u) || u.Host != namespace || net.ParseIP(u.Hostname()) != nil {
			http.Error(w, "invalid mirror namespace", http.StatusBadRequest)
			return
		}
		host = u.Hostname()
		if host == "docker.io" {
			host = "registry-1.docker.io"
		}
		if !isAllowedHost(host, p.allowedPatterns) {
			http.Error(w, "mirror namespace not allowed", http.StatusBadRequest)
			return
		}
	}
	query.Del("ns")
	if r.URL.Path == "/v2/" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "2")
		if r.Method == http.MethodGet {
			io.WriteString(w, "{}")
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/"), "/")
	if len(parts) < 3 || parts[len(parts)-2] != "manifests" && parts[len(parts)-2] != "blobs" {
		http.NotFound(w, r)
		return
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			http.NotFound(w, r)
			return
		}
	}
	repo := strings.Join(parts[:len(parts)-2], "/")
	proxy := httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.URL.User = nil
			pr.Out.URL.RawQuery = query.Encode()
			pr.Out.Host = pr.Out.URL.Host
			pr.Out.Body = nil
			pr.Out.ContentLength = 0
			pr.Out.TransferEncoding = nil
			// Forward only download semantics, never client credentials or cookies.
			headers := make(http.Header)
			for _, key := range []string{"Accept", "Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "User-Agent"} {
				if values := pr.Out.Header.Values(key); len(values) > 0 {
					headers[key] = values
				}
			}
			pr.Out.Header = headers
		},
		Transport: mirrorTransport{proxy: p, repository: repo},
		ModifyResponse: func(resp *http.Response) error {
			// Public pulls are authenticated here; clients must not visit upstream auth/CDN endpoints.
			resp.Header.Del("WWW-Authenticate")
			resp.Header.Del("Location")
			resp.Header.Del("Set-Cookie")
			return nil
		},
	}
	proxy.ServeHTTP(w, r)
}

// mirrorTransport supplies anonymous pull credentials and follows blob redirects.
type mirrorTransport struct {
	proxy      *ProxyHandler
	repository string
}

func (m mirrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.RequestURI = ""
	realm := &url.URL{Scheme: "https", Host: "auth.docker.io", Path: "/token"}
	service := "registry.docker.io"
	if req.URL.Host != "registry-1.docker.io" {
		resp, err := m.download(out)
		if err != nil {
			return nil, err
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		scheme, _, _ := strings.Cut(challenge, " ")
		if resp.StatusCode != http.StatusUnauthorized || resp.Request.URL.Hostname() != req.URL.Hostname() || !strings.EqualFold(scheme, "Bearer") {
			return resp, nil
		}
		resp.Body.Close()
		params, err := mirrorBearerParams(challenge)
		if err != nil {
			return nil, fmt.Errorf("invalid registry auth challenge: %w", err)
		}
		realm, err = url.Parse(params["realm"])
		if err != nil || !mirrorHTTPSURL(realm) || !isAllowedHost(realm.Hostname(), m.proxy.allowedPatterns) {
			return nil, fmt.Errorf("registry token realm not allowed")
		}
		service = params["service"]
	}
	query := realm.Query()
	query.Set("service", service)
	query.Set("scope", "repository:"+m.repository+":pull")
	realm.RawQuery = query.Encode()
	tokenReq, err := http.NewRequestWithContext(req.Context(), http.MethodGet, realm.String(), nil)
	if err != nil {
		return nil, err
	}
	// ponytail: fetch one anonymous token per resource; add a bounded expiry cache if this RTT becomes a bottleneck.
	tokenResp, err := m.proxy.transport.RoundTrip(tokenReq)
	if err != nil {
		return nil, err
	}
	if tokenResp.StatusCode != http.StatusOK {
		if tokenResp.StatusCode >= 300 && tokenResp.StatusCode < 400 {
			tokenResp.Body.Close()
			return nil, fmt.Errorf("unexpected registry token redirect")
		}
		return tokenResp, nil
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(tokenResp.Body, 1<<20)).Decode(&token)
	tokenResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decode registry token: %w", err)
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" {
		return nil, fmt.Errorf("registry returned an empty token")
	}
	out.Header.Set("Authorization", "Bearer "+token.Token)
	return m.download(out)
}

func (m mirrorTransport) download(req *http.Request) (*http.Response, error) {
	var digest string
	crossedHost := false
	client := http.Client{
		Transport: m.proxy.transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many registry redirects")
			}
			u := next.URL
			allowed := isAllowedHost(u.Hostname(), m.proxy.allowedPatterns)
			if req.URL.Host == "registry-1.docker.io" {
				allowed = mirrorDownloadHost(u.Hostname())
			} else if req.URL.Host == "ghcr.io" && strings.EqualFold(u.Hostname(), "pkg-containers.githubusercontent.com") {
				allowed = true
			}
			if !mirrorHTTPSURL(u) || !allowed {
				return fmt.Errorf("registry redirect host not allowed: %s", u.Host)
			}
			crossedHost = crossedHost || !strings.EqualFold(u.Hostname(), req.URL.Hostname())
			if crossedHost {
				next.Header.Del("Authorization")
			}
			if digest == "" && next.Response != nil {
				digest = next.Response.Header.Get("Docker-Content-Digest")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// URL errors can contain signed CDN query strings; report only the underlying error.
		if e, ok := err.(*url.Error); ok {
			err = e.Err
		}
		return nil, err
	}
	if resp.Header.Get("Docker-Content-Digest") == "" && digest != "" {
		resp.Header.Set("Docker-Content-Digest", digest)
	}
	return resp, nil
}

func mirrorHTTPSURL(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" &&
		(u.Host == u.Hostname() || u.Host == u.Hostname()+":443")
}

func mirrorBearerParams(challenge string) (map[string]string, error) {
	_, params, _ := strings.Cut(challenge, " ")
	// Auth parameters use commas; MIME's parser handles the same quoted values
	// and escapes after converting only separators outside quoted strings.
	var value strings.Builder
	quoted, escaped := false, false
	for _, c := range params {
		switch {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case !quoted && c == ';':
			return nil, fmt.Errorf("invalid auth parameter separator")
		case !quoted && c == ',':
			c = ';'
		}
		value.WriteRune(c)
	}
	_, result, err := mime.ParseMediaType("Bearer;" + value.String())
	return result, err
}

func mirrorDownloadHost(host string) bool {
	// Keep this separate from the general forward-proxy allowlist.
	switch strings.ToLower(host) {
	case "registry-1.docker.io", "production.cloudfront.docker.com", "production.cloudflare.docker.com":
		return true
	default:
		return false
	}
}
