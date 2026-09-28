package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	if ns, ok := query["ns"]; ok && (len(ns) != 1 || ns[0] != "docker.io" && ns[0] != "registry-1.docker.io") {
		http.Error(w, "mirror only supports Docker Hub", http.StatusBadRequest)
		return
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
			pr.Out.URL.Host = "registry-1.docker.io"
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

// mirrorTransport supplies anonymous Hub credentials and follows blob redirects.
type mirrorTransport struct {
	proxy      *ProxyHandler
	repository string
}

func (m mirrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	query := url.Values{"service": {"registry.docker.io"}, "scope": {"repository:" + m.repository + ":pull"}}
	tokenReq, err := http.NewRequestWithContext(req.Context(), http.MethodGet, "https://auth.docker.io/token?"+query.Encode(), nil)
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
			return nil, fmt.Errorf("unexpected Docker Hub token redirect")
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
		return nil, fmt.Errorf("decode Docker Hub token: %w", err)
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" {
		return nil, fmt.Errorf("Docker Hub returned an empty token")
	}
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.Header.Set("Authorization", "Bearer "+token.Token)
	var digest string
	client := http.Client{
		Transport: m.proxy.transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many Docker Hub redirects")
			}
			u := next.URL
			if u.Scheme != "https" || u.User != nil || u.Port() != "" && u.Port() != "443" || !mirrorDownloadHost(u.Hostname()) {
				return fmt.Errorf("Docker Hub redirect host not allowed: %s", u.Host)
			}
			if u.Hostname() != "registry-1.docker.io" {
				next.Header.Del("Authorization")
			}
			if digest == "" && next.Response != nil {
				digest = next.Response.Header.Get("Docker-Content-Digest")
			}
			return nil
		},
	}
	resp, err := client.Do(out)
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

func mirrorDownloadHost(host string) bool {
	// Keep this separate from the general forward-proxy allowlist.
	switch strings.ToLower(host) {
	case "registry-1.docker.io", "production.cloudfront.docker.com", "production.cloudflare.docker.com":
		return true
	default:
		return false
	}
}
