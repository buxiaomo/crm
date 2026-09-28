package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const authTestUser = "crm-user"
const authTestPassword = "p@ss:/?# with space"

func authTestHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Configure through the public format so a missing config field fails behaviorally.
func enableTestAuth(t *testing.T, p *ProxyHandler) {
	t.Helper()
	if err := json.Unmarshal([]byte(`{"auth":{"users":{"crm-user":"p@ss:/?# with space","second":"another-secret"}}}`), globalConfig); err != nil {
		t.Fatal(err)
	}
	configured := newProxyHandler(p.allowedPatterns, false, p.level, globalConfig)
	configured.transport.CloseIdleConnections()
	configured.transport = p.transport
	*p = *configured
}

func TestAuthConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		valid        bool
	}{
		{"omitted", `{}`, true},
		{"null", `{"auth":null}`, true},
		{"users", `{"auth":{"users":{"alice":"secret:with-colon","bob":"other"}}}`, true},
		{"empty_auth", `{"auth":{}}`, false},
		{"empty_users", `{"auth":{"users":{}}}`, false},
		{"null_users", `{"auth":{"users":null}}`, false},
		{"empty_username", `{"auth":{"users":{"":"sensitive-value"}}}`, false},
		{"empty_password", `{"auth":{"users":{"sensitive-user":""}}}`, false},
		{"username_colon", `{"auth":{"users":{"sensitive:user":"sensitive-value"}}}`, false},
		{"username_control", `{"auth":{"users":{"sensitive\nuser":"sensitive-value"}}}`, false},
		{"password_control", `{"auth":{"users":{"sensitive-user":"sensitive\u007fvalue"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Listen: ":8888"}
			if err := json.Unmarshal([]byte(tc.config), cfg); err != nil {
				t.Fatal(err)
			}
			err := cfg.Validate()
			if (err == nil) != tc.valid {
				t.Errorf("Validate error=%v, valid=%t", err, tc.valid)
			}
			if err != nil && strings.Contains(err.Error(), "sensitive") {
				t.Error("configuration error disclosed credentials")
			}
		})
	}
}

func TestAuthConfigLoading(t *testing.T) {
	for _, tc := range []struct {
		ext, body string
	}{
		{"yaml", "listen: ':8888'\nauth:\n  users:\n    alice: loaded-secret\n"},
		{"json", `{"listen":":8888","auth":{"users":{"alice":"loaded-secret"}}}`},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config."+tc.ext)
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfigFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			p := testProxyHandler(t)
			p = newProxyHandler(p.allowedPatterns, false, 0, cfg)
			t.Cleanup(p.transport.CloseIdleConnections)
			for _, credentials := range []string{"", authTestHeader("alice", "loaded-secret")} {
				req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
				req.Header.Set("Authorization", credentials)
				rec := httptest.NewRecorder()
				p.ServeHTTP(rec, req)
				want := http.StatusOK
				if credentials == "" {
					want = http.StatusUnauthorized
				}
				if rec.Code != want {
					t.Errorf("loaded credentials present=%t: status=%d, want %d", credentials != "", rec.Code, want)
				}
			}
		})
	}
	for _, tc := range []struct {
		ext, body string
	}{
		{"yaml", "auth:\n  users: sensitive-type-error-secret\n"},
		{"json", `{"auth":{"users":"sensitive-type-error-secret"}}`},
	} {
		t.Run(tc.ext+"_invalid_type", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config."+tc.ext)
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfigFrom(path)
			if err == nil {
				t.Fatal("accepted invalid auth.users type")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Error("parse error disclosed configuration input")
			}
		})
	}
}

func TestAuthProtectsEveryEntry(t *testing.T) {
	p := testProxyHandler(t)
	enableTestAuth(t, p)
	var dials atomic.Int64
	p.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("test blocks unauthenticated upstream access")
	}
	valid := authTestHeader(authTestUser, authTestPassword)
	for _, endpoint := range []struct {
		method, path string
		proxy        bool
	}{
		{"HEAD", "/", false}, {"POST", "/", false}, {"OPTIONS", "/", false},
		{"HEAD", "/healthz", false}, {"POST", "/metrics", false},
		{"GET", "/healthz/", false}, {"GET", "/metrics/other", false},
		{"GET", "/%68ealthz", false}, {"GET", "/%6detrics", false}, {"GET", "/%2f", false},
		{"GET", "/v2/", false}, {"HEAD", "/v2/", false},
		{"GET", "/v2/library/nginx/manifests/latest", false},
		{"GET", "/v2/library/nginx/blobs/test", false}, {"POST", "/v2/upload", false},
		{"GET", "http://127.0.0.1:9/v2/", true}, {"CONNECT", "127.0.0.1:9", true},
		{"GET", "http://127.0.0.1:9/", true},
		{"GET", "http://127.0.0.1:9/metrics", true}, {"GET", "http://127.0.0.1:9/healthz", true},
	} {
		for _, credentials := range []struct {
			name   string
			values []string
		}{
			{"missing", nil}, {"wrong_user", []string{authTestHeader("unknown", authTestPassword)}},
			{"wrong_password", []string{authTestHeader(authTestUser, "wrong")}},
			{"bearer", []string{"Bearer token"}}, {"bad_base64", []string{"Basic !!!"}},
			{"missing_colon", []string{"Basic YWxpY2U="}}, {"duplicate", []string{valid, valid}},
			{"wrong_header", nil},
		} {
			t.Run(endpoint.method+endpoint.path+"/"+credentials.name, func(t *testing.T) {
				req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
				header, challenge, other := "Authorization", "WWW-Authenticate", "Proxy-Authorization"
				want := http.StatusUnauthorized
				if endpoint.proxy {
					header, challenge, other = "Proxy-Authorization", "Proxy-Authenticate", "Authorization"
					want = http.StatusProxyAuthRequired
				}
				for _, value := range credentials.values {
					req.Header.Add(header, value)
				}
				if credentials.name == "wrong_header" {
					req.Header.Set(other, valid)
				}
				rec := httptest.NewRecorder()
				p.ServeHTTP(rec, req)
				if rec.Code != want || rec.Header().Get(challenge) != `Basic realm="CRM", charset="UTF-8"` {
					t.Errorf("status=%d challenge=%q, want %d and CRM Basic challenge", rec.Code, rec.Header().Get(challenge), want)
				}
			})
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("unauthenticated requests attempted %d upstream connections", n)
	}
	// Authentication takes precedence even when all request slots are occupied.
	concurrentReqs = make(chan struct{}, 1)
	concurrentReqs <- struct{}{}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("busy unauthenticated request status=%d, want 401", rec.Code)
	}
}

func TestAuthMirrorPull(t *testing.T) {
	for _, registry := range []struct{ host, token, cdn, query string }{
		{"registry-1.docker.io", "auth.docker.io", "production.cloudfront.docker.com", ""},
		{"ghcr.io", "ghcr.io", "pkg-containers.githubusercontent.com", "?ns=ghcr.io"},
	} {
		t.Run(registry.host, func(t *testing.T) {
			var requests, tokens, downloads atomic.Int64
			content := "authenticated layer"
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
			p, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				for _, header := range []string{"Proxy-Authorization", "Cookie", "X-Client-Secret"} {
					if r.Header.Get(header) != "" {
						t.Errorf("%s leaked %s", r.Host, header)
					}
				}
				if strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") || r.URL.User != nil {
					t.Errorf("%s received CRM credentials", r.Host)
				}
				if r.Host == registry.token && r.URL.Path == "/token" {
					tokens.Add(1)
					if r.Header.Get("Authorization") != "" || r.URL.Query().Get("scope") != "repository:org/image:pull" {
						t.Error("token request included credentials or wrong scope")
					}
					io.WriteString(w, `{"token":"anonymous-token"}`)
					return
				}
				if r.Host == registry.cdn {
					downloads.Add(1)
					if r.Header.Get("Authorization") != "" {
						t.Error("credentials reached CDN")
					}
					io.WriteString(w, content)
					return
				}
				if r.Host != registry.host {
					t.Errorf("unexpected upstream %s", r.Host)
				}
				if registry.host == "ghcr.io" && r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", `Bearer realm="https://ghcr.io/token", service="ghcr.io"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Header.Get("Authorization") != "Bearer anonymous-token" {
					t.Error("registry did not receive its anonymous token")
				}
				w.Header().Set("Docker-Content-Digest", digest)
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
					http.Redirect(w, r, "https://"+registry.cdn+"/download", http.StatusTemporaryRedirect)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(content)))
				if r.Method != http.MethodHead {
					io.WriteString(w, content)
				}
			})
			enableTestAuth(t, p)
			client := server.Client()
			client.Timeout = 3 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			for _, path := range []string{"/v2/org/image/manifests/latest", "/v2/org/image/blobs/test"} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					u, err := url.Parse(server.URL + path + registry.query)
					if err != nil {
						t.Fatal(err)
					}
					u.User = url.UserPassword(authTestUser, authTestPassword)
					req, err := http.NewRequest(method, u.String(), nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Proxy-Authorization", authTestHeader(authTestUser, authTestPassword))
					req.Header.Set("Cookie", "session=local-secret")
					req.Header.Set("X-Client-Secret", "local-secret")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != 200 || resp.Header.Get("Docker-Content-Digest") != digest || resp.Header.Get("Location") != "" || resp.Header.Get("WWW-Authenticate") != "" {
						t.Errorf("authenticated pull changed response: %d %v", resp.StatusCode, resp.Header)
					}
					if method == http.MethodGet && string(body) != content || method == http.MethodHead && len(body) != 0 {
						t.Errorf("%s returned body=%q", method, body)
					}
				}
			}
			if tokens.Load() != 4 || downloads.Load() != 1 {
				t.Errorf("token/CDN requests=%d/%d, want 4/1", tokens.Load(), downloads.Load())
			}
			before := requests.Load()
			for _, password := range []string{"", "wrong"} {
				u, err := url.Parse(server.URL + "/v2/org/image/blobs/test" + registry.query)
				if err != nil {
					t.Fatal(err)
				}
				if password != "" {
					u.User = url.UserPassword(authTestUser, password)
				}
				resp, err := client.Get(u.String())
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("request after successful pull bypassed authentication: %d", resp.StatusCode)
				}
			}
			if requests.Load() != before {
				t.Error("unauthenticated request reached upstream after successful pull")
			}
		})
	}
}

func TestAuthHTTPProxyCredentials(t *testing.T) {
	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "Bearer upstream-secret" {
			t.Error("proxy credentials leaked or independent upstream authorization was lost")
		}
		io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	p := testProxyHandler(t)
	enableTestAuth(t, p)
	server := httptest.NewServer(logMiddleware(0, p))
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("second", "another-secret")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for i, path := range []string{"/v2/resource", "/", "/metrics", "/healthz"} {
		req, err := http.NewRequest(http.MethodGet, upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer upstream-secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "upstream" || requests.Load() != int64(i+1) {
			t.Errorf("authenticated proxy %s status=%d requests=%d; expected upstream content", path, resp.StatusCode, requests.Load())
		}
	}
}

func TestAuthCONNECT(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	defer func() { upstream.Close(); <-acceptDone }()
	p := testProxyHandler(t)
	enableTestAuth(t, p)
	done := make(chan struct{}, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		logMiddleware(0, p).ServeHTTP(w, r)
	}))
	defer server.Close()
	for _, credentials := range []string{"", authTestHeader(authTestUser, "wrong"), authTestHeader(authTestUser, authTestPassword)} {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", upstream.Addr(), upstream.Addr(), credentials)
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		want := http.StatusProxyAuthRequired
		if credentials == authTestHeader(authTestUser, authTestPassword) {
			want = http.StatusOK
		}
		if resp.StatusCode != want {
			t.Errorf("CONNECT status=%d, want %d", resp.StatusCode, want)
		}
		if resp.StatusCode == http.StatusOK {
			fmt.Fprint(conn, "ping")
			payload := make([]byte, 4)
			if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "ping" {
				t.Errorf("CONNECT payload=%q error=%v", payload, err)
			}
		} else if resp.Header.Get("Proxy-Authenticate") != `Basic realm="CRM", charset="UTF-8"` {
			t.Error("CONNECT did not return the local proxy challenge")
		}
		conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("CONNECT handler did not exit")
		}
	}
	if accepted.Load() != 1 {
		t.Errorf("upstream connections=%d, want only the authenticated connection", accepted.Load())
	}
}

func TestAuthChallengePreservesHealth(t *testing.T) {
	p := testProxyHandler(t)
	enableTestAuth(t, p)
	oldMetrics := metrics
	metrics = &Metrics{StartTime: time.Now()}
	defer func() { metrics = oldMetrics }()
	unauthorized := httptest.NewRecorder()
	p.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous request status=%d, want 401", unauthorized.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.SetBasicAuth(authTestUser, authTestPassword)
	resp := httptest.NewRecorder()
	p.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("normal auth challenge marked the service unhealthy: status=%d", resp.Code)
	}
}

func TestAuthPublicEndpoints(t *testing.T) {
	base := testProxyHandler(t)
	enableTestAuth(t, base)
	globalConfig.AllowedHosts = []string{"custom-registry.example", "CUSTOM-REGISTRY.EXAMPLE", "^registry<test>\\.example$"}
	p := newProxyHandler(buildAllowedPatterns(globalConfig), false, 0, globalConfig)
	t.Cleanup(p.transport.CloseIdleConnections)
	oldMetrics := metrics
	metrics = &Metrics{StartTime: time.Now()}
	t.Cleanup(func() { metrics = oldMetrics })
	p.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("public endpoint or unauthenticated mirror request reached upstream")
		return nil, fmt.Errorf("unexpected upstream access")
	}
	assertNoSecrets := func(body string) {
		t.Helper()
		for _, secret := range []string{authTestUser, authTestPassword, "another-secret"} {
			if strings.Contains(body, secret) {
				t.Error("public response disclosed authentication credentials")
			}
		}
	}
	// Check the configured list directly and through the anonymous HTTP endpoint.
	page := httptest.NewRecorder()
	p.serveIndex(page, httptest.NewRequest(http.MethodGet, "/", nil))
	assertNoSecrets(page.Body.String())
	for _, item := range []string{"<li>docker.io</li>", "<li>custom-registry.example</li>", `<li>^registry&lt;test&gt;\.example$</li>`} {
		if strings.Count(page.Body.String(), item) != 1 {
			t.Errorf("allowlist item %q missing or duplicated", item)
		}
	}
	if strings.Contains(page.Body.String(), "CUSTOM-REGISTRY.EXAMPLE") || strings.Contains(page.Body.String(), "<test>") {
		t.Error("allowlist was not deduplicated or HTML escaped")
	}
	server := httptest.NewServer(logMiddleware(0, p))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 3 * time.Second
	for _, endpoint := range []struct{ path, contentType, content string }{
		{"/", "text/html", "<li>custom-registry.example</li>"},
		{"/healthz", "application/json", `"status": "healthy"`},
		{"/metrics", "text/plain", "total_requests "},
	} {
		for _, credentials := range []string{"", "Basic invalid"} {
			req, err := http.NewRequest(http.MethodGet, server.URL+endpoint.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if credentials != "" {
				req.Header.Set("Authorization", credentials)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("WWW-Authenticate") != "" {
				t.Errorf("public GET %s status=%d challenge=%q", endpoint.path, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
			}
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), endpoint.contentType) || !strings.Contains(string(body), endpoint.content) {
				t.Errorf("public GET %s did not return its expected content", endpoint.path)
			}
			assertNoSecrets(string(body))
		}
	}
	resp, err := client.Get(server.URL + "/v2/library/nginx/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("public requests authorized a subsequent mirror pull: status=%d", resp.StatusCode)
	}
	// Public endpoints still share the existing concurrency limit.
	concurrentReqs = make(chan struct{}, 1)
	concurrentReqs <- struct{}{}
	busy := httptest.NewRecorder()
	p.ServeHTTP(busy, httptest.NewRequest(http.MethodGet, "/", nil))
	if busy.Code != http.StatusTooManyRequests {
		t.Errorf("public index bypassed concurrency limit: status=%d", busy.Code)
	}
}

func TestIndexAuthStatus(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		enabled      bool
	}{
		{"omitted", "listen: ':8888'\n", false},
		{"null", "listen: ':8888'\nauth: null\n", false},
		{"enabled", "listen: ':8888'\nauth:\n  users:\n    status-user-private: status-password-private\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "status.yaml")
			if err := os.WriteFile(path, []byte(tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfigFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			base := testProxyHandler(t)
			globalConfig = cfg
			p := newProxyHandler(base.allowedPatterns, false, 0, cfg)
			t.Cleanup(p.transport.CloseIdleConnections)
			page := httptest.NewRecorder()
			p.serveIndex(page, httptest.NewRequest(http.MethodGet, "/", nil))
			server := httptest.NewServer(logMiddleware(0, p))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 3 * time.Second
			resp, err := client.Get(server.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("WWW-Authenticate") != "" {
				t.Errorf("anonymous index status=%d challenge=%q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
			}
			want := []string{"未开启认证：镜像加速允许匿名访问"}
			unwanted := []string{"已开启认证", "未授权无法使用镜像加速，请先配置客户端认证"}
			if tc.enabled {
				want, unwanted = unwanted, want
			}
			unwanted = append(unwanted, "status-user-private", "status-password-private", "auth.users", "auth:", "users:", "REPLACE_WITH_A_STRONG_PASSWORD")
			for _, rendered := range []struct{ name, body string }{
				{"direct", page.Body.String()}, {"http", string(body)},
			} {
				for _, text := range want {
					if !strings.Contains(rendered.body, text) {
						t.Errorf("%s index missing authentication state %q", rendered.name, text)
					}
				}
				for _, text := range unwanted {
					if strings.Contains(rendered.body, text) {
						t.Errorf("%s index disclosed credentials/configuration or displayed the opposite state", rendered.name)
					}
				}
			}
			resp, err = client.Get(server.URL + "/v2/")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			wantStatus := http.StatusOK
			if tc.enabled {
				wantStatus = http.StatusUnauthorized
			}
			if resp.StatusCode != wantStatus {
				t.Errorf("anonymous mirror status=%d after index, want %d", resp.StatusCode, wantStatus)
			}
		})
	}
}
