package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The real HTTP client can only reach CRM; all upstream HTTPS hosts are local.
func mirrorTestServer(t *testing.T, handler http.HandlerFunc) (*ProxyHandler, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	p := testProxyHandler(t)
	p.allowedPatterns = buildAllowedPatterns(nil)
	p.transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Local test upstream only.
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	server := httptest.NewServer(logMiddleware(0, p))
	t.Cleanup(server.Close)
	return p, server
}

func mirrorRequest(t *testing.T, server *httptest.Server, method, path string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")
	req.Header.Set("Authorization", "Bearer client-secret")
	req.Header.Set("Cookie", "session=client-secret")
	req.Header.Set("Proxy-Authorization", "Basic client-secret")
	req.Header.Set("X-Client-Secret", "client-secret")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "hop-secret")
	client := server.Client()
	client.Timeout = 3 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestMirrorPull(t *testing.T) {
	layer := "compressed layer bytes"
	config := `{"architecture":"amd64","os":"linux"}`
	digest := func(s string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(s))) }
	manifest := fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":%q},"layers":[{"digest":%q}]}`, digest(config), digest(layer))
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, digest(manifest))
	resources := map[string]string{
		"/v2/library/nginx/manifests/latest":              index,
		"/v2/library/nginx/manifests/" + digest(manifest): manifest,
		"/v2/library/nginx/blobs/" + digest(config):       config,
		"/v2/library/nginx/blobs/" + digest(layer):        layer,
	}
	var auth, registry, cdn int
	_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"Cookie", "Proxy-Authorization", "X-Hop", "X-Client-Secret"} {
			if r.Header.Get(h) != "" {
				t.Errorf("%s leaked %s", r.Host, h)
			}
		}
		switch r.Host {
		case "auth.docker.io":
			auth++
			if r.Method != http.MethodGet || r.URL.Path != "/token" || r.URL.Query().Get("service") != "registry.docker.io" || r.URL.Query().Get("scope") != "repository:library/nginx:pull" {
				t.Errorf("invalid token request: %s %s", r.Method, r.URL)
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("client authorization leaked to token endpoint")
			}
			io.WriteString(w, `{"token":"anonymous-pull-token"}`)
		case "registry-1.docker.io":
			registry++
			if r.URL.Query().Has("ns") || r.Header.Get("Authorization") != "Bearer anonymous-pull-token" {
				t.Errorf("invalid registry request: %s auth=%q", r.URL, r.Header.Get("Authorization"))
			}
			if r.Header.Get("Accept") != "application/vnd.oci.image.index.v1+json" {
				t.Error("Accept was not preserved")
			}
			data, ok := resources[r.URL.Path]
			if !ok {
				t.Errorf("unexpected registry path %s", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", digest(data))
			if strings.Contains(r.URL.Path, "/blobs/") && r.Method != http.MethodHead {
				http.Redirect(w, r, "https://production.cloudfront.docker.com"+r.URL.Path+"?signature=a%2Fb%2Bc", http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			if r.Method != http.MethodHead {
				io.WriteString(w, data)
			}
		case "production.cloudfront.docker.com":
			cdn++
			if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "signature=a%2Fb%2Bc" {
				t.Errorf("CDN credentials/query changed: %s", r.URL)
			}
			io.WriteString(w, resources[r.URL.Path])
		default:
			t.Errorf("unexpected host %s", r.Host)
		}
	})
	resp, _ := mirrorRequest(t, server, http.MethodGet, "/v2/")
	if resp.StatusCode != 200 || resp.Header.Get("Docker-Distribution-Api-Version") != "registry/2.0" {
		t.Fatalf("v2 ping status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		for path, want := range resources {
			resp, body := mirrorRequest(t, server, method, path+"?ns=docker.io")
			if resp.StatusCode != 200 {
				t.Fatalf("%s %s returned %d: %s", method, path, resp.StatusCode, body)
			}
			if resp.Header.Get("Docker-Content-Digest") != digest(want) {
				t.Errorf("%s %s lost digest", method, path)
			}
			if method == http.MethodGet && string(body) != want || method == http.MethodHead && len(body) != 0 {
				t.Errorf("%s %s body=%q", method, path, body)
			}
		}
	}
	if auth != 8 || registry != 8 || cdn != 2 {
		t.Errorf("requests auth=%d registry=%d cdn=%d", auth, registry, cdn)
	}
}

func TestMirrorRejectsRequests(t *testing.T) {
	_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("rejected request reached upstream: %s", r.URL)
		w.WriteHeader(500)
	})
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/v2/library/nginx/blobs/uploads/", 405},
		{"PUT", "/v2/library/nginx/manifests/latest", 405},
		{"DELETE", "/v2/library/nginx/manifests/latest", 405},
		{"GET", "/v2/library/nginx/manifests/latest?ns=evil.example", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=docker.io&ns=evil.example", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=%zz", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io&ns=gcr.io", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io.evil.example", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=https://ghcr.io", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=user@ghcr.io", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io:444", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io/path", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io%3Fother=value", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=ghcr.io%23fragment", 400},
		{"GET", "/v2/library/nginx/manifests/latest?ns=127.0.0.1", 400},
		{"GET", "/v2/_catalog", 404},
		{"GET", "/v2/manifests/latest", 404},
		{"GET", "/v2/library/nginx/manifests/", 404},
		{"GET", "/v2/library/nginx/manifests/latest/extra", 404},
		{"GET", "/v2/library/../nginx/manifests/latest", 404},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			resp, body := mirrorRequest(t, server, tc.method, tc.path)
			if resp.StatusCode != tc.status {
				t.Errorf("status=%d want=%d body=%s", resp.StatusCode, tc.status, body)
			}
		})
	}
}

// Reproduces containerd's namespace requests through the real HTTP entry point.
func TestMirrorRegistryPull(t *testing.T) {
	for _, tc := range []struct {
		ns, host, cdn string
		auth          bool
	}{
		{"ghcr.io", "ghcr.io", "pkg-containers.githubusercontent.com", true},
		{"GHCR.IO:443", "ghcr.io", "pkg-containers.githubusercontent.com", true},
		{"gcr.io", "gcr.io", "gcr.io", false},
		{"registry.example", "registry.example", "cdn.example", true},
	} {
		t.Run(tc.ns, func(t *testing.T) {
			tokenHost := tc.host
			if tc.host == "registry.example" {
				tokenHost = "auth.example"
			}
			config, layer := `{"architecture":"amd64","os":"linux"}`, "layer content"
			digest := func(s string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(s))) }
			manifest := fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":%q},"layers":[{"digest":%q}]}`, digest(config), digest(layer))
			resources := map[string]string{
				"/v2/org/image/manifests/latest":        manifest,
				"/v2/org/image/blobs/" + digest(config): config,
				"/v2/org/image/blobs/" + digest(layer):  layer,
			}
			var tokens int
			p, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				for _, h := range []string{"Cookie", "Proxy-Authorization", "X-Hop", "X-Client-Secret"} {
					if r.Header.Get(h) != "" {
						t.Errorf("%s leaked %s", r.Host, h)
					}
				}
				if r.Header.Get("Authorization") == "Bearer client-secret" {
					t.Error("client token leaked")
				}
				if r.Host == tokenHost && r.URL.Path == "/token" {
					tokens++
					if !tc.auth || r.Method != "GET" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("service") != tc.host || r.URL.Query().Get("scope") != "repository:org/image:pull" {
						t.Errorf("invalid token request: %s %s", r.Method, r.URL)
					}
					io.WriteString(w, `{"access_token":"registry-token"}`)
					return
				}
				if r.URL.Path == "/download" && r.Host == tc.cdn {
					if tc.cdn != tc.host && r.Header.Get("Authorization") != "" {
						t.Error("registry token leaked to CDN")
					}
					if r.URL.RawQuery != "signature=a%2Fb%2Bc" {
						t.Errorf("CDN query changed: %s", r.URL)
					}
					io.WriteString(w, layer)
					return
				}
				if r.Host != tc.host || r.URL.Query().Has("ns") || r.URL.Query().Get("extra") != "a/b" {
					t.Errorf("wrong upstream: host=%s url=%s", r.Host, r.URL)
				}
				if tc.auth && r.Header.Get("Authorization") == "" {
					// Parameter order varies; upstream scope must not widen the pull permission.
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer scope="repository:other:pull,push", service=%q, realm="https://%s/token?scope=repository:other:push"`, tc.host, tokenHost))
					w.WriteHeader(401)
					return
				}
				if tc.auth && r.Header.Get("Authorization") != "Bearer registry-token" {
					t.Error("missing registry token")
				}
				if r.Header.Get("Accept") != "application/vnd.oci.image.index.v1+json" {
					t.Error("Accept lost")
				}
				data, ok := resources[r.URL.Path]
				if !ok {
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Docker-Content-Digest", digest(data))
				if data == layer && r.Method == "GET" {
					http.Redirect(w, r, "https://"+tc.cdn+"/download?signature=a%2Fb%2Bc", 307)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				w.Header().Set("Content-Length", fmt.Sprint(len(data)))
				if r.Method == "GET" {
					io.WriteString(w, data)
				}
			})
			p.allowedPatterns = buildAllowedPatterns(&Config{AllowedHosts: []string{"registry.example", "auth.example", "cdn.example"}})
			resp, _ := mirrorRequest(t, server, "GET", "/v2/?ns="+url.QueryEscape(tc.ns))
			if resp.StatusCode != 200 {
				t.Fatalf("ping status=%d", resp.StatusCode)
			}
			for _, method := range []string{"HEAD", "GET"} {
				for path, want := range resources {
					resp, body := mirrorRequest(t, server, method, path+"?ns="+url.QueryEscape(tc.ns)+"&extra=a%2Fb")
					if resp.StatusCode != 200 {
						t.Fatalf("%s %s: status=%d body=%s", method, path, resp.StatusCode, body)
					}
					if resp.Header.Get("Docker-Content-Digest") != digest(want) {
						t.Error("digest lost")
					}
					if method == "GET" && string(body) != want || method == "HEAD" && len(body) != 0 {
						t.Errorf("wrong body %q", body)
					}
					if resp.Header.Get("WWW-Authenticate") != "" || resp.Header.Get("Location") != "" {
						t.Error("upstream endpoint leaked")
					}
				}
			}
			if tc.auth && tokens != 6 || !tc.auth && tokens != 0 {
				t.Errorf("token requests=%d", tokens)
			}
		})
	}
}

func TestMirrorRegistryAuthErrors(t *testing.T) {
	for _, tc := range []struct {
		name, challenge, body       string
		tokenStatus, want, requests int
	}{
		{"basic", `Basic realm="private"`, "", 0, 401, 1},
		{"missing_realm", `Bearer service="ghcr.io"`, "", 0, 502, 1},
		{"http_realm", `Bearer realm="http://ghcr.io/token"`, "", 0, 502, 1},
		{"unknown_realm", `Bearer realm="https://evil.example/token"`, "", 0, 502, 1},
		{"userinfo_realm", `Bearer realm="https://user@ghcr.io/token"`, "", 0, 502, 1},
		{"port_realm", `Bearer realm="https://ghcr.io:444/token"`, "", 0, 502, 1},
		{"duplicate_realm", `Bearer realm="https://ghcr.io/token",realm="https://gcr.io/token"`, "", 0, 502, 1},
		{"empty_token", `Bearer realm="https://ghcr.io/token"`, `{}`, 200, 502, 1},
		{"invalid_json", `Bearer realm="https://ghcr.io/token"`, `{`, 200, 502, 1},
		{"rate_limit", `Bearer realm="https://ghcr.io/token"`, `{"error":"limited"}`, 429, 429, 1},
		{"token_redirect", `Bearer realm="https://ghcr.io/token"`, "", 307, 502, 1},
		{"retry_once", `Bearer realm="https://ghcr.io/token"`, `{"token":"denied"}`, 200, 401, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "ghcr.io" {
					t.Errorf("unexpected upstream %s", r.Host)
				}
				if r.URL.Path == "/token" {
					if tc.tokenStatus == 0 {
						t.Error("unsafe token request reached upstream")
						w.WriteHeader(500)
						return
					}
					w.Header().Set("Location", "https://evil.example/token")
					w.Header().Set("Retry-After", "60")
					w.WriteHeader(tc.tokenStatus)
					io.WriteString(w, tc.body)
					return
				}
				requests++
				w.Header().Set("WWW-Authenticate", tc.challenge)
				w.WriteHeader(401)
			})
			resp, _ := mirrorRequest(t, server, "GET", "/v2/org/image/manifests/latest?ns=ghcr.io")
			if resp.StatusCode != tc.want || requests != tc.requests {
				t.Errorf("status=%d requests=%d, want %d/%d", resp.StatusCode, requests, tc.want, tc.requests)
			}
			if tc.want == 429 && resp.Header.Get("Retry-After") != "60" {
				t.Error("Retry-After lost")
			}
			if resp.Header.Get("WWW-Authenticate") != "" || resp.Header.Get("Location") != "" {
				t.Error("upstream endpoint leaked")
			}
		})
	}
}

func TestMirrorRegistryRedirectCredentials(t *testing.T) {
	for _, target := range []string{
		"https://pkg-containers.githubusercontent.com/blob", "https://evil.example/blob",
		"http://ghcr.io/blob", "https://ghcr.io:444/blob", "https://user@ghcr.io/blob",
		"https://pkg-containers.githubusercontent.com.evil.example/blob",
	} {
		t.Run(target, func(t *testing.T) {
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					io.WriteString(w, `{"token":"anonymous"}`)
					return
				}
				if r.Host == "pkg-containers.githubusercontent.com" {
					if r.Header.Get("Authorization") != "" {
						t.Error("token leaked to CDN")
					}
					http.Redirect(w, r, "https://ghcr.io/returned", 307)
					return
				}
				if r.Host != "ghcr.io" {
					t.Errorf("unsafe host reached: %s", r.Host)
				}
				if r.URL.Path == "/returned" {
					if r.Header.Get("Authorization") != "" {
						t.Error("token restored after cross-host redirect")
					}
					io.WriteString(w, "blob")
					return
				}
				if r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", `Bearer realm="https://ghcr.io/token"`)
					w.WriteHeader(401)
					return
				}
				http.Redirect(w, r, target, 307)
			})
			resp, body := mirrorRequest(t, server, "GET", "/v2/org/image/blobs/test?ns=ghcr.io")
			want := 502
			if target == "https://pkg-containers.githubusercontent.com/blob" {
				want = 200
			}
			if resp.StatusCode != want || want == 200 && string(body) != "blob" {
				t.Errorf("status=%d body=%s", resp.StatusCode, body)
			}
		})
	}
}

func TestMirrorRegistryResponseSemantics(t *testing.T) {
	for _, status := range []int{206, 304, 401, 403, 404, 416, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "gcr.io" || r.Header.Get("Range") != "bytes=1-3" || r.Header.Get("If-Range") != `"etag"` {
					t.Errorf("wrong upstream or lost range: %s %v", r.Host, r.Header)
				}
				w.Header().Set("Content-Range", "bytes 1-3/10")
				w.Header().Set("Retry-After", "60")
				w.Header().Set("Set-Cookie", "upstream=secret")
				w.WriteHeader(status)
			})
			req, err := http.NewRequest("GET", server.URL+"/v2/org/image/blobs/test?ns=gcr.io", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Range", "bytes=1-3")
			req.Header.Set("If-Range", `"etag"`)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != status || resp.Header.Get("Content-Range") != "bytes 1-3/10" || resp.Header.Get("Retry-After") != "60" || resp.Header.Get("Set-Cookie") != "" {
				t.Errorf("changed response: %d %v", resp.StatusCode, resp.Header)
			}
		})
	}
}

func TestMirrorRegistryTimeout(t *testing.T) {
	for _, slowPath := range []string{"/v2/org/image/manifests/latest", "/token"} {
		t.Run(slowPath, func(t *testing.T) {
			canceled := make(chan struct{})
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == slowPath {
					<-r.Context().Done()
					close(canceled)
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://ghcr.io/token"`)
				w.WriteHeader(401)
			})
			globalConfig.Security.RequestTimeout = 50 * time.Millisecond
			resp, _ := mirrorRequest(t, server, "GET", "/v2/org/image/manifests/latest?ns=ghcr.io")
			if resp.StatusCode != 502 {
				t.Fatalf("status=%d", resp.StatusCode)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("upstream was not canceled")
			}
		})
	}
}

func TestMirrorTokenErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		status, want int
	}{
		{"rate_limit", `{"error":"limited"}`, 429, 429},
		{"invalid_json", `{`, 200, 502},
		{"empty_token", `{}`, 200, 502},
		{"oversized_token", `{"token":"` + strings.Repeat("x", 1<<20) + `"}`, 200, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "auth.docker.io" {
					t.Errorf("unexpected host %s", r.Host)
				}
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			resp, _ := mirrorRequest(t, server, "GET", "/v2/library/nginx/manifests/latest")
			if resp.StatusCode != tc.want {
				t.Errorf("status=%d want=%d", resp.StatusCode, tc.want)
			}
			if tc.status == 429 && resp.Header.Get("Retry-After") != "60" {
				t.Error("Retry-After lost")
			}
		})
	}
}

func TestMirrorRedirects(t *testing.T) {
	for _, target := range []string{
		"https://evil.example/blob", "http://production.cloudfront.docker.com/blob",
		"https://production.cloudfront.docker.com:444/blob", "https://user@production.cloudfront.docker.com/blob",
		"https://ghcr.io/blob", "https://production.cloudfront.docker.com.evil.example/blob",
		"https://registry-1.docker.io/v2/library/nginx/blobs/loop",
	} {
		t.Run(target, func(t *testing.T) {
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "auth.docker.io" {
					io.WriteString(w, `{"access_token":"anonymous"}`)
					return
				}
				if r.Host != "registry-1.docker.io" {
					t.Errorf("unsafe redirect reached %s", r.Host)
				}
				http.Redirect(w, r, target, 307)
			})
			resp, _ := mirrorRequest(t, server, "GET", "/v2/library/nginx/blobs/test")
			if resp.StatusCode != 502 {
				t.Errorf("unsafe redirect status=%d", resp.StatusCode)
			}
		})
	}
}

func TestMirrorResponseSemantics(t *testing.T) {
	for _, status := range []int{200, 206, 304, 401, 403, 404, 416, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "auth.docker.io" {
					io.WriteString(w, `{"token":"anonymous"}`)
					return
				}
				if r.Header.Get("Range") != "bytes=1-3" || r.Header.Get("If-Range") != `"etag"` {
					t.Error("Range/If-Range lost")
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.docker.io/token"`)
				w.Header().Set("Content-Range", "bytes 1-3/10")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				if status != 304 {
					io.WriteString(w, "123")
				}
			})
			req, _ := http.NewRequest("GET", server.URL+"/v2/library/nginx/blobs/test", nil)
			req.Header.Set("Range", "bytes=1-3")
			req.Header.Set("If-Range", `"etag"`)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != status || resp.Header.Get("WWW-Authenticate") != "" || resp.Header.Get("Content-Range") != "bytes 1-3/10" {
				t.Errorf("status/headers changed: %d %v", resp.StatusCode, resp.Header)
			}
		})
	}
}

func TestMirrorTimeout(t *testing.T) {
	for _, slowHost := range []string{"auth.docker.io", "registry-1.docker.io", "production.cloudfront.docker.com"} {
		t.Run(slowHost, func(t *testing.T) {
			canceled := make(chan struct{})
			_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == slowHost {
					<-r.Context().Done()
					close(canceled)
					return
				}
				if r.Host == "auth.docker.io" {
					io.WriteString(w, `{"token":"anonymous"}`)
					return
				}
				http.Redirect(w, r, "https://production.cloudfront.docker.com/blob", 307)
			})
			globalConfig.Security.RequestTimeout = 50 * time.Millisecond
			resp, _ := mirrorRequest(t, server, "GET", "/v2/library/nginx/blobs/test")
			if resp.StatusCode != 502 {
				t.Fatalf("timeout status=%d", resp.StatusCode)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("request timeout did not cancel upstream")
			}
		})
	}
}

func TestMirrorNoCache(t *testing.T) {
	var requests int
	_, server := mirrorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.docker.io" {
			io.WriteString(w, `{"token":"anonymous"}`)
			return
		}
		requests++
		io.WriteString(w, "blob")
	})
	for _, ns := range []string{"", "?ns=registry-1.docker.io"} {
		resp, body := mirrorRequest(t, server, "GET", "/v2/library/nginx/blobs/test"+ns)
		if resp.StatusCode != 200 || string(body) != "blob" {
			t.Fatalf("uncached blob status=%d body=%s", resp.StatusCode, body)
		}
	}
	if requests != 2 {
		t.Errorf("upstream requests=%d, want 2", requests)
	}
}
