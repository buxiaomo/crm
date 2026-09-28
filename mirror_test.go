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
