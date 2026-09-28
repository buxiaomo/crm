package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testProxyHandler(t *testing.T) *ProxyHandler {
	t.Helper()
	oldConfig, oldConcurrent := globalConfig, concurrentReqs
	t.Cleanup(func() { globalConfig, concurrentReqs = oldConfig, oldConcurrent })
	globalConfig = &Config{Security: SecurityConfig{
		MaxRequestSize: 1 << 20, RequestTimeout: time.Second, MaxConcurrentReqs: 10,
	}}
	concurrentReqs = make(chan struct{}, 10)
	p := newProxyHandler([]*regexp.Regexp{regexp.MustCompile(`^127\.0\.0\.1$`)}, nil, false, 0, nil)
	t.Cleanup(p.transport.CloseIdleConnections)
	return p
}

func TestConnectThroughMiddleware(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	p := testProxyHandler(t)
	done := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		logMiddleware(0, p).ServeHTTP(w, r)
	}))
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("CONNECT handler did not exit")
		}
	}()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nping", upstream.Addr(), upstream.Addr())
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT returned %d: %s", resp.StatusCode, b)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("tunnel payload=%q", payload)
	}
}

func TestLiteralAllowedHost(t *testing.T) {
	allowed := buildAllowedPatterns(&Config{AllowedHosts: []string{"docker.io", `^.*\.pkg\.dev$`}})
	for _, host := range []string{"docker.io", "DOCKER.IO:443", "us.pkg.dev", "auth.docker.io", "production.cloudfront.docker.com"} {
		if !isAllowedHost(host, allowed) {
			t.Errorf("rejected allowed host %s", host)
		}
	}
	for _, host := range []string{"docker.io.evil.invalid", "dockerXio.evil.invalid", "notdocker.io"} {
		if isAllowedHost(host, allowed) {
			t.Errorf("unexpectedly allowed %s", host)
		}
	}
}

func TestHTTPTimeout(t *testing.T) {
	p := testProxyHandler(t)
	globalConfig.Security.RequestTimeout = 20 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(100 * time.Millisecond):
			io.WriteString(w, "late response")
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	recorder := httptest.NewRecorder()
	start := time.Now()
	p.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, upstream.URL+"/v2/test", nil))
	if recorder.Code == http.StatusOK {
		t.Fatalf("20ms request timeout ignored: status=200 after %s", time.Since(start))
	}
}

func TestCanceledHTTP(t *testing.T) {
	p := testProxyHandler(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served canceled request")
	}))
	defer upstream.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/v2/test", nil).WithContext(ctx)
	p.ServeHTTP(recorder, req)
	if recorder.Code == http.StatusOK {
		t.Fatal("canceled request still reached upstream and returned 200")
	}
}

func TestValidatePreservesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "important.txt")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Listen: ":8888", SocketPath: path}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected rejection of a non-socket path")
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		t.Fatalf("Validate deleted a regular file (validation error: %v)", err)
	}
}

func TestExpiredCachedCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"registry.example"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CertificateAuthority{caCert: root, caPrivKey: key, certCache: map[string]*tls.Certificate{
		"registry.example": {Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
	}}
	cert, err := ca.GetCertificate("registry.example")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if time.Now().After(parsed.NotAfter) {
		t.Fatalf("expired certificate reused: NotAfter=%s", parsed.NotAfter)
	}
}

func TestUnknownLengthBodyLimit(t *testing.T) {
	p := testProxyHandler(t)
	received := make(chan int64, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received <- n
	}))
	defer upstream.Close()
	payload := strings.Repeat("x", int(globalConfig.Security.MaxRequestSize)+1)
	req := httptest.NewRequest(http.MethodPost, upstream.URL+"/v2/upload", io.NopCloser(strings.NewReader(payload)))
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status=%d, want 413", recorder.Code)
	}
	select {
	case n := <-received:
		if n > globalConfig.Security.MaxRequestSize {
			t.Fatalf("forwarded %d bytes despite %d-byte limit (ContentLength=%d)", n, globalConfig.Security.MaxRequestSize, req.ContentLength)
		}
	default:
	}
}

func TestMITMBodyLimit(t *testing.T) {
	p := testProxyHandler(t)
	globalConfig.Security.MaxRequestSize = 8
	globalConfig.Security.RequestTimeout = 3 * time.Second
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		w.Write(b)
	}))
	defer upstream.Close()
	p.allowedPatterns = []*regexp.Regexp{regexp.MustCompile(`^registry\.example$`)}
	p.mitmAllowed = p.allowedPatterns
	p.mitmEnabled = true
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p.mitmCA = &CertificateAuthority{caCert: root, caPrivKey: key, certCache: make(map[string]*tls.Certificate)}
	p.transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Local test upstream only.
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(upstream.URL, "https://"))
	}
	done := make(chan struct{}, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		logMiddleware(0, p).ServeHTTP(w, r)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, tt := range []struct {
		body    string
		chunked bool
		status  int
	}{
		{"", false, 200}, {"12345678", false, 200},
		{"123456789", true, 413}, {"123456789", false, 413},
	} {
		var body io.Reader = strings.NewReader(tt.body)
		if tt.chunked {
			body = io.NopCloser(body)
		}
		resp, err := client.Post("https://registry.example/v2/upload", "application/octet-stream", body)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tt.status {
			t.Errorf("body=%q chunked=%t: status=%d, want %d", tt.body, tt.chunked, resp.StatusCode, tt.status)
		}
		if tt.status == 200 && string(b) != tt.body {
			t.Errorf("body=%q, want %q", b, tt.body)
		}
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Fatal("MITM handler did not exit")
		}
	}
	// Do not finish the chunked request: rejection must not wait for EOF.
	reader, writer := io.Pipe()
	result := make(chan error, 1)
	go func() {
		resp, err := client.Post("https://registry.example/v2/upload", "application/octet-stream", reader)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 413 {
				err = fmt.Errorf("status=%d, want 413", resp.StatusCode)
			}
		}
		result <- err
	}()
	if _, err := writer.Write([]byte("123456789")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("oversized chunked MITM request waited for EOF")
		writer.Close()
		<-result
	}
	writer.Close()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("MITM handler did not exit")
	}

}

func TestSocketValidationHasNoSideEffects(t *testing.T) {
	path := testSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := &Config{Listen: ":8888", SocketPath: path}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("validation removed active socket: %v", err)
	}
	conn.Close()
	target := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg.SocketPath = link
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted symlink as socket path")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("validation removed symlink: %v", err)
	}
}

func TestListenUnixPreservesActiveSocketAndReplacesStaleSocket(t *testing.T) {
	path := testSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if other, err := listenUnix(path); err == nil {
		other.Close()
		t.Fatal("replaced an active socket")
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("active socket was removed: %v", err)
	}
	conn.Close()
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	listener.Close()
	fresh, err := listenUnix(path)
	if err != nil {
		t.Fatalf("could not replace stale socket: %v", err)
	}
	fresh.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed on close: %v", err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := listenUnix(path); err == nil {
		other.Close()
		t.Fatal("replaced a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keep" {
		t.Fatalf("regular file changed: %q, %v", b, err)
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	// Keep the path below Unix socket limits, including on macOS.
	dir, err := os.MkdirTemp("", "crm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "crm.sock")
}

func TestConnectTimeoutWithBlockedUpstream(t *testing.T) {
	p := testProxyHandler(t)
	globalConfig.Security.RequestTimeout = 100 * time.Millisecond
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			tcp := conn.(*net.TCPConn)
			tcp.SetReadBuffer(1024)
			accepted <- tcp
		}
	}()
	done := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		logMiddleware(0, p).ServeHTTP(w, r)
	}))
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Addr(), upstream.Addr())
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status=%d", resp.StatusCode)
	}
	peer := <-accepted
	defer func() {
		peer.Close()
		conn.Close()
		<-done
	}()
	sending := make(chan struct{})
	go func() {
		defer close(sending)
		io.Copy(conn, strings.NewReader(strings.Repeat("x", 8<<20)))
	}()
	defer func() { conn.Close(); <-sending }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CONNECT stayed open past timeout with upstream write blocked")
	}
}

func TestHTTPBodyLimitDoesNotWaitForEOF(t *testing.T) {
	p := testProxyHandler(t)
	globalConfig.Security.MaxRequestSize = 8
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(logMiddleware(0, p))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	reader, writer := io.Pipe()
	defer writer.Close()
	result := make(chan error, 1)
	go func() {
		resp, err := client.Post(upstream.URL+"/v2/upload", "application/octet-stream", reader)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 413 {
				err = fmt.Errorf("status=%d, want 413", resp.StatusCode)
			}
		}
		result <- err
	}()
	if _, err := writer.Write([]byte("123456789")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("oversized HTTP body waited for EOF")
		writer.Close()
		<-result
	}
}
