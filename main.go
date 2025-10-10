package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"encoding/json"

	yaml "gopkg.in/yaml.v3"
)

// defaultAllowedHosts lists registries allowed to proxy.
var defaultAllowedHosts = []string{
	"docker.io",
	"registry-1.docker.io",
	"gcr.io",
	"k8s.io",
	"registry.k8s.io",
	"docker.elastic.co",
	"ghcr.io",
}

type Config struct {
	Listen       string   `yaml:"listen" json:"listen"`
	AllowedHosts []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	InsecureTLS  bool     `yaml:"insecure_tls" json:"insecure_tls"`
	LogLevel     string   `yaml:"log_level" json:"log_level"`
}

// LogLevel controls logging granularity
type LogLevel int

const (
	LevelInfo LogLevel = iota + 1
	LevelDebug
)

// loadConfigAuto loads configuration from the current directory.
// It prefers YAML (config.yaml/config.yml), and falls back to JSON (config.json).
// If no config file is found, returns an error.
func loadConfigAuto() (*Config, error) {
	// Prefer YAML
	candidates := []string{"config.yaml", "config.yml", "config.json"}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		return nil, fmt.Errorf("no config file found; expected one of: %v", candidates)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	switch {
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML %s: %w", path, err)
		}
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file extension: %s", path)
	}
	return &cfg, nil
}

// loadConfigFrom loads configuration from a specific file path.
func loadConfigFrom(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	switch {
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML %s: %w", path, err)
		}
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file extension: %s", path)
	}
	return &cfg, nil
}

// resolveLogLevel determines logging level based on config.
// Supported levels: info, debug. Defaults to info.
func resolveLogLevel(cfg *Config) LogLevel {
	if cfg == nil {
		return LevelInfo
	}
	lvl := strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	switch lvl {
	case "", "info":
		return LevelInfo
	case "debug":
		return LevelDebug
	default:
		log.Printf("unknown log_level '%s', falling back to 'info'", lvl)
		return LevelInfo
	}
}

// buildAllowedPatterns compiles allowed host patterns (case-insensitive).
// Entries without regex metacharacters are treated as exact literals.
func buildAllowedPatterns(cfg *Config) []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(defaultAllowedHosts))
	// add defaults as exact matches
	for _, h := range defaultAllowedHosts {
		esc := regexp.QuoteMeta(h)
		re := regexp.MustCompile("(?i)^" + esc + "$")
		patterns = append(patterns, re)
	}
	if cfg != nil {
		for _, pat := range cfg.AllowedHosts {
			s := strings.TrimSpace(pat)
			if s == "" {
				continue
			}
			// detect regex metacharacters
			if strings.ContainsAny(s, ".[+*?^$(){}|\\]") {
				// treat as user-supplied regex; make it case-insensitive
				s = "(?i)" + s
			} else {
				// treat as literal exact hostname
				s = "(?i)^" + regexp.QuoteMeta(s) + "$"
			}
			re, err := regexp.Compile(s)
			if err != nil {
				log.Printf("invalid allowed_hosts pattern '%s': %v (skipped)", pat, err)
				continue
			}
			patterns = append(patterns, re)
		}
	}
	return patterns
}

func isAllowedHost(host string, patterns []*regexp.Regexp) bool {
	// strip port if present
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	for _, re := range patterns {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// ProxyHandler implements a simple forward proxy without caching.
type ProxyHandler struct {
	allowedPatterns []*regexp.Regexp
	allowedDisplay  []string
	transport       *http.Transport
	level           LogLevel
}

func newProxyHandler(allowed []*regexp.Regexp, display []string, insecureTLS bool, level LogLevel) *ProxyHandler {
	tr := &http.Transport{
		Proxy:                 nil, // do not chain proxies by default
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// No caching; Go's transport does not cache by default.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
	}
	return &ProxyHandler{allowedPatterns: allowed, allowedDisplay: display, transport: tr, level: level}
}

var reqSeq uint64

func nextReqID() string {
	id := atomic.AddUint64(&reqSeq, 1)
	return fmt.Sprintf("%08x", id)
}

type writeCounter struct {
	w http.ResponseWriter
	n int64
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n, err := wc.w.Write(p)
	wc.n += int64(n)
	return n, err
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := nextReqID()
	clientAddr := r.RemoteAddr
	if i := strings.LastIndex(clientAddr, ":"); i != -1 {
		clientAddr = clientAddr[:i]
	}
	// Health check
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	// Index page: show supported registries and usage
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		p.serveIndex(w, r)
		return
	}

	// Handle CONNECT for HTTPS tunneling
	if r.Method == http.MethodConnect {
		if p.level >= LevelInfo {
			log.Printf("[req %s] CONNECT start host=%s client=%s ua=%s", reqID, r.Host, clientAddr, r.Header.Get("User-Agent"))
		}
		p.handleConnect(w, r, reqID, clientAddr, start)
		return
	}

	// For normal HTTP proxying, ensure URL is absolute
	if !r.URL.IsAbs() {
		http.Error(w, "proxy requires absolute URL", http.StatusBadRequest)
		return
	}

	// Validate host
	if !isAllowedHost(r.URL.Hostname(), p.allowedPatterns) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	if p.level >= LevelInfo {
		authPresent := "false"
		if r.Header.Get("Authorization") != "" {
			authPresent = "true"
		}
		log.Printf("[req %s] HTTP start method=%s url=%s host=%s client=%s ua=%s accept=%s content-type=%s auth=%s", reqID, r.Method, r.URL.String(), r.URL.Host, clientAddr, r.Header.Get("User-Agent"), r.Header.Get("Accept"), r.Header.Get("Content-Type"), authPresent)
	}

	if p.level >= LevelDebug {
		// 打印入站请求头部（完整）
		log.Printf("[req %s] HTTP request headers:", reqID)
		for k, vs := range r.Header {
			for _, v := range vs {
				log.Printf("[req %s] > %s: %s", reqID, k, v)
			}
		}
	}

	// Create outbound request
	outReq := r.Clone(context.Background())
	// Remove proxy headers that should not be forwarded
	outReq.RequestURI = ""
	outReq.Host = r.URL.Host
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	// 在 Debug 模式下附加 httptrace 以观察传输阶段
	if p.level >= LevelDebug {
		trace := &httptrace.ClientTrace{
			DNSStart: func(info httptrace.DNSStartInfo) {
				log.Printf("[req %s] trace dns start: %s", reqID, info.Host)
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				if info.Err != nil {
					log.Printf("[req %s] trace dns error: %v", reqID, info.Err)
				} else {
					addrs := make([]string, 0, len(info.Addrs))
					for _, a := range info.Addrs {
						addrs = append(addrs, a.String())
					}
					log.Printf("[req %s] trace dns done addrs=%v", reqID, addrs)
				}
			},
			ConnectStart: func(network, addr string) { log.Printf("[req %s] trace connect start: %s %s", reqID, network, addr) },
			ConnectDone: func(network, addr string, err error) {
				if err != nil {
					log.Printf("[req %s] trace connect error: %s %s %v", reqID, network, addr, err)
				} else {
					log.Printf("[req %s] trace connect done: %s %s", reqID, network, addr)
				}
			},
			TLSHandshakeStart: func() { log.Printf("[req %s] trace tls handshake start", reqID) },
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				if err != nil {
					log.Printf("[req %s] trace tls error: %v", reqID, err)
				} else {
					log.Printf("[req %s] trace tls done version=%x cipher=%x", reqID, state.Version, state.CipherSuite)
				}
			},
			GotConn: func(info httptrace.GotConnInfo) {
				log.Printf("[req %s] trace got conn reused=%t idle=%t", reqID, info.Reused, info.WasIdle)
			},
			GotFirstResponseByte: func() { log.Printf("[req %s] trace first response byte", reqID) },
		}
		outCtx := httptrace.WithClientTrace(outReq.Context(), trace)
		outReq = outReq.WithContext(outCtx)
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy status and headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream body without buffering (no caching)
	wc := &writeCounter{w: w}
	if _, err := io.Copy(wc, resp.Body); err != nil {
		// client disconnected or write error; log and ignore
		log.Printf("stream error: %v", err)
	}

	dur := time.Since(start)
	if p.level >= LevelDebug {
		// 打印上游响应头部（完整）
		log.Printf("[req %s] HTTP response headers status=%d:", reqID, resp.StatusCode)
		for k, vs := range resp.Header {
			for _, v := range vs {
				log.Printf("[req %s] < %s: %s", reqID, k, v)
			}
		}
	}
	if p.level >= LevelInfo {
		cl := resp.Header.Get("Content-Length")
		if cl == "" {
			cl = "unknown"
		}
		log.Printf("[req %s] HTTP done status=%d bytes_sent=%d content-length=%s duration=%s", reqID, resp.StatusCode, wc.n, cl, dur)
	} else {
		log.Printf("%s %s -> %d in %s", r.Method, r.URL.String(), resp.StatusCode, dur)
	}
}

// serveIndex renders a simple HTML page with allowed registries and usage.
func (p *ProxyHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="utf-8"><title>Container Registry Mirrors</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px;max-width:920px;margin:auto;color:#222}
h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;margin:24px 0 8px}code,pre{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:2px 6px}
ul{padding-left:20px}footer{margin-top:32px;color:#666;font-size:12px}
.muted{color:#666;font-size:13px}
</style></head><body>
<h1>Container Registry Mirrors</h1>
<p class="muted">一个无缓存的前向代理，专为容器镜像 registry 中转：支持 HTTP 代理与 HTTPS CONNECT 隧道。可限制允许的主机。</p>

<h2>支持的仓库地址</h2>
<ul>`)
	// list displays
	shown := make(map[string]struct{})
	for _, h := range p.allowedDisplay {
		s := strings.TrimSpace(h)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := shown[key]; ok {
			continue
		}
		shown[key] = struct{}{}
		fmt.Fprintf(w, "<li><code>%s</code></li>\n", s)
	}
	fmt.Fprint(w, `</ul>

<h2>使用方式（加速器风格）</h2>
<p>将本服务作为镜像加速器或代理：</p>
<ul>
  <li><b>Docker 守护进程（仅 docker.io/registry-1.docker.io）：</b>
    在 <code>/etc/docker/daemon.json</code> 设置：
    <pre>{
  "registry-mirrors": ["https://mirrors.xiaomo.site"]
}</pre>
  </li>

  <li><b>Containerd：</b>
    在 <code>/etc/containerd/config.toml</code> 设置：
    <pre>[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".registry]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."gcr.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.elastic.co"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."ghcr.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."k8s.gcr.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."mcr.microsoft.com"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."nvcr.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."quay.io"]
          endpoint = [ "https://mirrors.xiaomo.site" ]</pre>
  </li>
</ul>

<footer>若需在 HTTPS 下查看详细请求信息，请启用调试用 MITM 模式（默认未开启）。</footer>
</body></html>`)
}

func (p *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request, reqID string, clientAddr string, start time.Time) {
	host := r.Host
	if !isAllowedHost(host, p.allowedPatterns) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	// Establish TCP connection to upstream
	upstream, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("dial upstream failed: %v", err), http.StatusBadGateway)
		return
	}

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		upstream.Close()
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		upstream.Close()
		return
	}

	// Send 200 Connection Established
	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := clientBuf.Flush(); err != nil {
		clientConn.Close()
		upstream.Close()
		return
	}

	// Bidirectional copy with byte counting
	up2cl, cl2up := tunnelCopy(clientConn, upstream)
	dur := time.Since(start)
	if p.level >= LevelInfo {
		log.Printf("[req %s] CONNECT done host=%s client=%s bytes_upstream_to_client=%d bytes_client_to_upstream=%d duration=%s", reqID, host, clientAddr, up2cl, cl2up, dur)
	} else {
		log.Printf("CONNECT %s -> done in %s", host, dur)
	}
}

func tunnelCopy(client net.Conn, upstream net.Conn) (upstreamToClient int64, clientToUpstream int64) {
	done := make(chan struct{}, 2)
	var n1, n2 int64
	go func() {
		n, _ := io.Copy(client, upstream)
		n1 = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(upstream, client)
		n2 = n
		done <- struct{}{}
	}()
	// Wait for one side to finish then close both to unblock the other
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
	return n1, n2
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to config file (yaml/yml/json)")
	flag.StringVar(&cfgPath, "c", "", "alias of -config")
	flag.Parse()

	var cfg *Config
	var err error
	if cfgPath != "" {
		cfg, err = loadConfigFrom(cfgPath)
	} else {
		cfg, err = loadConfigAuto()
	}
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	level := resolveLogLevel(cfg)
	if level >= LevelDebug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	listenAddr := ":8080"
	if cfg != nil && cfg.Listen != "" {
		listenAddr = cfg.Listen
	}

	allowed := buildAllowedPatterns(cfg)
	insecure := false
	if cfg != nil {
		insecure = cfg.InsecureTLS
	}

	// build display list: defaults + user config
	display := make([]string, 0, len(defaultAllowedHosts))
	display = append(display, defaultAllowedHosts...)
	if cfg != nil && len(cfg.AllowedHosts) > 0 {
		display = append(display, cfg.AllowedHosts...)
	}

	handler := newProxyHandler(allowed, display, insecure, level)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: logMiddleware(level, handler),
	}

	log.Printf("registry forward proxy listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func logMiddleware(level LogLevel, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 基础访问日志：遵循统一的日志级别
		if level >= LevelInfo {
			ua := r.Header.Get("User-Agent")
			log.Printf("%s %s UA=%s", r.Method, r.URL.String(), ua)
		}
		next.ServeHTTP(w, r)
	})
}
