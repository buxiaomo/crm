package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"encoding/json"

	yaml "gopkg.in/yaml.v3"
)

// 缓冲池用于优化内存分配
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024) // 32KB buffer
	},
}

// 安全配置常量
// 常量已移动到配置文件中，通过 SecurityConfig 进行配置

// 并发控制
var concurrentReqs chan struct{}

// 全局配置
var globalConfig *Config

// 指标统计
type Metrics struct {
	TotalRequests     int64
	ActiveConnections int64
	TotalBytes        int64
	ErrorCount        int64
	StartTime         time.Time
}

var metrics = &Metrics{
	StartTime: time.Now(),
}

// sanitizeUserAgent 对User-Agent进行脱敏处理
func sanitizeUserAgent(ua string) string {
	if len(ua) > 100 {
		return ua[:100] + "..."
	}
	// 移除可能的敏感信息（如版本号等）
	if strings.Contains(ua, "Docker") {
		return "Docker/***"
	}
	if strings.Contains(ua, "containerd") {
		return "containerd/***"
	}
	return ua
}

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
	Listen       string         `yaml:"listen" json:"listen"`
	AllowedHosts []string       `yaml:"allowed_hosts" json:"allowed_hosts"`
	InsecureTLS  bool           `yaml:"insecure_tls" json:"insecure_tls"`
	LogLevel     string         `yaml:"log_level" json:"log_level"`
	MITM         MITMConfig     `yaml:"mitm" json:"mitm"`
	Security     SecurityConfig `yaml:"security" json:"security"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	MaxRequestSize    int64         `yaml:"max_request_size" json:"max_request_size"`       // 最大请求大小（字节）
	MaxHeaderSize     int64         `yaml:"max_header_size" json:"max_header_size"`         // 最大请求头大小（字节）
	RequestTimeout    time.Duration `yaml:"request_timeout" json:"request_timeout"`         // 请求超时时间
	MaxConcurrentReqs int           `yaml:"max_concurrent_reqs" json:"max_concurrent_reqs"` // 最大并发请求数
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address cannot be empty")
	}

	// 验证监听地址格式
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("invalid listen address format: %v", err)
	}

	// 验证日志级别
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if c.LogLevel != "" && !validLevels[c.LogLevel] {
		return fmt.Errorf("invalid log level: %s, must be one of: debug, info, warn, error", c.LogLevel)
	}

	// 验证允许的主机列表
	if len(c.AllowedHosts) == 0 {
		log.Println("Warning: no allowed hosts specified, using defaults")
	}

	// 设置安全配置默认值
	if c.Security.MaxRequestSize == 0 {
		c.Security.MaxRequestSize = 10 * 1024 * 1024 * 1024 // 10GB 默认最大请求大小
	}
	if c.Security.MaxHeaderSize == 0 {
		c.Security.MaxHeaderSize = 1024 * 1024 // 1MB 默认最大请求头大小
	}
	if c.Security.RequestTimeout == 0 {
		c.Security.RequestTimeout = 30 * time.Minute // 30分钟默认请求超时
	}
	if c.Security.MaxConcurrentReqs == 0 {
		c.Security.MaxConcurrentReqs = 1000 // 1000 默认最大并发请求数
	}

	// 验证安全配置范围
	if c.Security.MaxRequestSize < 1024*1024 { // 最小1MB
		return fmt.Errorf("max_request_size must be at least 1MB")
	}
	if c.Security.MaxHeaderSize < 1024 { // 最小1KB
		return fmt.Errorf("max_header_size must be at least 1KB")
	}
	if c.Security.RequestTimeout < time.Minute { // 最小1分钟
		return fmt.Errorf("request_timeout must be at least 1 minute")
	}
	if c.Security.MaxConcurrentReqs < 1 {
		return fmt.Errorf("max_concurrent_reqs must be at least 1")
	}

	return nil
}

// ErrorResponse represents a structured error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// sendErrorResponse sends a structured error response
func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Code:    statusCode,
		Message: message,
	}

	// 简单的JSON编码，避免引入额外依赖
	fmt.Fprintf(w, `{"error":"%s","code":%d,"message":"%s"}`,
		response.Error, response.Code, response.Message)
}

// MITMConfig 控制中间人模式的配置
type MITMConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`           // 是否启用 MITM 模式
	CACertPath string `yaml:"ca_cert_path" json:"ca_cert_path"` // CA 证书路径
	CAKeyPath  string `yaml:"ca_key_path" json:"ca_key_path"`   // CA 私钥路径
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

// CertificateAuthority 管理 CA 证书和签发动态证书
// 用于 MITM 模式下动态生成和缓存 TLS 证书
type CertificateAuthority struct {
	caCert     *x509.Certificate           // CA 根证书
	caPrivKey  *rsa.PrivateKey             // CA 私钥
	certCache  map[string]*tls.Certificate // 主机名到证书的缓存映射
	cacheMutex sync.RWMutex                // 保护证书缓存的互斥锁
}

// loadCA 从指定路径加载 CA 证书和私钥
// certPath: CA 证书文件路径
// keyPath: CA 私钥文件路径
// 返回初始化的 CertificateAuthority 和可能的错误
func loadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	// 读取 CA 证书
	caCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("解析 CA 证书 PEM 失败")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}

	// 读取 CA 私钥
	caKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 私钥失败: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("解析 CA 私钥 PEM 失败")
	}

	// 尝试解析私钥（支持 PKCS1 和 PKCS8 格式）
	var caPrivKey *rsa.PrivateKey
	if caPrivKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes); err != nil {
		// 如果 PKCS1 解析失败，尝试 PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 CA 私钥失败: %w", err)
		}

		// 转换为 RSA 私钥
		var ok bool
		caPrivKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA 私钥不是 RSA 类型")
		}
	}

	return &CertificateAuthority{
		caCert:    caCert,
		caPrivKey: caPrivKey,
		certCache: make(map[string]*tls.Certificate),
	}, nil
}

// 为指定域名签发证书
func (ca *CertificateAuthority) GetCertificate(hostname string) (*tls.Certificate, error) {
	// 检查缓存
	ca.cacheMutex.RLock()
	if cert, ok := ca.certCache[hostname]; ok {
		ca.cacheMutex.RUnlock()
		return cert, nil
	}
	ca.cacheMutex.RUnlock()

	// 生成新证书
	ca.cacheMutex.Lock()
	defer ca.cacheMutex.Unlock()

	// 再次检查缓存（避免并发生成）
	if cert, ok := ca.certCache[hostname]; ok {
		return cert, nil
	}

	// 生成私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w", err)
	}

	// 准备证书模板
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// 使用 CA 签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.caCert, &privKey.PublicKey, ca.caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	// 创建 tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	// 存入缓存
	ca.certCache[hostname] = cert
	return cert, nil
}

// ProxyHandler implements a simple forward proxy without caching.
type ProxyHandler struct {
	allowedPatterns []*regexp.Regexp
	allowedDisplay  []string
	transport       *http.Transport
	level           LogLevel

	// MITM 相关
	mitmEnabled bool
	mitmCA      *CertificateAuthority
	mitmAllowed []*regexp.Regexp
}

func newProxyHandler(allowed []*regexp.Regexp, display []string, insecureTLS bool, level LogLevel, cfg *Config) *ProxyHandler {
	tr := &http.Transport{
		Proxy:                 nil, // do not chain proxies by default
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,               // 增加最大空闲连接数
		MaxIdleConnsPerHost:   50,                // 每个主机的最大空闲连接数
		MaxConnsPerHost:       100,               // 每个主机的最大连接数
		IdleConnTimeout:       120 * time.Second, // 延长空闲连接超时
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, // 添加响应头超时
		// No caching; Go's transport does not cache by default.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
	}

	handler := &ProxyHandler{
		allowedPatterns: allowed,
		allowedDisplay:  display,
		transport:       tr,
		level:           level,
		mitmEnabled:     false,
	}

	// 如果配置了 MITM 模式，加载 CA 证书
	if cfg != nil && cfg.MITM.Enabled && cfg.MITM.CACertPath != "" && cfg.MITM.CAKeyPath != "" {
		ca, err := loadCA(cfg.MITM.CACertPath, cfg.MITM.CAKeyPath)
		if err != nil {
			log.Printf("MITM 模式初始化失败: %v", err)
		} else {
			handler.mitmEnabled = true
			handler.mitmCA = ca

			// 使用全局允许的主机模式
			handler.mitmAllowed = allowed
			log.Printf("MITM 模式已启用，允许 %d 个主机模式", len(allowed))
		}
	}

	return handler
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
	// 增加请求计数
	atomic.AddInt64(&metrics.TotalRequests, 1)
	atomic.AddInt64(&metrics.ActiveConnections, 1)
	defer atomic.AddInt64(&metrics.ActiveConnections, -1)

	// 并发控制
	select {
	case concurrentReqs <- struct{}{}:
		defer func() { <-concurrentReqs }()
	default:
		atomic.AddInt64(&metrics.ErrorCount, 1)
		http.Error(w, "服务器繁忙，请稍后重试", http.StatusTooManyRequests)
		return
	}

	// 请求大小限制
	if r.ContentLength > globalConfig.Security.MaxRequestSize {
		atomic.AddInt64(&metrics.ErrorCount, 1)
		http.Error(w, "请求体过大", http.StatusRequestEntityTooLarge)
		return
	}

	// 设置请求超时
	ctx, cancel := context.WithTimeout(r.Context(), globalConfig.Security.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	start := time.Now()
	reqID := nextReqID()
	clientAddr := r.RemoteAddr
	if i := strings.LastIndex(clientAddr, ":"); i != -1 {
		clientAddr = clientAddr[:i]
	}

	// Health check
	if r.URL.Path == "/healthz" {
		p.serveHealthCheck(w, r)
		return
	}

	// Metrics endpoint
	if r.URL.Path == "/metrics" {
		p.serveMetrics(w, r)
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
			// 日志脱敏：隐藏敏感的User-Agent信息
			ua := sanitizeUserAgent(r.Header.Get("User-Agent"))
			log.Printf("[req %s] CONNECT start host=%s client=%s ua=%s", reqID, r.Host, clientAddr, ua)
		}
		p.handleConnect(w, r, reqID, clientAddr, start)
		return
	}

	// For normal HTTP proxying, ensure URL is absolute
	if !r.URL.IsAbs() {
		atomic.AddInt64(&metrics.ErrorCount, 1)
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
	// 统计传输字节数
	atomic.AddInt64(&metrics.TotalBytes, wc.n)

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

// serveMetrics serves basic metrics in plain text format
func (p *ProxyHandler) serveMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	uptime := time.Since(metrics.StartTime)
	fmt.Fprintf(w, "# HELP total_requests Total number of requests\n")
	fmt.Fprintf(w, "# TYPE total_requests counter\n")
	fmt.Fprintf(w, "total_requests %d\n", atomic.LoadInt64(&metrics.TotalRequests))
	fmt.Fprintf(w, "# HELP active_connections Current active connections\n")
	fmt.Fprintf(w, "# TYPE active_connections gauge\n")
	fmt.Fprintf(w, "active_connections %d\n", atomic.LoadInt64(&metrics.ActiveConnections))
	fmt.Fprintf(w, "# HELP total_bytes Total bytes transferred\n")
	fmt.Fprintf(w, "# TYPE total_bytes counter\n")
	fmt.Fprintf(w, "total_bytes %d\n", atomic.LoadInt64(&metrics.TotalBytes))
	fmt.Fprintf(w, "# HELP error_count Total error count\n")
	fmt.Fprintf(w, "# TYPE error_count counter\n")
	fmt.Fprintf(w, "error_count %d\n", atomic.LoadInt64(&metrics.ErrorCount))
	fmt.Fprintf(w, "# HELP uptime_seconds Server uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE uptime_seconds gauge\n")
	fmt.Fprintf(w, "uptime_seconds %.0f\n", uptime.Seconds())
}

// serveHealthCheck provides enhanced health check with system status
func (p *ProxyHandler) serveHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 检查系统状态
	activeConns := atomic.LoadInt64(&metrics.ActiveConnections)
	errorRate := float64(atomic.LoadInt64(&metrics.ErrorCount)) / float64(atomic.LoadInt64(&metrics.TotalRequests)+1) * 100

	status := "healthy"
	statusCode := http.StatusOK

	// 健康检查逻辑
	if activeConns > int64(globalConfig.Security.MaxConcurrentReqs)*8/10 { // 80%阈值
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}
	if errorRate > 10 { // 错误率超过10%
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{
		"status": "%s",
		"timestamp": "%s",
		"uptime": "%.0fs",
		"active_connections": %d,
		"total_requests": %d,
		"error_rate": "%.2f%%"
	}`, status, time.Now().Format(time.RFC3339), time.Since(metrics.StartTime).Seconds(),
		activeConns, atomic.LoadInt64(&metrics.TotalRequests), errorRate)
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

<footer>
若需在 HTTPS 下查看详细请求信息，请启用调试用 MITM 模式（默认未开启）。<br>
项目地址：<a href="https://github.com/buxiaomo/crm.git" target="_blank">https://github.com/buxiaomo/crm.git</a>
</footer>
</body></html>`)
}

func (p *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request, reqID string, clientAddr string, start time.Time) {
	host := r.Host
	if !isAllowedHost(host, p.allowedPatterns) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		log.Printf("[req %s] 拒绝连接到非允许主机: %s", reqID, host)
		return
	}

	// 检查是否启用 MITM 模式且该主机允许 MITM
	if p.mitmEnabled && p.mitmCA != nil && isAllowedHost(host, p.mitmAllowed) {
		if p.level >= LevelDebug {
			log.Printf("[req %s] MITM 模式处理 CONNECT 请求: %s", reqID, host)
		}
		p.handleMITMConnect(w, r, reqID, clientAddr, start)
		return
	}

	// 标准 CONNECT 处理（透明隧道）
	upstream, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("dial upstream failed: %v", err)
		http.Error(w, errMsg, http.StatusBadGateway)
		log.Printf("[req %s] 连接上游失败: %s, 错误: %v", reqID, host, err)
		return
	}
	defer upstream.Close() // 确保连接关闭

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		log.Printf("[req %s] 不支持连接劫持", reqID)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		log.Printf("[req %s] 连接劫持失败: %v", reqID, err)
		return
	}
	defer clientConn.Close() // 确保连接关闭

	// Send 200 Connection Established
	if _, err := clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[req %s] 发送连接建立响应失败: %v", reqID, err)
		return
	}

	if err := clientBuf.Flush(); err != nil {
		log.Printf("[req %s] 刷新缓冲区失败: %v", reqID, err)
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

// handleMITMConnect 处理 MITM 模式下的 CONNECT 请求
// 实现中间人模式，解密 HTTPS 流量并转发
func (p *ProxyHandler) handleMITMConnect(w http.ResponseWriter, r *http.Request, reqID string, clientAddr string, start time.Time) {
	host := r.Host

	// 为目标主机生成证书
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	cert, err := p.mitmCA.GetCertificate(hostname)
	if err != nil {
		log.Printf("[req %s] 为 %s 生成证书失败: %v", reqID, hostname, err)
		http.Error(w, "证书生成失败", http.StatusInternalServerError)
		return
	}

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[req %s] 不支持连接劫持", reqID)
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[req %s] 连接劫持失败: %v", reqID, err)
		http.Error(w, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close() // 确保连接关闭

	// Send 200 Connection Established
	if _, err := clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[req %s] 发送连接建立响应失败: %v", reqID, err)
		return
	}

	if err := clientBuf.Flush(); err != nil {
		log.Printf("[req %s] 刷新缓冲区失败: %v", reqID, err)
		return
	}

	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// 将连接升级为 TLS
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[req %s] TLS 握手失败: %v", reqID, err)
		tlsConn.Close()
		return
	}

	// 创建 HTTP 服务器处理解密后的请求
	connReader := bufio.NewReader(tlsConn)
	connWriter := bufio.NewWriter(tlsConn)

	// 处理来自客户端的 HTTP 请求
	for {
		// 设置读取超时
		if err := tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			break
		}

		// 读取请求
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[req %s] 读取 MITM 请求失败: %v", reqID, err)
			}
			break
		}

		// 修改请求以发送到上游
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.RequestURI = ""

		// 记录请求信息
		if p.level >= LevelInfo {
			authPresent := "false"
			if req.Header.Get("Authorization") != "" {
				authPresent = "true"
			}
			log.Printf("[req %s] MITM HTTP start method=%s url=%s host=%s client=%s ua=%s accept=%s content-type=%s auth=%s",
				reqID, req.Method, req.URL.String(), req.URL.Host, clientAddr,
				req.Header.Get("User-Agent"), req.Header.Get("Accept"),
				req.Header.Get("Content-Type"), authPresent)
		}

		if p.level >= LevelDebug {
			// 打印请求头部
			log.Printf("[req %s] MITM HTTP request headers:", reqID)
			for k, vs := range req.Header {
				for _, v := range vs {
					log.Printf("[req %s] > %s: %s", reqID, k, v)
				}
			}
		}

		// 发送请求到上游
		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			log.Printf("[req %s] MITM 上游请求失败: %v", reqID, err)

			// 向客户端返回错误
			errResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("upstream error: %v", err))),
				Request:    req,
			}
			errResp.Header.Set("Content-Type", "text/plain")
			errResp.Header.Set("Connection", "close")

			if err := errResp.Write(connWriter); err != nil {
				log.Printf("[req %s] 写入错误响应失败: %v", reqID, err)
			}
			if err := connWriter.Flush(); err != nil {
				log.Printf("[req %s] 刷新错误响应失败: %v", reqID, err)
			}
			break
		}

		// 记录响应信息
		if p.level >= LevelDebug {
			log.Printf("[req %s] MITM HTTP response headers status=%d:", reqID, resp.StatusCode)
			for k, vs := range resp.Header {
				for _, v := range vs {
					log.Printf("[req %s] < %s: %s", reqID, k, v)
				}
			}
		}

		// 将响应写回客户端
		resp.Header.Set("Connection", "keep-alive") // 保持连接
		if err := resp.Write(connWriter); err != nil {
			log.Printf("[req %s] 写入响应失败: %v", reqID, err)
			break
		}
		if err := connWriter.Flush(); err != nil {
			log.Printf("[req %s] 刷新响应失败: %v", reqID, err)
			break
		}

		// 关闭响应体
		resp.Body.Close()

		// 检查是否需要关闭连接
		if resp.Header.Get("Connection") == "close" {
			break
		}
	}

	// 关闭连接
	tlsConn.Close()

	dur := time.Since(start)
	if p.level >= LevelInfo {
		log.Printf("[req %s] MITM CONNECT done host=%s client=%s duration=%s", reqID, host, clientAddr, dur)
	} else {
		log.Printf("MITM CONNECT %s -> done in %s", host, dur)
	}
}

func tunnelCopy(client net.Conn, upstream net.Conn) (upstreamToClient int64, clientToUpstream int64) {
	done := make(chan struct{}, 2)
	var n1, n2 int64

	// 优化的复制函数，使用缓冲池
	copyWithBuffer := func(dst net.Conn, src net.Conn) int64 {
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)

		n, _ := io.CopyBuffer(dst, src, buffer)
		// 统计传输字节数
		atomic.AddInt64(&metrics.TotalBytes, n)
		return n
	}

	go func() {
		n1 = copyWithBuffer(client, upstream)
		done <- struct{}{}
	}()
	go func() {
		n2 = copyWithBuffer(upstream, client)
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
	// 解析命令行参数
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to config file (yaml/yml/json)")
	flag.StringVar(&cfgPath, "c", "", "alias of -config")
	flag.Parse()

	// 加载配置文件
	var cfg *Config
	var err error
	if cfgPath != "" {
		cfg, err = loadConfigFrom(cfgPath)
		if err != nil {
			log.Fatalf("无法从指定路径加载配置: %v", err)
		}
	} else {
		cfg, err = loadConfigAuto()
		if err != nil {
			log.Fatalf("无法自动加载配置: %v", err)
		}
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置验证失败: %v", err)
	}

	// 初始化全局配置和并发控制
	globalConfig = cfg
	concurrentReqs = make(chan struct{}, cfg.Security.MaxConcurrentReqs)

	// 设置日志级别
	level := resolveLogLevel(cfg)
	if level >= LevelDebug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Printf("调试模式已启用")
	} else {
		log.SetFlags(log.LstdFlags)
	}

	// 设置监听地址
	listenAddr := ":8080"
	if cfg != nil && cfg.Listen != "" {
		listenAddr = cfg.Listen
	}
	log.Printf("将使用监听地址: %s", listenAddr)

	// 构建允许的主机模式
	allowed := buildAllowedPatterns(cfg)
	log.Printf("已配置 %d 个允许的主机模式", len(allowed))

	// 设置 TLS 安全选项
	insecure := false
	if cfg != nil {
		insecure = cfg.InsecureTLS
		if insecure {
			log.Printf("警告: 已启用不安全 TLS 模式")
		}
	}

	// 构建显示列表
	display := make([]string, 0, len(defaultAllowedHosts))
	display = append(display, defaultAllowedHosts...)
	if cfg != nil && len(cfg.AllowedHosts) > 0 {
		display = append(display, cfg.AllowedHosts...)
	}

	// 创建代理处理器和服务器
	handler := newProxyHandler(allowed, display, insecure, level, cfg)
	srv := &http.Server{
		Addr:           listenAddr,
		Handler:        logMiddleware(level, handler),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: int(globalConfig.Security.MaxHeaderSize),
	}

	// 设置优雅关闭
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 在单独的 goroutine 中启动服务器
	go func() {
		// 启动服务器
		log.Printf("Container Registry Mirrors 正在监听 %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务器错误: %v", err)
		}
	}()

	// 等待中断信号
	<-ctx.Done()
	log.Println("收到关闭信号，正在优雅关闭...")

	// 创建关闭超时上下文
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// 优雅关闭服务器
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("服务器关闭出错: %v", err)
	}

	log.Println("服务器已安全关闭")
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
