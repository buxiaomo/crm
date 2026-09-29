package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	"auth.docker.io",
	"production.cloudfront.docker.com",
	"gcr.io",
	"k8s.io",
	"registry.k8s.io",
	"docker.elastic.co",
	"ghcr.io",
}

type Config struct {
	Auth         *AuthConfig    `yaml:"auth" json:"auth"`
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
	if err := c.Auth.Validate(); err != nil {
		return err
	}
	if c.Listen == "" {
		return fmt.Errorf("listen address cannot be empty")
	}

	if filepath.IsAbs(c.Listen) {
		// 检查 socket 路径的目录是否存在
		dir := filepath.Dir(c.Listen)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("socket directory does not exist: %s", dir)
		}
		if info, err := os.Lstat(c.Listen); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("socket path is not a socket: %s", c.Listen)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("check socket path: %w", err)
		}
	} else {
		// 裸端口与 host:port 均使用 TCP，绝对路径使用 Unix socket。
		if _, err := strconv.ParseUint(c.Listen, 10, 16); err == nil {
			c.Listen = ":" + c.Listen
		}
		if _, _, err := net.SplitHostPort(c.Listen); err != nil {
			return fmt.Errorf("invalid listen address format (use a TCP address or an absolute socket path): %w", err)
		}
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
	return loadConfigFrom(path)
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
			return nil, fmt.Errorf("failed to parse YAML %s: check syntax and field types", path)
		}
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON %s: check syntax and field types", path)
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
			// A dot alone is part of a literal hostname, not a regex marker.
			if strings.ContainsAny(s, "[+*?^$(){}|\\]") {
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
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
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
	if cert, ok := ca.certCache[hostname]; ok && cert.Leaf != nil && time.Now().Add(time.Minute).Before(cert.Leaf.NotAfter) {
		ca.cacheMutex.RUnlock()
		return cert, nil
	}
	ca.cacheMutex.RUnlock()

	// 生成新证书
	ca.cacheMutex.Lock()
	defer ca.cacheMutex.Unlock()

	// 再次检查缓存（避免并发生成）
	if cert, ok := ca.certCache[hostname]; ok && cert.Leaf != nil && time.Now().Add(time.Minute).Before(cert.Leaf.NotAfter) {
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
		Leaf:        &template,
	}

	// 存入缓存
	ca.certCache[hostname] = cert
	return cert, nil
}

// ProxyHandler implements a simple forward proxy without caching.
type ProxyHandler struct {
	auth            *AuthConfig
	allowedPatterns []*regexp.Regexp
	allowedDisplay  []string
	transport       *http.Transport
	level           LogLevel

	// MITM 相关
	mitmEnabled bool
	mitmCA      *CertificateAuthority
	mitmAllowed []*regexp.Regexp
}

func newProxyHandler(allowed []*regexp.Regexp, insecureTLS bool, level LogLevel, cfg *Config) *ProxyHandler {
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
		allowedDisplay:  append([]string(nil), defaultAllowedHosts...),
		transport:       tr,
		level:           level,
		mitmEnabled:     false,
	}

	if cfg != nil {
		handler.auth = cfg.Auth
		handler.allowedDisplay = append(handler.allowedDisplay, cfg.AllowedHosts...)
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

// limitedBody prevents Transport.Close from draining a rejected chunked upload.
type limitedBody struct {
	io.ReadCloser
	w        http.ResponseWriter
	exceeded atomic.Bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var sizeErr *http.MaxBytesError
	if errors.As(err, &sizeErr) {
		b.exceeded.Store(true)
		_ = http.NewResponseController(b.w).SetReadDeadline(time.Now())
	}
	return n, err
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 增加请求计数
	atomic.AddInt64(&metrics.TotalRequests, 1)
	atomic.AddInt64(&metrics.ActiveConnections, 1)
	defer atomic.AddInt64(&metrics.ActiveConnections, -1)

	if !p.authenticate(w, r) {
		// An authentication challenge does not indicate an unhealthy service.
		return
	}

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
	body := &limitedBody{
		ReadCloser: http.MaxBytesReader(w, r.Body, globalConfig.Security.MaxRequestSize),
		w:          w,
	}
	r.Body = body

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

	// Local informational endpoints must not intercept forward-proxy targets.
	if !r.URL.IsAbs() && r.URL.Host == "" {
		switch r.URL.EscapedPath() {
		case "/healthz":
			p.serveHealthCheck(w, r)
			return
		case "/metrics":
			p.serveMetrics(w, r)
			return
		case "/":
			if r.Method == http.MethodGet {
				p.serveIndex(w, r)
				return
			}
		}
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

	// Registry mirror clients send origin-form URLs through the HTTPS frontend.
	if !r.URL.IsAbs() && strings.HasPrefix(r.URL.Path, "/v2/") {
		p.serveMirror(w, r)
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
		log.Printf("[req %s] HTTP start method=%s url=%s host=%s client=%s ua=%s accept=%s content-type=%s auth=%s", reqID, r.Method, logURL(r), r.URL.Host, clientAddr, r.Header.Get("User-Agent"), r.Header.Get("Accept"), r.Header.Get("Content-Type"), authPresent)
	}

	if p.level >= LevelDebug {
		// 记录非认证请求头
		log.Printf("[req %s] HTTP request headers:", reqID)
		for k, vs := range r.Header {
			if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Proxy-Authorization") {
				continue
			}
			for _, v := range vs {
				log.Printf("[req %s] > %s: %s", reqID, k, v)
			}
		}
	}

	// Create outbound request
	outReq := r.Clone(r.Context())
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
		status := proxyErrorStatus(err)
		if body.exceeded.Load() {
			status = http.StatusRequestEntityTooLarge
		}
		if status == http.StatusRequestEntityTooLarge {
			w.Header().Set("Connection", "close")
		}
		http.Error(w, fmt.Sprintf("upstream error: %v", err), status)
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
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		// client disconnected or write error; log and ignore
		log.Printf("stream error: %v", err)
	}
	// 统计传输字节数
	atomic.AddInt64(&metrics.TotalBytes, n)

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
		log.Printf("[req %s] HTTP done status=%d bytes_sent=%d content-length=%s duration=%s", reqID, resp.StatusCode, n, cl, dur)
	} else {
		log.Printf("%s %s -> %d in %s", r.Method, logURL(r), resp.StatusCode, dur)
	}
}

func proxyErrorStatus(err error) int {
	var sizeErr *http.MaxBytesError
	if errors.As(err, &sizeErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadGateway
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

// serveIndex renders authentication status, usage instructions, and the registry allowlist.
func (p *ProxyHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="utf-8"><title>Container Registry Mirrors</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px;max-width:920px;margin:auto;color:#222}
h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;margin:24px 0 8px}code,pre{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:2px 6px}
ul{padding-left:20px}footer{margin-top:32px;color:#666;font-size:12px}
.muted{color:#666;font-size:13px}
.auth-notice{padding:12px 16px;background:#fff8e1;border:1px solid #e6bd61;border-radius:6px}
</style></head><body>
<h1>Container Registry Mirrors</h1>
<p class="muted">仅加速公开镜像，不支持私有仓库或推送。请将示例域名替换为实际地址。</p>`)
	if p.auth != nil {
		fmt.Fprint(w, `<p class="auth-notice"><strong>已开启认证</strong>：未授权无法使用镜像加速，请先配置客户端认证。</p>`)
	} else {
		fmt.Fprint(w, `<p class="muted">未开启认证：镜像加速允许匿名访问。</p>`)
	}
	fmt.Fprint(w, `

<h2>代理允许的仓库</h2>
<ul>`)
	shown := make(map[string]struct{})
	for _, host := range p.allowedDisplay {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		key := strings.ToLower(host)
		if _, ok := shown[key]; ok {
			continue
		}
		shown[key] = struct{}{}
		fmt.Fprintf(w, "<li>%s</li>\n", html.EscapeString(host))
	}
	fmt.Fprint(w, `</ul>

<h2>Docker 镜像加速设置</h2>
<p>仅适用于 Docker Hub，受上游匿名额度限制。</p>
<h3>匿名访问</h3>
<p>未开启认证时，合并到 <code>/etc/docker/daemon.json</code>：</p>
<pre>{
  "registry-mirrors": ["https://mirrors.xiaomo.site"]
}</pre>
<p>重启 Docker 后执行 <code>docker pull nginx</code>。</p>
<h3>需要账号认证时</h3>
<p><code>registry-mirrors</code> 不支持 URL 账号密码。移除无效 mirror 条目，保留其他配置；重启后登录 CRM：</p>
<pre>sudo systemctl restart docker
docker login mirrors.xiaomo.site --username admin
docker pull mirrors.xiaomo.site/library/tomcat:latest</pre>
<p>替换示例用户名，按提示输入密码；拉取时必须保留 CRM 域名前缀。</p>

<h2>Containerd 镜像加速设置</h2>
<p>在 <code>/etc/containerd/config.toml</code> 中按现有配置版本合并一组片段，保留其他配置；<code>version</code> 放在文件顶层。</p>
<p>配置版本 2（Containerd 1.5+ 的 1.x，或沿用版本 2 的 2.x）：</p>
<pre>version = 2

[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"</pre>
<p>配置版本 3（Containerd 2.x）：</p>
<pre>version = 3

[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/containerd/certs.d"</pre>
<p>创建 <code>/etc/containerd/certs.d/docker.io/hosts.toml</code>：</p>
<pre>server = "https://registry-1.docker.io"

[host."https://mirrors.xiaomo.site"]
  capabilities = ["pull", "resolve"]</pre>
<p>使用可信的 HTTPS 入口。失败时回退 Docker Hub；禁止直连时，将 <code>server</code> 也设为 CRM 地址。</p>
<p>GHCR / GCR：将目录名 <code>docker.io</code> 和 <code>server</code> 域名改为 <code>ghcr.io</code> / <code>gcr.io</code>，CRM host 不变。</p>
<p>需要认证时，仅在 CRM host 下添加请求头（不支持 URL 账号密码）：</p>
<pre>[host."https://mirrors.xiaomo.site".header]
  Authorization = "Basic BASE64_OF_USERNAME_COLON_PASSWORD"</pre>
<p>将不带换行的“用户名:密码”编码为单行 Base64，填入占位符。必须使用 HTTPS，并限制 <code>hosts.toml</code> 仅服务账号可读。</p>
<p>修改 <code>config.toml</code> 后重启并验证；仅改 <code>hosts.toml</code> 无需重启：</p>
<pre>sudo systemctl restart containerd
sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock \
  --image-endpoint unix:///run/containerd/containerd.sock \
  pull docker.io/library/nginx:latest</pre>
<p>使用 <code>ctr</code> 时须指定 hosts 目录：</p>
<pre>sudo ctr images pull --hosts-dir /etc/containerd/certs.d docker.io/library/nginx:latest</pre>
<p>其他仓库和旧版配置见 <a href="https://github.com/buxiaomo/crm/blob/main/README.md#containerd-镜像加速器">Containerd 配置说明</a>；旧式 mirrors 不与 <code>config_path</code> 混用。</p>

<h2>可选：前向代理</h2>
<p>需将服务端 <code>listen</code> 设为 TCP 地址（如 <code>:8888</code>）；Unix socket 模式不可用。</p>
<pre>curl -x http://proxy.example.com:8888 https://registry-1.docker.io/v2/</pre>
<p>curl 认证：增加 <code>--proxy-user 用户名</code>，按提示输入密码。</p>
<p>Docker：合并到 <code>/etc/docker/daemon.json</code> 后重启：</p>
<pre>{
  "proxies": {
    "http-proxy": "http://proxy.example.com:8888",
    "https-proxy": "http://proxy.example.com:8888"
  }
}</pre>
<p>Containerd：在 systemd 服务配置中设置 <code>HTTP_PROXY</code> 和 <code>HTTPS_PROXY</code> 后重启。</p>

<footer>
项目地址：<a href="https://github.com/buxiaomo/crm.git" target="_blank">https://github.com/buxiaomo/crm.git</a>
</footer>
</body></html>`)
}

// bufferedConn preserves bytes read ahead while parsing CONNECT.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func connectClient(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, err
	}
	// Replace inherited HTTP deadlines with the CONNECT request deadline.
	deadline, _ := r.Context().Deadline()
	if err = conn.SetDeadline(deadline); err == nil {
		_, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	}
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &bufferedConn{Conn: conn, reader: rw.Reader}, nil
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
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", host)
	if err != nil {
		errMsg := fmt.Sprintf("dial upstream failed: %v", err)
		http.Error(w, errMsg, http.StatusBadGateway)
		log.Printf("[req %s] 连接上游失败: %s, 错误: %v", reqID, host, err)
		return
	}
	defer upstream.Close() // 确保连接关闭
	stop := context.AfterFunc(r.Context(), func() { upstream.Close() })
	defer stop()

	clientConn, err := connectClient(w, r)
	if err != nil {
		log.Printf("[req %s] 建立隧道失败: %v", reqID, err)
		return
	}
	defer clientConn.Close()

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

	clientConn, err := connectClient(w, r)
	if err != nil {
		log.Printf("[req %s] 建立隧道失败: %v", reqID, err)
		return
	}
	defer clientConn.Close()

	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// 将连接升级为 TLS
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		log.Printf("[req %s] TLS 握手失败: %v", reqID, err)
		tlsConn.Close()
		return
	}

	// 创建 HTTP 服务器处理解密后的请求
	connReader := bufio.NewReader(tlsConn)
	connWriter := bufio.NewWriter(tlsConn)

	// 处理来自客户端的 HTTP 请求
	for {
		// 读取请求
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[req %s] 读取 MITM 请求失败: %v", reqID, err)
			}
			break
		}

		// 修改请求以发送到上游
		req = req.WithContext(r.Context())
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.Host = host
		req.RequestURI = ""
		req.Header.Del("Proxy-Authorization")
		// The tunnel owns this body; Transport must not drain it after a size error.
		req.Body = http.MaxBytesReader(nil, io.NopCloser(req.Body), globalConfig.Security.MaxRequestSize)

		// 记录请求信息
		if p.level >= LevelInfo {
			authPresent := "false"
			if req.Header.Get("Authorization") != "" {
				authPresent = "true"
			}
			log.Printf("[req %s] MITM HTTP start method=%s url=%s host=%s client=%s ua=%s accept=%s content-type=%s auth=%s",
				reqID, req.Method, logURL(req), req.URL.Host, clientAddr,
				req.Header.Get("User-Agent"), req.Header.Get("Accept"),
				req.Header.Get("Content-Type"), authPresent)
		}

		if p.level >= LevelDebug {
			// 打印请求头部
			log.Printf("[req %s] MITM HTTP request headers:", reqID)
			for k, vs := range req.Header {
				if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Proxy-Authorization") {
					continue
				}
				for _, v := range vs {
					log.Printf("[req %s] > %s: %s", reqID, k, v)
				}
			}
		}

		// 发送请求到上游
		var resp *http.Response
		if req.ContentLength > globalConfig.Security.MaxRequestSize {
			err = &http.MaxBytesError{Limit: globalConfig.Security.MaxRequestSize}
		} else {
			resp, err = p.transport.RoundTrip(req)
		}
		if err != nil {
			log.Printf("[req %s] MITM 上游请求失败: %v", reqID, err)

			// 向客户端返回错误
			errResp := &http.Response{
				StatusCode: proxyErrorStatus(err),
				Close:      true,
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
		// ponytail: close after uploads; track writer completion if upload keep-alive is needed.
		resp.Close = resp.Close || req.Close || req.ContentLength != 0 || len(req.TransferEncoding) > 0
		err = resp.Write(connWriter)
		resp.Body.Close()
		if err != nil {
			log.Printf("[req %s] 写入响应失败: %v", reqID, err)
			break
		}
		if err := connWriter.Flush(); err != nil {
			log.Printf("[req %s] 刷新响应失败: %v", reqID, err)
			break
		}

		// 检查是否需要关闭连接
		if resp.Close {
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

// listenUnix only removes a stale socket whose listener is no longer running.
func listenUnix(path string) (net.Listener, error) {
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path is not a socket: %s", path)
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			return nil, fmt.Errorf("socket is already in use: %s", path)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("check existing socket: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	return net.Listen("unix", path)
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

	// 创建代理处理器和服务器
	handler := newProxyHandler(allowed, insecure, level, cfg)
	srv := &http.Server{
		Handler:           logMiddleware(level, handler),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       cfg.Security.RequestTimeout,
		WriteTimeout:      cfg.Security.RequestTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    int(globalConfig.Security.MaxHeaderSize),
	}

	// 设置优雅关闭
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 根据 listen 创建唯一监听器。
	var listener net.Listener
	listenerType := "TCP"
	if filepath.IsAbs(cfg.Listen) {
		listenerType = "Unix socket"
		listener, err = listenUnix(cfg.Listen)
	} else {
		listener, err = net.Listen("tcp", cfg.Listen)
	}
	if err != nil {
		log.Fatalf("无法创建 %s 监听器: %v", listenerType, err)
	}
	defer listener.Close()
	if listenerType == "Unix socket" {
		if err := os.Chmod(cfg.Listen, 0666); err != nil {
			log.Printf("警告: 无法设置 socket 文件权限: %v", err)
		}
	}
	log.Printf("Container Registry Mirrors 正在监听 %s %s", listenerType, listener.Addr())
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// responseWriter 包装 http.ResponseWriter 以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// getClientIP 获取客户端真实IP地址，支持代理头
func getClientIP(r *http.Request) string {
	// 检查 X-Forwarded-For 头（最常用的代理头）
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For 可能包含多个IP，取第一个
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// 检查 X-Real-IP 头（Nginx常用）
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 检查 CF-Connecting-IP 头（Cloudflare）
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return strings.TrimSpace(cfip)
	}

	// 检查 True-Client-IP 头（Akamai）
	if tcip := r.Header.Get("True-Client-IP"); tcip != "" {
		return strings.TrimSpace(tcip)
	}

	// 回退到 RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// logURL excludes credentials supplied in URL userinfo.
func logURL(r *http.Request) string {
	u := *r.URL
	u.User = nil
	return u.String()
}

func logMiddleware(level LogLevel, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 获取客户端IP
		clientIP := getClientIP(r)

		// 包装ResponseWriter以捕获状态码
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // 默认状态码
		}

		// 基础访问日志：遵循统一的日志级别
		if level >= LevelInfo {
			ua := r.Header.Get("User-Agent")
			log.Printf("%s %s IP=%s UA=%s", r.Method, logURL(r), clientIP, ua)
		}

		// 调用下一个处理器
		next.ServeHTTP(rw, r)

		// 记录响应信息
		duration := time.Since(start)
		if level >= LevelInfo {
			log.Printf("%s %s IP=%s Status=%d Duration=%s",
				r.Method, logURL(r), clientIP, rw.statusCode, duration)
		}
	})
}
