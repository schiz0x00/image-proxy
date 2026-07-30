package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	disableSSRFCheck = true // origin servers in these tests are on localhost
	m.Run()
}

func doReq(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	proxyHandler(w, httptest.NewRequest("GET", target, nil))
	return w
}

func TestValidation(t *testing.T) {
	if w := doReq(t, "/image"); w.Code != 400 || !strings.Contains(w.Body.String(), "Missing 'url'") {
		t.Errorf("missing url: got %d %q", w.Code, w.Body.String())
	}
	for _, bad := range []string{"notaurl", "ftp://x/y.png", "file:///etc/passwd", "http://"} {
		if w := doReq(t, "/image?url="+url.QueryEscape(bad)); w.Code != 400 {
			t.Errorf("%s: expected 400, got %d", bad, w.Code)
		}
	}
	// CORS must be present even on errors
	if w := doReq(t, "/image"); w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header on 400")
	}
}

func TestProxyStreamsAndSetsHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "https://www.sephora.com/" {
			t.Error("origin headers not forwarded")
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(200)
		w.Write([]byte("pngbytes"))
	}))
	defer origin.Close()

	w := doReq(t, "/image?url="+url.QueryEscape(origin.URL+"/a.png"))
	body, _ := io.ReadAll(w.Body)
	if w.Code != 200 || string(body) != "pngbytes" || w.Header().Get("Content-Type") != "image/png" {
		t.Errorf("got %d %q ct=%q", w.Code, body, w.Header().Get("Content-Type"))
	}
}

func TestOriginStatusPassthrough(t *testing.T) {
	origin := httptest.NewServer(http.NotFoundHandler())
	defer origin.Close()
	if w := doReq(t, "/image?url="+url.QueryEscape(origin.URL)); w.Code != 404 {
		t.Errorf("expected 404 passthrough, got %d", w.Code)
	}
}

func TestOriginUnreachable(t *testing.T) {
	if w := doReq(t, "/image?url="+url.QueryEscape("http://127.0.0.1:1/x.png")); w.Code != 502 {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

func TestRedirectBlocking(t *testing.T) {
	// Origin that redirects to a private IP — redirect should be blocked
	// even though the initial request to localhost is allowed (SSRF bypass).
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer origin.Close()

	w := doReq(t, "/image?url="+url.QueryEscape(origin.URL+"/redirect"))
	if w.Code != 502 {
		t.Errorf("expected 502 from blocked redirect, got %d", w.Code)
	}
}

func TestRedirectLimit(t *testing.T) {
	// Redirect loop — should be stopped at 5 hops.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer origin.Close()

	w := doReq(t, "/image?url="+url.QueryEscape(origin.URL+"/loop"))
	if w.Code != 502 {
		t.Errorf("expected 502 from redirect loop, got %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Referrer-Policy":         "no-referrer",
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	}))
	defer origin.Close()

	recs := map[string]*httptest.ResponseRecorder{
		"svg passthrough": doReq(t, "/image?url="+url.QueryEscape(origin.URL+"/x.svg")),
		"error response":  doReq(t, "/image"),
	}
	health := httptest.NewRecorder()
	healthHandler(health, httptest.NewRequest("GET", "/health", nil))
	recs["health"] = health

	for label, w := range recs {
		for h, v := range want {
			if got := w.Header().Get(h); got != v {
				t.Errorf("%s: %s = %q, want %q", label, h, got, v)
			}
		}
	}
}

func TestInFlightLimit(t *testing.T) {
	// Saturate the semaphore, then confirm the next request sheds load.
	for i := 0; i < maxInFlight; i++ {
		inFlight <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxInFlight; i++ {
			<-inFlight
		}
	})

	w := doReq(t, "/image?url="+url.QueryEscape("http://example.com/x.png"))
	if w.Code != 503 {
		t.Errorf("expected 503 when saturated, got %d", w.Code)
	}
}

func TestRateLimiterTableCap(t *testing.T) {
	rl := newRateLimiter(20, 40)
	for i := 0; i < maxTrackedClients; i++ {
		rl.clients[strconv.Itoa(i)] = &clientBucket{tokens: 1, last: time.Now()}
	}
	if rl.Allow("new-client") {
		t.Error("expected a full table to refuse an unknown client")
	}
	if !rl.Allow("42") { // already tracked, still served
		t.Error("expected a tracked client to still be allowed")
	}
}

func TestHostAllowlist(t *testing.T) {
	// Empty allowlist allows everything, so the proxy keeps working unconfigured.
	if !hostAllowed("evil.example") {
		t.Error("empty allowlist should allow any host")
	}

	allowedHosts = []string{"sephora.com", "cdn.example.net"}
	t.Cleanup(func() { allowedHosts = nil })

	for _, h := range []string{"sephora.com", "www.sephora.com", "SEPHORA.COM", "cdn.example.net:8443"} {
		if !hostAllowed(h) {
			t.Errorf("%s: expected allowed", h)
		}
	}
	for _, h := range []string{"evil.example", "sephora.com.evil.example", "notsephora.com", "example.net"} {
		if hostAllowed(h) {
			t.Errorf("%s: expected blocked", h)
		}
	}

	if w := doReq(t, "/image?url="+url.QueryEscape("http://evil.example/x.png")); w.Code != 403 {
		t.Errorf("expected 403 for disallowed host, got %d", w.Code)
	}
}

func TestClientIP(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest("GET", "/image", nil)
		r.RemoteAddr = "203.0.113.9:1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// No trusted proxies: the header is untrusted and must be ignored.
	if got := clientIP(req("1.2.3.4")); got != "203.0.113.9" {
		t.Errorf("hops=0: got %q, want RemoteAddr", got)
	}

	trustedProxyHops = 1
	t.Cleanup(func() { trustedProxyHops = 0 })

	if got := clientIP(req("198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("hops=1: got %q", got)
	}
	// A client prepending a forged entry must not shift the choice.
	if got := clientIP(req("1.2.3.4, 198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("hops=1 spoofed: got %q, want the proxy-appended entry", got)
	}
	if got := clientIP(req("")); got != "203.0.113.9" {
		t.Errorf("hops=1 no header: got %q, want RemoteAddr", got)
	}
}

func TestOversizedContentLengthRejected(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", "999999999") // ~1 GB, past the 50 MB cap
		w.WriteHeader(200)
	}))
	defer origin.Close()

	if w := doReq(t, "/image?url="+url.QueryEscape(origin.URL+"/big.png")); w.Code != 502 {
		t.Errorf("expected 502 for oversized Content-Length, got %d", w.Code)
	}
}

func TestRedactURL(t *testing.T) {
	// Query strings hold tokens and must never reach the log.
	if got := redactURL("https://cdn.example/a.png?sig=secret"); got != "https://cdn.example/a.png?redacted" {
		t.Errorf("query not redacted: %q", got)
	}
	// A newline would let a caller forge log lines.
	if got := redactURL("https://cdn.example/a.png\n2026-01-01 forged entry"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("control characters survived: %q", got)
	}
	// Unparseable input still gets scrubbed rather than returned as-is.
	if got := redactURL("::not a url::\x00\n"); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("control characters survived the error branch: %q", got)
	}
}

func TestIsPrivateIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "fe80::1",
		"100.64.0.1", "198.18.0.1", "198.19.0.1", "192.0.0.1",
		"224.0.0.1", "239.255.255.250", "ff02::1", // multicast beyond link-local
		"240.0.0.1", "255.255.255.255", "0.1.2.3", // reserved / broadcast / this-network
		"fc00::1", "fd12:3456::1", // unique-local
		"2002:7f00:0001::",               // 6to4 wrapping 127.0.0.1
		"2001:0:5d58:d802:0:0:f5ff:fffe", // Teredo, public server, 10.0.0.1 client
		"::ffff:169.254.169.254",         // v4-mapped metadata
	}
	for _, s := range blocked {
		if !isPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s: expected blocked", s)
		}
	}
	allowed := []string{"93.184.216.34", "1.1.1.1", "172.32.0.1", "192.169.0.1", "2606:4700::1111"}
	for _, s := range allowed {
		if isPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s: expected allowed", s)
		}
	}
}

// ssrfControl is the real boundary — it sees the resolved IP, so it holds even
// when DNS rebinding makes the pre-flight hostname check pass.
func TestSSRFControl(t *testing.T) {
	disableSSRFCheck = false
	t.Cleanup(func() { disableSSRFCheck = true })

	for _, addr := range []string{
		"169.254.169.254:80", // cloud metadata — the rebinding target
		"127.0.0.1:8080",
		"10.0.0.1:443",
		"[::1]:80",
		"metadata.google.internal:80", // unresolved name must never reach connect
	} {
		if err := ssrfControl("tcp", addr, nil); err == nil {
			t.Errorf("%s: expected block, got nil", addr)
		}
	}
	if err := ssrfControl("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public IP blocked: %v", err)
	}
}

func TestSSRFBlocking(t *testing.T) {
	disableSSRFCheck = false
	t.Cleanup(func() { disableSSRFCheck = true })

	tests := []struct {
		label string
		url   string
	}{
		{"loopback IPv4", "http://127.0.0.1:9999/img.png"},
		{"loopback IPv6", "http://[::1]:9999/img.png"},
		{"loopback IPv6 no port", "http://[::1]/img.png"},
		{"unique-local IPv6 no port", "http://[fd00::1]/img.png"},
		{"v4-mapped metadata", "http://[::ffff:169.254.169.254]/img.png"},
		{"private 10.x", "http://10.0.0.1/img.png"},
		{"private 172.16", "http://172.16.0.1/img.png"},
		{"private 192.168", "http://192.168.1.1/img.png"},
		{"link-local", "http://169.254.169.254/img.png"},
		{"unspecified", "http://0.0.0.0/img.png"},
		{"hostname localhost", "http://localhost:9999/img.png"},
		{"hostname .local", "http://myhost.local/img.png"},
		{"hostname .internal", "http://myhost.internal/img.png"},
	}
	for _, tt := range tests {
		w := doReq(t, "/image?url="+url.QueryEscape(tt.url))
		if w.Code != 403 {
			t.Errorf("%s: expected 403, got %d", tt.label, w.Code)
		}
	}
}
