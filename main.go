// Command image-proxy is a stateless streaming image proxy. It fetches an
// image from an upstream URL and streams it back to the caller without
// caching, storing, or transforming it. Fetching attacker-supplied URLs is the
// point of the service, so the SSRF, size, and rate controls in this file are
// the security boundary rather than incidental hardening.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultContentType = "image/jpeg"
	// ponytail: 50MB cap, raise if legitimate images ever exceed it
	maxResponseBytes = 50 << 20
	maxURLLength     = 8 * 1024 // 8 KB max URL query param value

	// maxInFlight bounds concurrent origin fetches. Per-IP rate limiting does
	// not bound the total: every new source address gets its own bucket, so a
	// distributed caller could otherwise open unlimited upstream connections.
	maxInFlight = 256

	// maxTrackedClients bounds the rate-limiter table. Entries expire after two
	// minutes, so without a cap a flood of unique source addresses inside that
	// window grows the map without limit.
	maxTrackedClients = 100_000
)

var inFlight = make(chan struct{}, maxInFlight)

// redactURL strips query parameters from a URL for safe logging, keeping the
// scheme, host, and path visible. Control characters are removed from whatever
// it returns: the input is caller-supplied, and a bare newline in it would let
// the caller forge log lines. url.ParseRequestURI already rejects such input on
// the request path, so this is defence in depth for the error branch below,
// which returns the string unparsed.
func redactURL(rawURL string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, rawURL)

	u, err := url.Parse(clean)
	if err != nil || u.Query().Encode() == "" {
		return clean
	}
	u.RawQuery = "redacted"
	return u.String()
}

// hostOnly strips the port and any IPv6 brackets from a URL host. With no
// port, an IPv6 literal still carries the brackets and net.ParseIP rejects
// those.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// allowedHosts limits which origins may be fetched, as exact hostnames or
// parent domains. Empty — the default — allows any public host, which leaves
// the proxy an open relay: anyone can route traffic through this address, on
// this bandwidth bill, with the abuse reports arriving here. Set ALLOWED_HOSTS
// in production.
var allowedHosts = func() (hosts []string) {
	for _, h := range strings.Split(os.Getenv("ALLOWED_HOSTS"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}()

func hostAllowed(host string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	h := strings.ToLower(hostOnly(host))
	for _, a := range allowedHosts {
		if h == a || strings.HasSuffix(h, "."+a) {
			return true
		}
	}
	return false
}

// ssrfControl is called by the dialer with the *resolved* IP, after the socket
// is created but before connect(2). This is the real SSRF boundary: checking
// the hostname up front cannot prevent DNS rebinding, because the client
// resolves the name a second time when it dials. Applies to every hop,
// including redirects.
func ssrfControl(_, address string, _ syscall.RawConn) error {
	if disableSSRFCheck {
		return nil
	}
	h, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("blocked: unparseable dial address")
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return errors.New("blocked: dial address is not an IP")
	}
	if isPrivateIP(ip) {
		return errors.New("blocked: target IP is in a private range")
	}
	return nil
}

// isBlockedHost is a pre-flight check so that obviously-local targets get a
// 403 instead of a 502. It is not the security boundary — ssrfControl is.
// Blocks bare hostnames that are clearly local (e.g. "localhost") and hosts
// that already resolve to a private IP.
func isBlockedHost(host string) (bool, string) {
	h := hostOnly(host)

	// Block obviously local bare hostnames.
	lower := strings.ToLower(h)
	switch lower {
	case "localhost", "localhost.localdomain", "local", "broadcasthost":
		return true, "hostname is a local alias"
	}
	if strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
		return true, "hostname is a local/internal suffix"
	}

	// If it's already an IP, check it directly.
	if ip := net.ParseIP(h); ip != nil {
		if isPrivateIP(ip) {
			return true, "IP is in a private/loopback range"
		}
		return false, ""
	}

	// Resolve DNS and check every returned address.
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), h)
	if err != nil {
		// Resolution failure — could be a transient issue or a trick.
		// Block to be safe rather than leak internal DNS info.
		return true, "hostname does not resolve"
	}
	for _, addr := range ips {
		if isPrivateIP(addr.IP) {
			return true, "hostname resolves to a private/loopback IP"
		}
	}
	return false, ""
}

func isPrivateIP(ip net.IP) bool {
	// Catch-all for everything that is not routable public unicast: loopback,
	// unspecified, all multicast (224.0.0.0/4, ff00::/8), link-local, the
	// IPv4 broadcast address, and malformed addresses.
	if !ip.IsGlobalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 0: // 0.0.0.0/8 "this network" — unroutable, aliases localhost
			return true
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // IETF protocol assignments
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // CGNAT
			return true
		case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // 198.18.0.0/15 benchmark
			return true
		case ip4[0] >= 240: // 240.0.0.0/4 reserved
			return true
		}
		return false
	}

	// IPv6 unique-local (fc00::/7)
	if ip[0]&0xfe == 0xfc {
		return true
	}
	// 6to4 (2002::/16) embeds the IPv4 address in bytes 2-5.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return isPrivateIP(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
	}
	// Teredo (2001::/32) carries the server IPv4 in bytes 4-7 and the client
	// IPv4, bitwise-inverted, in the last four bytes. Either can be internal.
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
		return isPrivateIP(net.IPv4(ip[4], ip[5], ip[6], ip[7])) ||
			isPrivateIP(net.IPv4(^ip[12], ^ip[13], ^ip[14], ^ip[15]))
	}
	return false
}

// disableSSRFCheck lets tests reach localhost origin servers. It is set only
// from test code — deliberately not readable from the environment or a flag,
// so no production configuration can switch the SSRF check off.
var disableSSRFCheck bool

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.8010.37 Safari/537.36"

// envDefault returns the variable's value, or fallback when it is unset or
// empty. Empty is treated as unset so an operator cannot accidentally send an
// empty header that some origins reject.
func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envBool parses a 0/1/true/false-style toggle. Unset or unparseable values
// fall back to def so a typo does not silently disable a workaround.
func envBool(name string, def bool) bool {
	if v := os.Getenv(name); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// Headers sent with every origin request, configurable per deployment. Origins
// routinely answer 403 to a bare "Mozilla/5.0" user agent, so the default is a
// complete Chrome on Windows 11 UA rather than a fingerprintable stub.
var originHeaders = map[string]string{
	"User-Agent": envDefault("ORIGIN_USER_AGENT", chromeUA),
	"Accept":     envDefault("ORIGIN_ACCEPT", "image/*,*/*;q=0.8"),
	"Referer":    envDefault("ORIGIN_REFERER", "https://www.sephora.com/"),
}

// Origin-specific URL rewrites. Each is scoped tightly to the exact host/path
// it repairs and defaults to on so availability fixes ship with the service;
// set the matching variable to "false" to disable it.
var (
	// www.vertbaudet.fr/fstrz/r/s/media.vertbaudet.fr/... is served through an
	// optimization reverse proxy that answers 403 to non-browser traffic, while
	// the same image on media.vertbaudet.fr streams normally.
	rewriteVertbaudetFstrz = envBool("REWRITE_VERTBAUDET_FSTRZ", true)
	// firebasestorage.googleapis.com refuses object URLs without an alt=media
	// query parameter (403); adding it makes them streamable.
	ensureFirebaseAltMedia = envBool("ENSURE_FIREBASE_ALT_MEDIA", true)
)

// normalizeOriginURL applies the rewrites above to the parsed target so every
// check that follows — allowlist, SSRF, redirect policy — and the request
// itself all use the URL that is actually fetched.
func normalizeOriginURL(u *url.URL) {
	if u == nil {
		return
	}
	if rewriteVertbaudetFstrz && strings.EqualFold(u.Host, "www.vertbaudet.fr") {
		const prefix = "/fstrz/r/s/media.vertbaudet.fr"
		if strings.HasPrefix(u.Path, prefix) {
			u.Scheme = "https"
			u.Host = "media.vertbaudet.fr"
			u.Path = strings.TrimPrefix(u.Path, prefix)
		}
	}
	if ensureFirebaseAltMedia && strings.EqualFold(u.Host, "firebasestorage.googleapis.com") {
		q := u.Query()
		if q.Get("alt") == "" {
			q.Set("alt", "media")
			u.RawQuery = q.Encode()
		}
	}
}

// No Client.Timeout: it would cap the total body transfer and truncate slow
// streams. Headers are bounded below; the request context handles the rest.
var originClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
			Control: ssrfControl,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxConnsPerHost:       64,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   16,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Limit to 5 redirects (Go default is 10).
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		// Validate the redirect target — same rules as the original request,
		// or a redirect would walk straight out of the allowlist.
		if blocked, _ := isBlockedHost(req.URL.Host); blocked {
			return errors.New("redirect target blocked by SSRF policy")
		}
		if !hostAllowed(req.URL.Host) {
			return errors.New("redirect target not in ALLOWED_HOSTS")
		}
		// Only follow http/https redirects.
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return errors.New("redirect to non-http(s) target not allowed")
		}
		return nil
	},
}

// ── Rate limiter ────────────────────────────────────────────────────

type rateLimiter struct {
	mu        sync.Mutex
	clients   map[string]*clientBucket
	rate      int // max requests per second
	burst     int // burst capacity
	lastPrune time.Time
}

type clientBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{
		clients:   make(map[string]*clientBucket),
		rate:      rate,
		burst:     burst,
		lastPrune: time.Now(),
	}
}

func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Prune stale entries every minute.
	if now.Sub(rl.lastPrune) > time.Minute {
		for k, b := range rl.clients {
			if now.Sub(b.last) > 2*time.Minute {
				delete(rl.clients, k)
			}
		}
		rl.lastPrune = now
	}

	b, ok := rl.clients[ip]
	if !ok {
		// Table full: refuse unknown clients rather than grow without bound.
		if len(rl.clients) >= maxTrackedClients {
			return false
		}
		b = &clientBucket{tokens: float64(rl.burst), last: now}
		rl.clients[ip] = b
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(rl.rate)
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// trustedProxyHops is the number of reverse proxies in front of this server.
// Zero (the default) means none, and X-Forwarded-For is ignored entirely: a
// client can set that header freely, so trusting it without a known hop count
// would let anyone pick their own rate-limit bucket.
var trustedProxyHops = func() int {
	n, _ := strconv.Atoi(os.Getenv("TRUSTED_PROXY_HOPS"))
	if n < 0 {
		n = 0
	}
	return n
}()

// clientIP returns the address to key rate limiting on. Behind a proxy,
// RemoteAddr is the proxy for every request, which would collapse all traffic
// into one bucket.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if trustedProxyHops == 0 {
		return ip
	}
	// Each proxy appends the address it saw, so the rightmost entries are the
	// trustworthy ones. Counting that many in from the right lands on the
	// furthest hop we can still believe; anything the client forged sits to
	// the left of it and is ignored.
	xff := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if i := len(xff) - trustedProxyHops; i >= 0 && i < len(xff) {
		if v := strings.TrimSpace(xff[i]); v != "" {
			return v
		}
	}
	return ip
}

// rateLimitMiddleware wraps a handler with per-IP rate limiting.
func rateLimitMiddleware(next http.Handler, rl *rateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r)) {
			writeCORS(w)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	rl := newRateLimiter(20, 40) // 20 req/s per IP, burst 40

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /image", proxyHandler)
	mux.HandleFunc("OPTIONS /image", optionsHandler)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           rateLimitMiddleware(mux, rl),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second, // upper bound; slow clients disconnected
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024, // 16 KB max headers
	}

	log.Println("Starting image proxy on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK"))
}

func optionsHandler(w http.ResponseWriter, _ *http.Request) {
	writeCORS(w)
	writeSecurityHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	writeCORS(w)
	writeSecurityHeaders(w)

	imageURL := r.URL.Query().Get("url")
	if imageURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}
	if len(imageURL) > maxURLLength {
		// #nosec G706 -- only the length is logged, never the URL itself.
		log.Printf("URL too long: %d bytes", len(imageURL))
		http.Error(w, "URL too long", http.StatusBadRequest)
		return
	}

	u, err := url.ParseRequestURI(imageURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "Invalid 'url' query parameter", http.StatusBadRequest)
		return
	}

	// Apply origin-specific rewrites before validation so the allowlist and
	// SSRF checks, and the request itself, all use the target we will fetch.
	normalizeOriginURL(u)
	imageURL = u.String()

	if !hostAllowed(u.Host) {
		// #nosec G706 -- redactURL strips control characters and the query string.
		log.Printf("Blocked host not in ALLOWED_HOSTS: url=%s", redactURL(imageURL))
		http.Error(w, "Blocked: target host is not allowed", http.StatusForbidden)
		return
	}

	if !disableSSRFCheck {
		if blocked, reason := isBlockedHost(u.Host); blocked {
			// #nosec G706 -- redactURL strips control characters and the query string.
			log.Printf("Blocked SSRF attempt: url=%s reason=%s", redactURL(imageURL), reason)
			http.Error(w, "Blocked: target host is not allowed", http.StatusForbidden)
			return
		}
	}

	// Bound concurrent upstream fetches. Applied here rather than as
	// middleware so /health keeps answering while the proxy is saturated.
	select {
	case inFlight <- struct{}{}:
		defer func() { <-inFlight }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Server too busy", http.StatusServiceUnavailable)
		return
	}

	// #nosec G704 -- fetching a caller-supplied URL is what this service does.
	// The target has already passed hostAllowed and isBlockedHost, and the
	// dialer re-checks the resolved IP in ssrfControl on every hop.
	originReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, imageURL, nil)
	if err != nil {
		log.Printf("Failed to create origin request: %v", err)
		http.Error(w, "Failed to create origin request", http.StatusInternalServerError)
		return
	}
	for k, v := range originHeaders {
		originReq.Header.Set(k, v)
	}

	// #nosec G704 -- see above; originClient pins the SSRF check to the dial.
	resp, err := originClient.Do(originReq)
	if err != nil {
		status := http.StatusBadGateway
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
			(errors.As(err, &netErr) && netErr.Timeout()) {
			status = http.StatusGatewayTimeout
		}
		log.Printf("Failed to fetch image from origin: %v", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = defaultContentType
	}
	// Only allow image/* content types to prevent content-type confusion.
	if !strings.HasPrefix(contentType, "image/") {
		contentType = defaultContentType
	}
	w.Header().Set("Content-Type", contentType)

	// Only forward Content-Length when it agrees with what we are willing to
	// stream. Forwarding a larger value promised the client bytes that
	// io.LimitReader would never deliver, leaving a truncated response with a
	// mismatched length. Anything unparseable is dropped so Go frames the
	// response itself.
	if cl, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil && cl >= 0 {
		if cl > maxResponseBytes {
			log.Printf("Origin response too large: %d bytes > %d", cl, maxResponseBytes)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(cl, 10))
	}
	w.WriteHeader(resp.StatusCode)

	written, err := io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		log.Printf("Error streaming response body: %v", err)
	}
	// #nosec G706 -- redactURL strips control characters and the query string.
	log.Printf("%s status=%d bytes=%d duration=%s", redactURL(imageURL), resp.StatusCode, written, time.Since(start))
}

func writeCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
}

func writeSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// image/svg+xml satisfies the image/ prefix check, and an SVG opened
	// directly in a browser can run script — served from our origin, on our
	// domain. The sandbox and empty default-src stop that; neither affects the
	// image when it is embedded with <img>.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
