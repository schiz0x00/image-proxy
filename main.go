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
	"strings"
	"time"
)

const (
	defaultContentType = "image/jpeg"
	// ponytail: 50MB cap, raise if legitimate images ever exceed it
	maxResponseBytes = 50 << 20
)

// isBlockedHost checks whether the host resolves to a private, loopback,
// link-local, multicast, or unspecified IP — classic SSRF targets. Also
// blocks bare hostnames that are clearly local (e.g. "localhost").
func isBlockedHost(host string) (bool, string) {
	// Strip port if present.
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port, use as-is
	}

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
	// Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}
	// Unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}
	// Link-local unicast (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return true
	}
	// Link-local multicast (224.0.0.0/24, ff01::/16, ff02::/16)
	if ip.IsLinkLocalMulticast() {
		return true
	}
	// Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // CGNAT
			return true
		case ip4[0] == 198 && ip4[1] == 18: // 198.18.0.0/15 benchmark testing
			return true
		}
	}
	// IPv6 unique-local (fc00::/7)
	if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}

// disableSSRFCheck disables the private-IP block for tests that need
// localhost origin servers. Never set in production.
var disableSSRFCheck bool

func init() {
	disableSSRFCheck = os.Getenv("IMAGE_PROXY_DISABLE_SSRF_CHECK") == "1"
}

var originHeaders = map[string]string{
	"User-Agent": "Mozilla/5.0",
	"Accept":     "image/*,*/*;q=0.8",
	"Referer":    "https://www.sephora.com/",
}

// No Client.Timeout: it would cap the total body transfer and truncate slow
// streams. Headers are bounded below; the request context handles the rest.
var originClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Limit to 5 redirects (Go default is 10).
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		// Validate the redirect target — same SSRF rules apply.
		if blocked, _ := isBlockedHost(req.URL.Host); blocked {
			return errors.New("redirect target blocked by SSRF policy")
		}
		// Only follow http/https redirects.
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return errors.New("redirect to non-http(s) target not allowed")
		}
		return nil
	},
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /image", proxyHandler)
	mux.HandleFunc("OPTIONS /image", optionsHandler)

	server := &http.Server{
		Addr:        ":8080",
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
		// WriteTimeout stays 0 to allow streaming; upstream timeouts and
		// client cancellation bound the response.
		IdleTimeout: 60 * time.Second,
	}

	log.Println("Starting image proxy on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func optionsHandler(w http.ResponseWriter, r *http.Request) {
	writeCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	writeCORS(w)

	imageURL := r.URL.Query().Get("url")
	if imageURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	u, err := url.ParseRequestURI(imageURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "Invalid 'url' query parameter", http.StatusBadRequest)
		return
	}

	if !disableSSRFCheck {
		if blocked, reason := isBlockedHost(u.Host); blocked {
			log.Printf("Blocked SSRF attempt: host=%s reason=%s", u.Host, reason)
			http.Error(w, "Blocked: target host is not allowed", http.StatusForbidden)
			return
		}
	}

	originReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, imageURL, nil)
	if err != nil {
		http.Error(w, "Failed to create origin request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for k, v := range originHeaders {
		originReq.Header.Set(k, v)
	}

	resp, err := originClient.Do(originReq)
	if err != nil {
		status := http.StatusBadGateway
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
			(errors.As(err, &netErr) && netErr.Timeout()) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, "Failed to fetch image from origin: "+err.Error(), status)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = defaultContentType
	}
	w.Header().Set("Content-Type", contentType)
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.WriteHeader(resp.StatusCode)

	written, err := io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		log.Printf("Error streaming response body: %v", err)
	}
	log.Printf("%s status=%d bytes=%d duration=%s", imageURL, resp.StatusCode, written, time.Since(start))
}

func writeCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
}
