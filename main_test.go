package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("IMAGE_PROXY_DISABLE_SSRF_CHECK", "1")
	disableSSRFCheck = true // init() ran before the env var was set
	defer os.Unsetenv("IMAGE_PROXY_DISABLE_SSRF_CHECK")
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

func TestSSRFBlocking(t *testing.T) {
	// Re-init with SSRF check enabled for this test.
	os.Unsetenv("IMAGE_PROXY_DISABLE_SSRF_CHECK")
	disableSSRFCheck = false

	t.Cleanup(func() {
		os.Setenv("IMAGE_PROXY_DISABLE_SSRF_CHECK", "1")
		disableSSRFCheck = true
	})

	tests := []struct {
		label string
		url   string
	}{
		{"loopback IPv4", "http://127.0.0.1:9999/img.png"},
		{"loopback IPv6", "http://[::1]:9999/img.png"},
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
