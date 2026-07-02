package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

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
