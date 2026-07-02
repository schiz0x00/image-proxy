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
	"time"
)

const (
	defaultContentType = "image/jpeg"
	// ponytail: 50MB cap, raise if legitimate images ever exceed it
	maxResponseBytes = 50 << 20
)

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
