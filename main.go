package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var version = "0.1.0"

// ChatMessage mirrors the OpenAI chat message format.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest mirrors the OpenAI /v1/chat/completions request body.
type ChatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
}

// ErrorResponse is a simple JSON error envelope.
type ErrorResponse struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Details []struct {
			Violation string `json:"violation"`
			Role      string `json:"role"`
			Snippet   string `json:"snippet"`
		} `json:"details,omitempty"`
	} `json:"error"`
}

func buildErrorResponse(violations []Violation) ErrorResponse {
	resp := ErrorResponse{}
	resp.Error.Type = "prompt_injection_detected"
	resp.Error.Message = fmt.Sprintf(
		"Request blocked by prompt-firewall: %d violation(s) detected", len(violations),
	)
	for _, v := range violations {
		snippet := v.Segment.Content
		if len(snippet) > 120 {
			snippet = snippet[:120] + "..."
		}
		resp.Error.Details = append(resp.Error.Details, struct {
			Violation string `json:"violation"`
			Role      string `json:"role"`
			Snippet   string `json:"snippet"`
		}{
			Violation: string(v.Type),
			Role:      v.Segment.Role,
			Snippet:   snippet,
		})
	}
	return resp
}

// stats tracks request counts atomically.
type stats struct {
	allowed int64
	blocked int64
}

// server holds shared dependencies.
type server struct {
	firewall *Firewall
	upstream *url.URL // nil when running standalone (no proxy)
	proxy    *httputil.ReverseProxy
	stats    stats
	startAt  time.Time
}

func newServer(upstreamURL string) (*server, error) {
	fw := NewFirewall()
	s := &server{firewall: fw, startAt: time.Now()}

	if upstreamURL != "" {
		u, err := url.Parse(upstreamURL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL: %w", err)
		}
		s.upstream = u
		s.proxy = httputil.NewSingleHostReverseProxy(u)
		originalDirector := s.proxy.Director
		s.proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = u.Host
		}
	}

	return s, nil
}

// handleScan is a lightweight endpoint that only returns a scan verdict.
// POST /v1/scan  ->  {"allowed": bool, "violations": [...]}
func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	segments := messagesToSegments(req.Messages)
	result := s.firewall.Scan(segments)

	if result.Allowed {
		atomic.AddInt64(&s.stats.allowed, 1)
	} else {
		atomic.AddInt64(&s.stats.blocked, 1)
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.Allowed {
		w.WriteHeader(http.StatusForbidden)
	}
	_ = json.NewEncoder(w).Encode(result)
}

// handleChatCompletions intercepts /v1/chat/completions, scans the request,
// and either blocks it or forwards it to the upstream LLM.
func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	segments := messagesToSegments(req.Messages)
	result := s.firewall.Scan(segments)

	if !result.Allowed {
		atomic.AddInt64(&s.stats.blocked, 1)
		resp := buildErrorResponse(result.Violations)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(resp)
		log.Printf("BLOCKED model=%s violations=%d", req.Model, len(result.Violations))
		return
	}

	atomic.AddInt64(&s.stats.allowed, 1)
	log.Printf("ALLOWED model=%s messages=%d", req.Model, len(req.Messages))

	if s.proxy == nil {
		// Standalone mode -- no upstream configured, return a stub 200.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "allowed",
			"note":   "no upstream configured; request passed firewall checks",
		})
		return
	}

	// Reconstruct the body for the proxy.
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	r.ContentLength = int64(len(body))
	s.proxy.ServeHTTP(w, r)
}

// handleHealth returns a simple health check response.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	upstream := ""
	if s.upstream != nil {
		upstream = s.upstream.String()
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"version":  version,
		"uptime":   time.Since(s.startAt).String(),
		"upstream": upstream,
	})
}

// handleStats returns request statistics.
func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	allowed := atomic.LoadInt64(&s.stats.allowed)
	blocked := atomic.LoadInt64(&s.stats.blocked)
	total := allowed + blocked
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   total,
		"allowed": allowed,
		"blocked": blocked,
		"uptime":  time.Since(s.startAt).String(),
	})
}

// messagesToSegments converts OpenAI-style messages to PCFI segments.
func messagesToSegments(messages []ChatMessage) []Segment {
	segments := make([]Segment, 0, len(messages))
	for _, m := range messages {
		segments = append(segments, Segment{
			Role:       m.Role,
			Content:    m.Content,
			Provenance: InferProvenance(m.Role),
		})
	}
	return segments
}

func main() {
	listen := flag.String("listen", "", "address to listen on (default :8080)")
	upstream := flag.String("upstream", "", "upstream LLM API URL to proxy to")
	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `prompt-firewall v%s

Stop prompt injection attacks before they reach your LLM.
A sub-millisecond reverse proxy that sits between your app and any LLM API.

Usage:
  prompt-firewall [flags]

Examples:
  # Start in scan-only mode on default port
  prompt-firewall

  # Proxy to OpenAI
  prompt-firewall --upstream https://api.openai.com --listen :8080

  # Proxy to Anthropic
  prompt-firewall --upstream https://api.anthropic.com --listen :9090

Flags:
`, version)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Environment variables:
  LISTEN_ADDR    address to listen on (flag takes precedence)
  UPSTREAM_URL   upstream LLM API URL (flag takes precedence)

Endpoints:
  POST /v1/chat/completions   scan + proxy to upstream LLM
  POST /v1/scan               scan only, return verdict
  GET  /health                health check
  GET  /healthz               health check (k8s)
  GET  /stats                 request counters
`)
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("prompt-firewall v%s\n", version)
		os.Exit(0)
	}

	// Flags take precedence over env vars.
	addr := *listen
	if addr == "" {
		addr = envOr("LISTEN_ADDR", ":8080")
	}
	upstreamURL := *upstream
	if upstreamURL == "" {
		upstreamURL = os.Getenv("UPSTREAM_URL")
	}

	s, err := newServer(upstreamURL)
	if err != nil {
		log.Fatalf("failed to initialise server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("/v1/scan", s.handleScan)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/stats", s.handleStats)

	srv := &http.Server{
		Addr:         addr,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	mode := "scan-only"
	if upstreamURL != "" {
		mode = "proxy"
	}
	log.Printf("prompt-firewall v%s listening on %s mode=%s upstream=%q", version, addr, mode, upstreamURL)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
