# prompt-firewall

## Build & Test

- Build: `make build` or `go build -o prompt-firewall .`
- Test: `make test` or `go test ./...`
- Benchmark: `go test -bench=. -benchmem ./...`
- Clean: `make clean`
- Language: Go (zero external dependencies)
- Install: `go install github.com/timholm/prompt-firewall@latest`

## Running

```bash
# Scan-only mode
prompt-firewall --listen :8080

# Proxy mode (forward clean requests to upstream LLM)
prompt-firewall --upstream https://api.openai.com --listen :8080

# Using env vars
UPSTREAM_URL=https://api.openai.com LISTEN_ADDR=:8080 prompt-firewall
```

## Architecture

Single Go package with two core modules:

**main.go:** HTTP server implementing the PCFI gateway as an OpenAI-compatible reverse proxy.
- `server` struct holds firewall instance, optional upstream reverse proxy, and atomic request counters
- `handleChatCompletions()`: POST `/v1/chat/completions` -- scans messages, blocks (403) if threats detected, forwards allowed requests to upstream
- `handleScan()`: POST `/v1/scan` -- lightweight verification endpoint returning verdict without forwarding
- `handleHealth()`: GET `/health` and `/healthz` -- health check with version and uptime
- `handleStats()`: GET `/stats` -- request counters (total, allowed, blocked)
- CLI flags: `--listen`, `--upstream`, `--version` (flags override env vars)

**pcfi.go:** Prompt Control-Flow Integrity detection engine.
- `ProvenanceLevel` (4 levels): System (highest trust) > Developer > User > Retrieved (lowest trust)
- `Segment`: Represents a single prompt message with role, content, and provenance metadata
- `Firewall`: Compiled regex pattern matchers for four threat categories:
  - `roleSwitchPatterns`: Attempts to reassign model identity ("you are now", "act as", "DAN mode")
  - `injectionPatterns`: Attempts to override instructions ("ignore previous", "override system prompt")
  - `delimiterEscapePatterns`: Attempts to break out of content markers ("</system>", "```system")
- `CheckSegment()`: Scans individual message against all patterns
- `Scan()`: Multi-message analysis with privilege escalation detection
- `looksLikeSystemContent()`: Detects lower-trust segments mimicking system instructions

## Patterns

**Error handling:** Explicit errors at package boundaries; firewall violations return structured violation objects.

**Message format:** OpenAI-compatible JSON (role, content, model, messages array).

**Threat detection:** Regex-based lexical analysis; patterns are case-insensitive and compiled once at firewall init.

**Testing:** Table-driven tests for pattern coverage; integration tests use `httptest` for handler verification. 22 tests + 2 benchmarks.

**Provenance mapping:**
- `system` -> ProvenanceSystem
- `developer`, `assistant` -> ProvenanceDeveloper
- `user` -> ProvenanceUser
- `retrieved`, `tool`, `function` -> ProvenanceRetrieved

## Common Tasks

**Add a new threat pattern:**
- Add regex pattern to appropriate list in `pcfi.go` (e.g., `injectionPatterns`)
- Create unit test in `pcfi_test.go` covering the new pattern
- Verify with `make test`

**Add a new endpoint:**
- Add handler method on `server` struct in `main.go`
- Register in `main()` via `mux.HandleFunc()`
- Add integration test in `pcfi_test.go`
