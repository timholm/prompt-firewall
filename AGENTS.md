# prompt-firewall

## Overview

Prompt-firewall is a Go-based API gateway middleware that defends language model APIs against prompt injection attacks using Prompt Control-Flow Integrity (PCFI). It analyzes incoming chat requests for injection patterns (role-switch attempts, lexical overrides, delimiter escapes, privilege escalation), tags each message segment with provenance metadata (system/developer/user/retrieved), and blocks suspicious requests before forwarding to the upstream LLM. The implementation provides sub-millisecond scanning overhead using compiled regex patterns and can operate as a drop-in reverse proxy or standalone verification service.

## Quick Start

```bash
# Build the binary
make build

# Run all tests
make test

# Start the server
./bin/prompt-firewall

# Or with upstream LLM
UPSTREAM_URL=https://api.openai.com/v1 ./bin/prompt-firewall
```

## Key Files

- **main.go** — HTTP server with `/v1/chat/completions` and `/v1/scan` endpoints. Converts incoming OpenAI-format requests to Segment objects, invokes firewall scan, and either blocks violations with structured error responses or proxies allowed requests to upstream.

- **pcfi.go** — Core firewall logic. Implements four threat detectors (role-switch, lexical-injection, privilege-escalation, delimiter-escape) using compiled regex patterns. Maintains provenance hierarchy (system > developer > user > retrieved) to enforce hierarchical policy rules.

- **pcfi_test.go** — Test suite covering 20+ individual threat patterns, multi-segment conversation analysis, HTTP handler integration, and performance benchmarks.

- **Makefile** — Build targets: `make build` (compile to bin/), `make test` (run tests), `make clean` (remove artifacts).

## How to Extend

**Add a new threat category:**
- Define a new `ViolationType` constant in `pcfi.go`
- Create a pattern slice (e.g., `newThreatPatterns`) with regex expressions
- Add pattern compilation to `NewFirewall()`
- Implement detection in `CheckSegment()` or `Scan()` (depending on whether it's single-segment or context-aware)
- Add unit tests in `pcfi_test.go` covering expected matches and false negatives

**Support a different LLM API format:**
- Modify `messagesToSegments()` in `main.go` to parse alternative message structures
- Ensure each message maps to a Segment with correct provenance inference
- Update request/response struct definitions to match the target API schema
- Add integration tests for the new format

**Enable custom policy rules:**
- Extend `ScanResult` with policy context (allowlist, custom severity levels)
- Modify `Firewall.Scan()` to apply custom rules after pattern detection
- Pass policy configuration through `server` struct or environment variables

## Testing

**Run all tests:**
```bash
make test
```

**Run tests with verbose output:**
```bash
go test -v ./...
```

**Run benchmarks:**
```bash
go test -bench=. -benchmem ./...
```

**Add a new test:**
- For pattern coverage: add entry to `cases []struct` in test function (e.g., `TestCheckSegment_LexicalInjection`)
- For HTTP handlers: use `httptest.NewRequest()` and `httptest.NewRecorder()` (see `TestHandleScan_Allowed`)
- For multi-segment logic: build a `[]Segment` slice and call `Firewall.Scan()` directly

**Test strategy:**
- Unit tests validate individual threat patterns against known injection vectors
- Integration tests verify HTTP handler behavior and JSON marshaling
- Benchmarks ensure overhead remains sub-millisecond across threat categories
- Table-driven tests enable rapid coverage of pattern variations
