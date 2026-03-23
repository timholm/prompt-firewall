# prompt-firewall

## Build & Test

- Build: `make build` → compiles to `bin/prompt-firewall`
- Test: `make test` → runs all unit and integration tests
- Clean: `make clean` → removes build artifacts
- Language: Go

## Architecture

Single Go package with two core modules:

**main.go:** HTTP server implementing the PCFI gateway as an OpenAI-compatible middleware.
- `server` struct holds firewall instance and optional upstream reverse proxy
- `handleChatCompletions()`: POST `/v1/chat/completions` — scans messages for violations, blocks (403 Forbidden) if threats detected, forwards allowed requests to upstream LLM
- `handleScan()`: POST `/v1/scan` — lightweight verification endpoint returning verdict without executing
- `messagesToSegments()`: Converts OpenAI-format messages to PCFI Segment objects with inferred provenance
- Server can run in standalone mode (no upstream) or as reverse proxy (UPSTREAM_URL env var)

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

**Error handling:** Explicit errors at package boundaries (URL parsing, JSON decode); firewall violations return structured violation objects (not errors).

**Message format:** OpenAI-compatible JSON (role, content, model, messages array).

**Threat detection:** Regex-based lexical analysis; patterns are case-insensitive and compiled once at firewall init.

**Testing:** Table-driven tests for pattern coverage; integration tests use `httptest` for handler verification.

**Provenance mapping:**
- `system` → ProvenanceSystem
- `developer`, `assistant` → ProvenanceDeveloper
- `user` → ProvenanceUser
- `retrieved`, `tool`, `function` → ProvenanceRetrieved

## Common Tasks

**Add a new threat pattern:**
- Add regex pattern to appropriate list in `pcfi.go` (e.g., `injectionPatterns`)
- Create unit test in `pcfi_test.go` covering the new pattern
- Verify with `make test`

**Extend to new LLM APIs:**
- Modify `messagesToSegments()` to parse alternative message formats
- Map external role names to ProvenanceLevel using `InferProvenance()`
- Update request/response marshaling in `main.go`

**Debug a false positive/negative:**
- Enable logging (already present in HTTP handlers via `log.Printf`)
- Check pattern regex in `pcfi.go` and test coverage in `pcfi_test.go`
- Add test case to verify expected behavior

**Profile performance:**
- Run benchmarks: `go test -bench=. -benchmem ./...`
- Existing benchmarks in `pcfi_test.go` measure scan overhead
