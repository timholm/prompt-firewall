# prompt-firewall

**Language:** go
**Source:** https://arxiv.org/abs/2603.18433
**Estimated lines:** 280

## Problem

LLM APIs and RAG pipelines are vulnerable to prompt injection attacks that override system policies.

## Solution

A lightweight API gateway middleware implementing Prompt Control-Flow Integrity (PCFI). Tags each prompt segment with provenance (system/developer/user/retrieved), applies lexical heuristics and role-switch detection, and enforces hierarchical policy rules with sub-millisecond overhead. Enterprise security teams and LLM API providers buy this as a drop-in defense layer.

## Expected Files

["main.go","pcfi.go","pcfi_test.go","README.md"]
