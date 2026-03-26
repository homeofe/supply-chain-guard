# supply-chain-guard: Next Actions for Incoming Agent

> Priority order. Work top-down.
> Each item should be self-contained so the agent can start without asking questions.
> Blocked tasks go to the bottom. Completed tasks move to "Recently Completed".

---

## Status Summary

| Status | Count |
|--------|-------|
| Ready | 7 |
| Blocked | 0 |
| Done | 10 |

---

## Ready - Work These Next

### T-001: Add solana-monitor unit tests [high]

**Goal:** `src/solana-monitor.ts` (485 lines) has zero test coverage. It handles wallet monitoring, watchlist persistence, and webhook delivery -- all critical paths.

**Context:**
- The module makes real HTTP calls to `https://api.mainnet-beta.solana.com` via `https.request`
- Tests must mock `node:https` to avoid network calls
- Watchlist uses `~/.supply-chain-guard/watchlist.json` for persistence -- tests must use temp dirs
- Webhook delivery sends HTTP POST on alert -- must be mocked

**What to do:**
1. Create `src/__tests__/solana-monitor.test.ts`
2. Mock `node:https` (use `vi.mock` in Vitest)
3. Test `monitorWallet` detects memo instructions containing suspicious URLs
4. Test `monitorWallet` ignores normal transactions (no false positives)
5. Test watchlist load/save/add/remove operations (use `os.tmpdir()` paths)
6. Test webhook alert fires when a C2 address is detected
7. Test `getRecentSignatures` handles RPC errors gracefully
8. Test rate-limit/retry behavior if applicable
9. Test that the baseline is correctly set on first run (no spurious alerts)
10. Aim for 15+ tests

**Files:** `src/solana-monitor.ts`, `src/__tests__/solana-monitor.test.ts`

**Definition of done:**
- [ ] `solana-monitor.test.ts` with 15+ tests, all passing
- [ ] No real network calls in tests
- [ ] `npm test` still passes (all 185 + new tests)
- [ ] DASHBOARD.md updated with new test count

---

### T-002: Add reporter unit tests [high]

**Goal:** `src/reporter.ts` (354 lines) formats output as text, JSON, markdown, and SARIF 2.1.0 -- none of this is tested.

**Context:**
- `formatReport(report, format)` is the main entry point
- SARIF format must be valid SARIF 2.1.0 (has a JSON schema)
- Text format uses ANSI color codes -- strip these in tests for easy assertion
- JSON format must be valid JSON with the expected structure
- Markdown format uses GFM tables

**What to do:**
1. Create `src/__tests__/reporter.test.ts`
2. Build a fixture `ScanReport` with findings of each severity level
3. Test JSON output: parse result, verify structure (findings array, summary, metadata)
4. Test SARIF output: parse result, verify `$schema`, `runs[0].results`, severity mapping
5. Test Markdown output: verify headers, table rows, finding counts
6. Test Text output: verify findings appear (strip ANSI codes)
7. Test empty report (no findings): all formats handle gracefully
8. Test severity-to-SARIF-level mapping: critical/high → error, medium/low → warning, info → note
9. Aim for 15+ tests

**Files:** `src/reporter.ts`, `src/__tests__/reporter.test.ts`

**Definition of done:**
- [ ] `reporter.test.ts` with 15+ tests, all passing
- [ ] SARIF output validated against expected schema structure
- [ ] `npm test` still passes

---

### T-003: Add CLI integration tests [medium]

**Goal:** `src/cli.ts` (420 lines) is the main user-facing entry point and has no automated tests.

**Context:**
- Built with commander, compiled to `dist/cli.js`
- Main commands: `scan <path>`, `watchlist add/remove/list`, `monitor <address>`
- `scan` accepts `--format text|json|markdown|sarif`, `--severity`, `--output`
- Must build first (`npm run build`) before CLI tests can run
- Use `child_process.spawnSync` or Vitest's exec helpers to run the compiled CLI
- Test against fixture directories in `src/__tests__/fixtures/`

**What to do:**
1. Create `src/__tests__/cli.test.ts`
2. Create fixture directories: `fixtures/clean-npm-pkg/` and `fixtures/malicious-npm-pkg/`
3. Test `supply-chain-guard --version` outputs current version
4. Test `supply-chain-guard --help` shows usage
5. Test `supply-chain-guard scan <clean-fixture>` exits 0 with no findings
6. Test `supply-chain-guard scan <malicious-fixture>` exits non-zero with findings
7. Test `--format json` produces valid JSON output
8. Test `--format sarif` produces valid SARIF structure
9. Test `watchlist list` works without error
10. Test unknown command exits with error code

**Files:** `src/cli.ts`, `src/__tests__/cli.test.ts`, `src/__tests__/fixtures/`

**Definition of done:**
- [ ] `cli.test.ts` with 10+ tests, all passing
- [ ] Fixture directories exist with appropriate package.json content
- [ ] `npm test` still passes

---

### T-004: SBOM export (CycloneDX/SPDX) [medium]

**Goal:** Add `--format sbom` output option that emits a CycloneDX 1.5 JSON Software Bill of Materials listing all scanned packages with their detected vulnerabilities.

**Context:**
- CycloneDX 1.5 JSON schema: https://cyclonedx.org/schema/bom-1.5.schema.json
- Required fields: `bomFormat`, `specVersion`, `serialNumber`, `version`, `metadata`, `components`, `vulnerabilities`
- Each finding with severity >= medium maps to a `vulnerabilities` entry
- Each scanned package becomes a `components` entry
- This is increasingly required for enterprise/compliance use cases (NIS2, SSDF)

**What to do:**
1. Add `sbom` to the format union type in `src/types.ts`
2. Add `formatSbom(report: ScanReport): string` to `src/reporter.ts`
3. Map findings to CycloneDX vulnerability objects (id = rule ID, ratings = severity)
4. Map scanned packages to CycloneDX component objects
5. Add `--format sbom` to CLI help text and docs
6. Add tests in `reporter.test.ts` for SBOM output structure
7. Update README with SBOM example

**Files:** `src/reporter.ts`, `src/types.ts`, `src/cli.ts`, `README.md`

---

### T-005: --fail-on severity threshold flag [medium]

**Goal:** Add `--fail-on <severity>` flag to `scan` command so CI pipelines can fail builds when findings exceed a threshold.

**Context:**
- Current behavior: exits 0 on clean, non-zero on any finding
- Desired: `--fail-on high` exits non-zero only if there are high/critical findings
- Useful for tiered pipelines: block on critical/high, warn on medium/low
- Severity order: critical > high > medium > low > info

**What to do:**
1. Add `--fail-on <severity>` option to `scan` command in `src/cli.ts`
2. Filter exit code logic: only non-zero if findings >= threshold severity
3. Add tests in `cli.test.ts` for the flag behavior
4. Update README with example

**Files:** `src/cli.ts`, `README.md`

---

### T-006: Cargo/Go module scanner [low]

**Goal:** Add supply-chain scanning for Rust (Cargo.toml/Cargo.lock) and Go (go.mod/go.sum) dependency files.

**Context:**
- Rust: check Cargo.lock for known malicious crate names, suspicious git dependencies, yanked versions
- Go: check go.sum for known bad modules, direct GitHub dependencies (no proxy), suspicious replace directives
- Pattern library can be extended from existing `src/patterns.ts` approach
- Go and Rust ecosystems have had real supply-chain attacks (e.g. malicious crates mimicking popular ones)

**What to do:**
1. Create `src/cargo-scanner.ts` (scan Cargo.toml + Cargo.lock)
2. Create `src/go-scanner.ts` (scan go.mod + go.sum)
3. Add patterns for known bad crate/module names to `src/patterns.ts`
4. Wire into `src/scanner.ts` central scanner
5. Add test files for both scanners
6. Update README with Cargo/Go examples

---

### T-007: Rate-limit handling in Solana monitor [low]

**Goal:** The Solana RPC endpoint (`api.mainnet-beta.solana.com`) rate-limits aggressive polling. Add exponential backoff and user-configurable rate limiting.

**Context:**
- Current code polls at a fixed interval without backoff on 429/503
- Public RPC rate limit: ~100 req/s, but sustained polling can be blocked
- Should: detect HTTP 429, wait `Retry-After` or exponential backoff, log warning
- Consider adding `--rpc <url>` flag to allow use of private RPC endpoints

**What to do:**
1. Add retry logic with exponential backoff in `src/solana-monitor.ts`
2. Handle HTTP 429 and 503 responses gracefully
3. Add `--rpc <url>` option to `monitor` CLI command
4. Update T-001 tests to cover retry behavior

---

## Recently Completed

| ID | Task | Completed |
|----|------|-----------|
| - | v3.0.0: All features merged to main | 2026-03-26 |
| - | AAHP handoff docs created (all 8 files) | 2026-03-26 |
| - | Stale feature branches deleted | 2026-03-26 |
| - | Dependabot PR #18 merged (picomatch 4.0.4) | 2026-03-26 |
