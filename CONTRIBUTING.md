# Contributing to supply-chain-guard

Thanks for your interest in contributing! This project aims to make supply-chain security accessible to everyone.

## How to Contribute

### Reporting New Malware Patterns

The most valuable contribution is adding new detection patterns. If you discover a new supply-chain attack or malware campaign:

1. Open an issue with the `new-pattern` label
2. Include IOCs (indicators of compromise) if available
3. Reference any public reports or advisories

### Adding Detection Rules

1. Fork the repository
2. Add patterns to `src/patterns.ts` (or the relevant scanner module)
3. Add tests for your new patterns
4. Submit a pull request

Each pattern needs:
- A unique rule ID (e.g., `CATEGORY_DESCRIPTION`)
- A regex pattern
- A description
- A severity level (critical/high/medium/low/info)
- Test coverage (positive + negative cases)

### Adding Correlation Rules

The correlation engine (`src/correlation-engine.ts`) links individual findings into incident clusters. To add a new correlation:

1. Identify 2-3+ rules that together indicate a specific attack chain
2. Add an entry to the `CORRELATION_RULES` array
3. Include an incident name, severity, confidence boost, and narrative
4. Add a test case in `src/__tests__/correlation-engine.test.ts`

### Adding IOCs to the Blocklist

Known indicators of compromise go in `src/ioc-blocklist.ts`:
- C2 domains and IPs
- Malware file hashes (MD5)
- Malicious GitHub accounts
- Compromised npm/PyPI package versions

### Code Contributions

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Run type check: `npm run lint`
6. Commit with a clear message
7. Push and open a PR

### Code Style

- TypeScript strict mode
- No `any` types (use `unknown` and type guards)
- Keep functions focused and testable
- Add JSDoc comments for public APIs
- New findings should include `confidence` and `category` fields (v4.2+)

### Testing

- All new features need tests
- All new patterns need test cases (both positive and negative)
- False-positive tests are valuable (ensure legitimate code isn't flagged)
- Run `npm test` before submitting

### Project Structure

```
src/
  scanner.ts              # Core orchestration
  patterns.ts             # Detection pattern database
  ioc-blocklist.ts        # Known IOC database
  correlation-engine.ts   # Incident clustering
  trust-breakdown.ts      # Trust scoring
  install-hook-scanner.ts # Install script analysis
  dependency-risk-analyzer.ts  # Typosquatting detection
  publishing-anomaly-detector.ts  # npm publish anomalies
  release-scanner.ts      # GitHub release analysis
  github-trust-scanner.ts # Repo trust signals
  github-actions-scanner.ts  # CI/CD attack detection
  dockerfile-scanner.ts   # Container security
  npm-scanner.ts          # npm package analysis
  pypi-scanner.ts         # PyPI package analysis
  cargo-scanner.ts        # Rust/Cargo analysis
  go-scanner.ts           # Go module analysis
  entropy.ts              # Shannon entropy analysis
  lockfile-checker.ts     # Lockfile integrity
  config-scanner.ts       # Package manager configs
  git-scanner.ts          # Git hooks/submodules
  policy-engine.ts        # Policy config, baseline, suppressions
  trust-signals.ts        # Positive trust indicators
  threat-intel.ts         # External IOC feed integration
  risk-engine.ts          # Multi-dimensional risk scoring
  diff-scanner.ts         # Git diff-based incremental scanning
  org-scanner.ts          # Organization-level scanning
  reporter.ts             # Output formatting
  cli.ts                  # CLI entry point
  types.ts                # TypeScript interfaces
  __tests__/              # Test files
```

## Development Setup

```bash
git clone https://github.com/homeofe/supply-chain-guard.git
cd supply-chain-guard
npm install
npm run build
npm test
```

## Questions?

Open an issue or reach out at emre.kohler@elvatis.com.
