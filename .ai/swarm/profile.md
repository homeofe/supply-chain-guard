# Swarm review profile: supply-chain-guard

This profile tells an aahp-swarm review what to scrutinize in this tool. It
contains no infrastructure detail and is safe to read publicly.

## Scope

Review the scanner's own correctness and safety, not generic style. Prioritize:

1. Detector and regex bypasses: inputs that evade a rule the scanner claims to
   catch (typosquat, install-script, obfuscation, dependency-confusion).
2. Scan-engine logic gaps: a real signal dropped, mis-ranked, or swallowed by a
   try/catch so a malicious package scores clean.
3. The tool's own shell and filesystem surface: any command built from untrusted
   input, mirroring the clone-path injection fixed in v5.2.38.
4. Output integrity: SARIF and SBOM correctness, and the PR-comment path that
   previously crashed on backticks.
5. Prompt-injection resistance in any text the tool ingests and echoes.

## Verdict expectations

Express every finding against the Scout, Tester, Risk, Verdict roles and the
typed-verdict schema. An ambiguous result must resolve to a typed HOLD state and
must never become a false ALLOW. Set safe_to_commit false for any non-ALLOW state.
