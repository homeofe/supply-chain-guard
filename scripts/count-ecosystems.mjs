#!/usr/bin/env node
// Ground-truth floor for the "N ecosystems" claim (aahp.config.json claims ->
// floorCmd). Prints, as a bare integer, the number of declared ecosystems
// (src/ecosystem-coverage.json) for which known-malicious indicators actually
// SHIP in feed.json or data/threat-catalog.jsonl. A matcher with nothing to
// match is not counted: every declared ecosystem is proven format by format in
// src/__tests__/coverage-matrix.test.ts, but "covered" is only claimed where
// there is data. Same split as the generated README list, so they cannot differ.
import { load, ecosystemsWithData } from "./generate-coverage-table.mjs";

const { coverage, bundleValues, catalogValues } = load();
process.stdout.write(String(ecosystemsWithData(coverage, bundleValues, catalogValues).withData.length));
