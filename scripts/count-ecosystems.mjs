#!/usr/bin/env node
// Ground-truth floor for the "N ecosystems" claim (aahp.config.json claims ->
// floorCmd). Prints the number of ecosystems declared in
// src/ecosystem-coverage.json as a bare integer. Every declared ecosystem is
// proven format by format in src/__tests__/coverage-matrix.test.ts, so the
// advertised number can never exceed what a real scan has been shown to match.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const coverage = JSON.parse(readFileSync(join(process.cwd(), "src", "ecosystem-coverage.json"), "utf8"));
process.stdout.write(String(coverage.ecosystems.length));
