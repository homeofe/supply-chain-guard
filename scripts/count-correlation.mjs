#!/usr/bin/env node
// Ground-truth floor for the "15+" correlation-rule claim (aahp.config.json claims
// -> floorCmd). Prints the number of incidents in src/correlation-engine.ts as a bare
// integer to stdout. Run by aahp check-claims with the node interpreter (no shell).
// Mirrors the historical inline countCorrelationRules().
import { readFileSync } from "node:fs";
import { join } from "node:path";

const txt = readFileSync(join(process.cwd(), "src", "correlation-engine.ts"), "utf8");
process.stdout.write(String([...txt.matchAll(/incident:\s*"[^"]+"/g)].length));
