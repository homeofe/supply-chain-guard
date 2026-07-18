#!/usr/bin/env node
// Ground-truth floor for the "350+" rule/indicator claim (aahp.config.json claims
// -> floorCmd). Prints the count of DISTINCT detection-rule IDs across src/*.ts as a
// bare integer to stdout. Run by aahp check-claims with the node interpreter (no shell,
// path kept inside the project root). Mirrors the historical inline countRuleIds().
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const src = join(process.cwd(), "src");
const ids = new Set();
for (const f of readdirSync(src).filter((n) => n.endsWith(".ts"))) {
  for (const m of readFileSync(join(src, f), "utf8").matchAll(/rule:\s*"([^"]+)"/g)) ids.add(m[1]);
}
process.stdout.write(String(ids.size));
