import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { WORKFLOW_PATTERNS } from "../github-actions-scanner.js";
import { matchPatternInContent } from "../patterns.js";
import { hasBroadUnboundedConsumingGap } from "../regex-complexity.js";
import type { PatternEntry } from "../types.js";

type WorkflowPattern = Omit<PatternEntry, "name"> & { flags?: string };

const broadPatterns = WORKFLOW_PATTERNS.filter((entry) =>
  hasBroadUnboundedConsumingGap(entry.pattern));

function withoutStructuralMatcher(entry: WorkflowPattern): WorkflowPattern {
  return { ...entry, correlatedMatcher: undefined };
}

function absoluteStarts(
  content: string,
  hits: readonly { line: number; match: RegExpMatchArray }[],
): number[] {
  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }
  return hits.map((hit) => lineStarts[hit.line - 1]! + (hit.match.index ?? 0));
}

function expectLegacyParity(entry: WorkflowPattern, content: string): void {
  const flags = entry.flags ?? "i";
  const baseline = matchPatternInContent(
    withoutStructuralMatcher(entry),
    content,
    flags,
  );
  const actual = matchPatternInContent(entry, content, flags);
  const label = `${entry.rule}: ${JSON.stringify(content)}`;

  expect(actual.map((hit) => hit.line), `${label} lines`)
    .toEqual(baseline.map((hit) => hit.line));
  expect(actual.map((hit) => hit.match.index), `${label} starts`)
    .toEqual(absoluteStarts(content, baseline));
  expect(actual.map((hit) => hit.text), `${label} evidence`)
    .toEqual(baseline.map((hit) => hit.text));
  expect(actual.coverage.complete, `${label} coverage`).toBe(true);
  expect(actual.coverage.regexAttempts, `${label} attempts`).toBe(1);
}

const positiveCases = [
  "prefix CURL remote | bash suffix",
  "prefix WGET remote | sh suffix",
  "prefix CURL remote -o payload.sh tail && bash payload.sh",
  "prefix WGET remote -O payload.sh tail && chmod +x payload.sh",
  "prefix ${{ secrets.API_KEY}} tail CURL suffix",
  "prefix CURL tail ${{ secrets.API_KEY}} suffix",
  "prefix ${{ secrets.API_KEY}} tail WGET suffix",
  "prefix WGET tail ${{ secrets.API_KEY}} suffix",
  "prefix BASE64 --decode payload | python suffix",
  "prefix CURL tail --data value ${{ env.TOKEN suffix",
  "prefix WRITE tail .GITHUB\\WORKFLOWS\\injected.yml suffix",
] as const;

const nearMissPrefixes = [
  "curl earlier ",
  "wget earlier ",
  "curl earlier ",
  "wget earlier ",
  "${{ secrets.EARLIER}} no-transport ",
  "curl earlier ",
  "${{ secrets.EARLIER}} no-transport ",
  "wget earlier ",
  "base64 -d earlier ",
  "curl -d earlier ",
  "echo earlier ",
] as const;

const edgeCases: ReadonlyArray<readonly string[]> = [
  [
    "curl x\ry | sh",
    "curl x\u2028y | node",
    "curl x | nope | bash",
    "curl x | bash tail | sh",
  ],
  [
    "wget x\ry | ruby",
    "wget x\u2029y | perl",
    "wget x | nope | sh",
    "wget x | sh tail | bash",
  ],
  [
    "curl\r-o file && sh",
    "curl x -o\rfile && bash",
    "curl -o file\r&& sh",
    "curl -o file && x\rsh",
    "curl one -o first curl two -o second && bash tail sh",
  ],
  [
    "wget\u2028-O file && chmod +x",
    "wget x -O\u2029file && sh",
    "wget -O file\u2028&& sh",
    "wget -O file && x\u2029bash",
    "wget one -O first wget two -O second && sh tail bash",
  ],
  [
    "${{ secrets.A\rB}}curl",
    "${{ secrets.A}} tail\rcurl",
    "${{ secrets.A ${{ secrets.B}} tail curl",
    "${{ secrets.A} tail curl",
  ],
  [
    "curl${{ secrets.A\rB}}",
    "curl\rtail ${{ secrets.A}}",
    "curl tail ${{ secrets.A ${{ secrets.B}}",
    "${{ secrets.OUTER curl ${{ secrets.INNER}}",
    "curl tail ${{ secrets.A}",
  ],
  [
    "${{ secrets.A\u2028B}}wget",
    "${{ secrets.A}} tail\u2028wget",
    "${{ secrets.A ${{ secrets.B}} tail wget",
    "${{ secrets.A} tail wget",
  ],
  [
    "wget${{ secrets.A\u2029B}}",
    "wget\u2029tail ${{ secrets.A}}",
    "wget tail ${{ secrets.A ${{ secrets.B}}",
    "${{ secrets.OUTER wget ${{ secrets.INNER}}",
    "wget tail ${{ secrets.A}",
  ],
  [
    "base64 -d\r|sh",
    "base64 -d x\r|sh",
    "base64 --decode x | nope | bash",
    "base64 -d one | sh tail | python",
  ],
  [
    "curl x\r-d y ${{ secrets.A",
    "curl x '-d y ${{ secrets.A",
    "curl -d x 'tail ${{ secrets.A",
    "curl --data-raw x ${{ env.A tail ${{ secrets.B",
  ],
  [
    "echo x\r.github/workflows/a.yml",
    "write x\u2028.github/workflows/a.yml",
    "cat x .github/workflows/a/ tail .github/workflows/b/",
    "precho x .github/workflows/a/",
  ],
] as const;

describe("GitHub Actions broad-gap structural matchers", () => {
  it("wires every broad workflow regex to an exact structural matcher", () => {
    expect(broadPatterns).toHaveLength(11);
    expect(
      broadPatterns.every((entry) => typeof entry.correlatedMatcher === "function"),
    ).toBe(true);
    expect(positiveCases).toHaveLength(broadPatterns.length);
    expect(nearMissPrefixes).toHaveLength(broadPatterns.length);
    expect(edgeCases).toHaveLength(broadPatterns.length);
  });

  it("preserves minimized legacy start, endpoint, barrier, and line semantics", () => {
    for (let index = 0; index < broadPatterns.length; index++) {
      const entry = broadPatterns[index]!;
      const positive = positiveCases[index]!;
      const prefix = nearMissPrefixes[index]!;
      const variants = [
        positive,
        `noise ${positive} tail`,
        `${positive} tail ${positive}`,
        `${prefix}${positive}`,
        `clean\n${positive}\n${positive}`,
        ...edgeCases[index]!,
      ];

      for (const content of variants) expectLegacyParity(entry, content);
    }
  });

  it("preserves the report-visible prefix for a long greedy match", () => {
    const entry = broadPatterns[2]!;
    const content = `curl ${"x".repeat(512)} -o payload ${"y".repeat(512)} && bash`;
    const baseline = matchPatternInContent(
      withoutStructuralMatcher(entry),
      content,
      entry.flags ?? "i",
    );
    const actual = matchPatternInContent(entry, content, entry.flags ?? "i");

    expect(actual).toHaveLength(1);
    expect(actual[0]!.text.slice(0, 120)).toBe(baseline[0]!.text.slice(0, 120));
    expect(actual[0]!.text.length).toBeLessThanOrEqual(240);
  });

  it(
    "fully evaluates a concrete 5 MiB repeated-prefix near miss for every broad rule",
    { timeout: 30_000 },
    () => {
      const units = [
        "curl remote ",
        "wget remote ",
        "curl -o payload ",
        "wget -O payload ",
        "${{ secrets.A}} x ",
        "curl x ",
        "${{ secrets.A}} x ",
        "wget x ",
        "base64 -d payload ",
        "curl -d value ",
        "echo value ",
      ] as const;
      expect(units).toHaveLength(broadPatterns.length);

      const fiveMiB = 5 * 1024 * 1024;
      const started = performance.now();
      for (let index = 0; index < broadPatterns.length; index++) {
        const entry = broadPatterns[index]!;
        const unit = units[index]!;
        const content = unit
          .repeat(Math.ceil(fiveMiB / unit.length))
          .slice(0, fiveMiB);
        const found = matchPatternInContent(entry, content, entry.flags ?? "i");

        expect(found, `${entry.rule} near miss`).toEqual([]);
        expect(found.coverage.complete, entry.rule).toBe(true);
        expect(found.coverage.regexAttempts, entry.rule).toBe(1);
      }
      expect(performance.now() - started).toBeLessThan(15_000);
    },
  );
});
