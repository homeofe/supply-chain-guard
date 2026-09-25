import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// A closing code fence takes nothing after it but spaces (CommonMark). On
// 2026-09-25 the README's quick-start block ended in "``` Everything else, ...",
// which cannot close a fence, so GitHub rendered the 135 lines after it as one
// code block: the table of contents, Background, What It Detects and the
// Installation heading. The build and every test stayed green for a day. These
// tests read the published Markdown the way a renderer does.

const ROOT = path.resolve(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8");

interface Walk {
  problems: string[];
  /** Headings a renderer shows, i.e. those outside every fenced block. */
  headings: string[];
}

function walkFences(text: string): Walk {
  const problems: string[] = [];
  const headings: string[] = [];
  let open: { char: string; len: number; line: number } | null = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
    if (open) {
      if (fence && fence[1][0] === open.char && fence[1].length >= open.len) {
        if (fence[2].trim() === "") open = null;
        else {
          problems.push(
            `line ${i + 1} ("${line.trim()}") cannot close the fence opened on line ${open.line}: ` +
              "a closing fence takes no text after it",
          );
        }
      }
      continue;
    }
    // A backtick fence's info string cannot contain a backtick.
    if (fence && !(fence[1][0] === "`" && fence[2].includes("`"))) {
      open = { char: fence[1][0], len: fence[1].length, line: i + 1 };
      continue;
    }
    const heading = /^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$/.exec(line);
    if (heading) headings.push(heading[1]);
  }
  if (open) problems.push(`the fence opened on line ${open.line} never closes`);
  return { problems, headings };
}

/** GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens. */
const slug = (heading: string) =>
  heading.toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");

function publishedMarkdown(): string[] {
  const files = ["README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rel = `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(rel);
      else if (entry.name.endsWith(".md")) files.push(rel);
    }
  };
  walk("docs");
  return files.filter((rel) => fs.existsSync(path.join(ROOT, rel)));
}

describe("walkFences", () => {
  it("reports a closing fence with text after it, as a renderer reads it", () => {
    const { problems, headings } = walkFences("```bash\nx\n``` prose\n\n## Hidden\n```\n");
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/^line 3 .*opened on line 1/);
    expect(headings).toEqual([]);
  });

  it("accepts a shorter fence inside a longer one, and a tilde fence closed by tildes", () => {
    const text = "````md\n```bash\nx\n```\n````\n~~~\n```not a close\n~~~\n## Shown\n";
    expect(walkFences(text)).toEqual({ problems: [], headings: ["Shown"] });
  });

  it("reports a fence that never closes", () => {
    expect(walkFences("# A\n```\ncode\n").problems).toEqual(["the fence opened on line 2 never closes"]);
  });
});

describe("published Markdown", () => {
  it("finds the files it checks", () => {
    const files = publishedMarkdown();
    expect(files).toContain("README.md");
    expect(files.filter((f) => f.startsWith("docs/")).length).toBeGreaterThan(10);
  });

  it("closes every code fence", () => {
    const problems = publishedMarkdown().flatMap((rel) =>
      walkFences(read(rel)).problems.map((p) => `${rel}: ${p}`),
    );
    expect(problems).toEqual([]);
  });

  it("links every README Contents entry to a heading outside a code block", () => {
    const readme = read("README.md");
    const contents = /\n## Contents\n([\s\S]*?)\n## /.exec(readme);
    expect(contents, "README has a Contents section").not.toBeNull();
    const anchors = [...contents![1].matchAll(/\]\(#([^)]+)\)/g)].map((m) => m[1]);
    expect(anchors.length).toBeGreaterThan(10);
    const shown = new Set(walkFences(readme).headings.map(slug));
    expect(anchors.filter((a) => !shown.has(a))).toEqual([]);
  });
});
