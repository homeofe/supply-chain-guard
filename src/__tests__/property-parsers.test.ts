import { describe, it, expect } from "vitest";
import fc from "fast-check";

import {
  lineAtOffset,
  lineOfNeedle,
  blankXmlComments,
  stripHashComment,
  trimTrailing,
  trimLeading,
  escapeRegExp,
} from "../text-lines.js";
import { parseWorkflow, stripYamlComments } from "../workflow-ast.js";
import { isoToEpoch } from "../../scripts/feed-partition.mjs";
import { stripBase64DataUris } from "../entropy.js";
import { escapeCmdShellArg } from "../install-guard.js";
import {
  hasDownloadExecChain,
  mentionsHostRuntime,
  mentionsHostRuntimePath,
} from "../install-hook-scanner.js";
import { classifyFileSurface } from "../internal-disclosure.js";
import { firstQuotedSlashRef } from "../policy-engine.js";
import { isPythonManifest } from "../python-lockfile-scanner.js";
import { DOWNLOAD_EXEC_MATCHERS, findDownloadExec, writesShellRc } from "../skills-scanner.js";

// Property-based tests for the code that reads attacker-controlled text.
//
// Every scanned manifest, lockfile and workflow is chosen by whoever wrote the
// repository being scanned, so these functions see adversarial input by design.
// The linear-time helpers in text-lines.ts each replaced a regex that went
// quadratic on crafted input, and each doc comment claims "same result as" that
// regex. An example-based test can only check the inputs someone thought of;
// these check the claim on thousands of generated ones, with the old regex as
// the oracle.
//
// The seed is fixed so a CI run is reproducible and a red build always names a
// failing input. To explore beyond it, run with SCG_FC_SEED=<n> (and raise
// SCG_FC_RUNS); a new counterexample then becomes a named regression case here.

const seed = Number(process.env.SCG_FC_SEED ?? 20260925);
const numRuns = Number(process.env.SCG_FC_RUNS ?? 1000);
const params = { seed, numRuns };

/** Text drawn from the characters these parsers actually branch on. */
const parserText = fc.string({
  unit: fc.constantFrom("a", "b", " ", "\t", "\n", "\r", "#", "<", "!", "-", ">", "x", ":"),
  maxLength: 200,
});
/** Anything at all, including astral and control characters. */
const anyText = fc.string({ unit: "binary", maxLength: 300 });

describe("text-lines: linear-time helpers agree with the regexes they replaced", () => {
  it("lineAtOffset equals the naive newline count for every offset", () => {
    fc.assert(
      fc.property(anyText, fc.nat(), (text, n) => {
        const offset = n % (text.length + 1);
        expect(lineAtOffset(text, offset)).toBe(text.slice(0, offset).split("\n").length);
      }),
      params,
    );
  });

  it("lineOfNeedle names the line of the first occurrence, or 1", () => {
    fc.assert(
      fc.property(parserText, parserText, (text, needle) => {
        const idx = text.indexOf(needle);
        const expected = idx < 0 ? 1 : text.slice(0, idx).split("\n").length;
        expect(lineOfNeedle(text, needle)).toBe(expected);
      }),
      params,
    );
  });

  it("blankXmlComments equals the regex it replaced, and preserves length and newlines", () => {
    const oracle = (t: string) => t.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
    fc.assert(
      fc.property(parserText, (text) => {
        const out = blankXmlComments(text);
        expect(out).toBe(oracle(text));
        expect(out.length).toBe(text.length);
        expect([...out].map((c, i) => c === "\n" || text[i] !== "\n")).not.toContain(false);
      }),
      params,
    );
  });

  it("stripHashComment: regression cases the property test found", () => {
    // Shrunk counterexample from the first run of the property below: a "#" in
    // column 0 ended the scan, so the trailing comment after it survived.
    expect(stripHashComment("#\t#")).toBe("#");
    expect(stripHashComment("#a #b")).toBe("#a");
    // Unchanged behaviour, as controls.
    expect(stripHashComment("image: x # pinned")).toBe("image: x");
    expect(stripHashComment("url: https://h/#frag")).toBe("url: https://h/#frag");
    expect(stripHashComment("#")).toBe("#");
  });

  it("stripHashComment equals line.replace(/[ \\t]+#.*$/, '') then trimEnd on space/tab text", () => {
    fc.assert(
      fc.property(
        fc.string({ unit: fc.constantFrom("a", "b", " ", "\t", "#", ":"), maxLength: 120 }),
        (line) => {
          const m = /[ \t]#/.exec(line);
          const expected = m ? line.slice(0, m.index + 1).trimEnd() : line;
          expect(stripHashComment(line)).toBe(expected);
        },
      ),
      params,
    );
  });

  it("trimTrailing and trimLeading equal the anchored regexes they replaced", () => {
    const chars = fc.string({ unit: fc.constantFrom("a", " ", "\t", "\n", ",", ";"), minLength: 1, maxLength: 3 });
    const esc = (s: string) => s.replace(/[\\\]^-]/g, "\\$&");
    fc.assert(
      fc.property(parserText, chars, (text, set) => {
        expect(trimTrailing(text, set)).toBe(text.replace(new RegExp(`[${esc(set)}]+$`), ""));
        expect(trimLeading(text, set)).toBe(text.replace(new RegExp(`^[${esc(set)}]+`), ""));
      }),
      params,
    );
  });
});

describe("workflow parser: total on arbitrary input", () => {
  it("parseWorkflow and stripYamlComments never throw, whatever the text", () => {
    fc.assert(
      fc.property(fc.oneof(anyText, parserText), (text) => {
        expect(() => stripYamlComments(text)).not.toThrow();
        expect(() => parseWorkflow(text)).not.toThrow();
      }),
      params,
    );
  });

  it("stripYamlComments never changes the number of lines", () => {
    fc.assert(
      fc.property(parserText, (text) => {
        expect(stripYamlComments(text).split("\n").length).toBe(text.split("\n").length);
      }),
      params,
    );
  });
});

describe("feed partition dates", () => {
  it("isoToEpoch round-trips every real calendar date", () => {
    fc.assert(
      fc.property(fc.date({ min: new Date("1970-01-01"), max: new Date("2099-12-31"), noInvalidDate: true }), (d) => {
        const iso = d.toISOString().slice(0, 10);
        expect(isoToEpoch(iso)).toBe(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
      }),
      params,
    );
  });

  it("isoToEpoch accepts nothing that is not exactly YYYY-MM-DD, and no rolled-over date", () => {
    // Date-shaped strings with any digits (month 13, day 31 in February, year 0)
    // alongside arbitrary text: random text alone almost never looks like a date.
    const pad = (n: number, w: number) => String(n).padStart(w, "0");
    const dateLike = fc
      .tuple(fc.integer({ min: 0, max: 9999 }), fc.integer({ min: 0, max: 99 }), fc.integer({ min: 0, max: 99 }))
      .map(([y, m, d]) => `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}`);
    fc.assert(
      fc.property(fc.oneof(anyText, dateLike), (text) => {
        const epoch = isoToEpoch(text);
        if (epoch !== null) {
          expect(text).toMatch(/^\d{4}-\d{2}-\d{2}$/);
          expect(new Date(epoch).toISOString().slice(0, 10)).toBe(text);
        }
      }),
      params,
    );
  });
});

// CodeQL js/polynomial-redos rewrites (2026-09-25). Each function below
// replaced a regular expression that was quadratic on the input shape CodeQL
// named, measured at minutes for a crafted 5 MB file. The originals are kept
// here verbatim as the oracle: the rewrite must give the same answer on every
// generated input, built from the tokens the original branches on.

/** Strings drawn from a token list: the characters an expression reacts to. */
const tokens = (list: string[], maxLength = 30) =>
  fc.array(fc.constantFrom(...list), { maxLength }).map((parts) => parts.join(""));

describe("CodeQL ReDoS rewrites agree with the expressions they replaced", () => {
  it("escapeRegExp makes any string match exactly itself", () => {
    fc.assert(
      fc.property(anyText, (text) => {
        expect(new RegExp(`^${escapeRegExp(text)}$`).test(text)).toBe(true);
      }),
      params,
    );
  });

  it("stripBase64DataUris equals the data-URI regex it replaced", () => {
    const OLD = /data:[^;,\s"'`]+;base64,[A-Za-z0-9+/=]+/g;
    const text = tokens(["data:", "image/png", ";base64,", ";", ",", "a", "Z", "9", "=", "+", "/", " ", "\n", '"', "`", "x"]);
    fc.assert(
      fc.property(text, (t) => {
        expect(stripBase64DataUris(t)).toBe(t.replace(OLD, ""));
      }),
      params,
    );
  });

  it("escapeCmdShellArg equals the two backslash regexes it replaced", () => {
    const META = /([()\][%!^"`<>&|;, *?])/g;
    const old = (arg: string) => {
      let escaped = arg.replace(/(\\*)"/g, '$1$1\\"');
      escaped = escaped.replace(/(\\*)$/, "$1$1");
      return `"${escaped}"`.replace(META, "^$1").replace(META, "^$1");
    };
    fc.assert(
      fc.property(tokens(["\\", '"', "a", " ", "&", "%", "b"]), (arg) => {
        expect(escapeCmdShellArg(arg)).toBe(old(arg));
      }),
      params,
    );
  });

  it("hasDownloadExecChain equals the two download/exec regexes it replaced", () => {
    const OLD_A = /(?:curl|wget|fetch).*(?:chmod\s+\+x|exec|spawn|child_process|\.\/|bash|sh\s|node\s)/i;
    const OLD_B = /(?:exec|spawn).*(?:curl|wget|fetch)/i;
    const text = tokens(["curl", "WGET", "fetch", "exec", "Spawn", "chmod", "+x", "sh", "node", "./", "bash", "child_process", " ", "\n", "\r", String.fromCharCode(0x2028), "x"]);
    fc.assert(
      fc.property(text, (t) => {
        expect(hasDownloadExecChain(t)).toBe(OLD_A.test(t) || OLD_B.test(t));
      }),
      params,
    );
  });

  it("mentionsHostRuntime equals HOST_RUNTIME_RE", () => {
    const OLD = /\b(?:openclaw|hermes|claude[-_ ]?code|claude[-_ ]?desktop|cursor|windsurf|cline|roo[-_ ]?code|aider|continue\.dev)\b|after[-_]tool[-_]call|before[-_]tool[-_]call|hook[-_ ]?event|tool[-_ ]?call[-_ ]?message|dispatch-[\w-]*\.(?:js|mjs|cjs)/i;
    const text = tokens(["dispatch-", "DISPATCH-", "a", "-", "_", ".js", ".MJS", ".cjs", ".jsx", ".", " ", "openclaw", "claude code", "after_tool_call", "x"]);
    fc.assert(
      fc.property(text, (t) => {
        expect(mentionsHostRuntime(t)).toBe(OLD.test(t));
      }),
      params,
    );
  });

  it("mentionsHostRuntimePath equals HOST_RUNTIME_PATH_RE", () => {
    const OLD = /node_modules[\\/][^\s'"]*(?:openclaw|hermes)|[~./][\w./-]*\.(?:openclaw|claude|cursor|windsurf|hermes)\b/i;
    const text = tokens(["node_modules/", "node_modules\\", "openclaw", "HERMES", "~", ".", "/", "a", "-", "_", " ", "'", '"', ".claude", ".Cursor", "claudex", "x"]);
    fc.assert(
      fc.property(text, (t) => {
        expect(mentionsHostRuntimePath(t)).toBe(OLD.test(t));
      }),
      params,
    );
  });

  it("classifyFileSurface marks a basename as an example exactly when EXAMPLE_ARTIFACT did", () => {
    const OLD = /(?:^|[./])(?:example|sample|template|tpl)(?:\.[^/]*)?$/i;
    const base = tokens(["tpl", "example", "Sample", "template", ".", "-", "a", "yml", "x"], 12);
    fc.assert(
      fc.property(base, (b) => {
        expect(classifyFileSurface(b) === "example").toBe(OLD.test(b));
      }),
      params,
    );
  });

  it("firstQuotedSlashRef equals the quoted-ref regex it replaced", () => {
    const OLD = /"([^"]+\/[^"]+)"/;
    fc.assert(
      fc.property(tokens(['"', "/", "a", "!", " ", "b"]), (t) => {
        expect(firstQuotedSlashRef(t)).toBe(t.match(OLD)?.[1]);
      }),
      params,
    );
  });

  it("isPythonManifest equals the requirements-basename regex it replaced", () => {
    const OLD = /^(?:[\w.-]*[-_.])?(?:requirements|constraints)(?:[-_.][\w.-]*)?\.txt$/i;
    const base = tokens(["requirements", "REQUIREMENTS", "constraints", "-", "_", ".", "txt", ".txt", ".TXT", "dev", "a", String.fromCharCode(0x212a), String.fromCharCode(0xe9)], 10);
    fc.assert(
      fc.property(base, (b) => {
        const expected = b === "pyproject.toml" || (b.toLowerCase().endsWith(".txt") && OLD.test(b));
        expect(isPythonManifest(b)).toBe(expected);
      }),
      params,
    );
  });

  // The four download-and-execute matchers against the expressions they
  // replace, including WHERE the match starts and WHAT it covers (the text is
  // the finding's evidence). The pipe-chain ones were regexes of this exact
  // form until the 6.3.0 pre-release review measured them quadratic.
  const DOWNLOAD_EXEC_REFERENCE = [
    /\b(?:curl|wget)\b[^\n|]*\|[^\n|]*\b(?:sudo\s+)?(?:bash|sh|zsh|dash)\b/i,
    /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|[^\n|]*\b(?:iex|invoke-expression)\b/i,
    /\b(?:iex|invoke-expression)\s*\(\s*(?:\(?\s*)?(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b/i,
    /\bbase64\s+(?:-d|-D|--decode)\b[^\n|]*\|[^\n|]*\b(?:bash|sh|zsh|dash)\b/i,
  ];
  const unusual = [String.fromCharCode(0x2028), String.fromCharCode(0xa0), String.fromCharCode(0x212a), String.fromCharCode(0x17f), "\r"];

  it("each download-exec matcher returns what its reference expression returns", () => {
    const text = tokens([
      "curl", "wget", "CURL", "iwr", "IRM", "invoke-webrequest", "invoke-restmethod", "iex", "invoke-expression",
      "base64", " -d", " -D", " --decode", "-d", "|", "||", "\n", " ", "  ", "\t", "sudo", "sudo ", "bash", "sh",
      "zsh", "dash", "shx", "x", "_", "-", "(", "((", "1", ...unusual,
    ], 40);
    fc.assert(
      fc.property(text, (t) => {
        DOWNLOAD_EXEC_REFERENCE.forEach((ref, k) => {
          const want = ref.exec(t);
          const got = DOWNLOAD_EXEC_MATCHERS[k]!(t);
          expect(got === null ? null : [got.index, got.text], `${k}: ${JSON.stringify(t)}`)
            .toEqual(want === null ? null : [want.index, want[0]]);
        });
      }),
      params,
    );
  });

  // A narrow alphabet reaches the structural cases (a newline before the
  // pipe, several shell words after it, sudo across lines) in almost every
  // run; the wide alphabet above covers the character classes. The first
  // mutation run showed the wide one alone let three logic cuts pass.
  it("each download-exec matcher agrees with its reference on the pipe structure", () => {
    const text = tokens(["curl", "iwr", "base64 -d", "iex", "sh", "bash", "sudo", " ", "|", "\n", "x"], 10);
    fc.assert(
      fc.property(text, (t) => {
        DOWNLOAD_EXEC_REFERENCE.forEach((ref, k) => {
          const want = ref.exec(t);
          const got = DOWNLOAD_EXEC_MATCHERS[k]!(t);
          expect(got === null ? null : [got.index, got.text], `${k}: ${JSON.stringify(t)}`)
            .toEqual(want === null ? null : [want.index, want[0]]);
        });
      }),
      params,
    );
    // Named cases for the three the first mutation run missed.
    for (const [t, want] of [
      ["curl x\n| sh", null], // a newline before the pipe ends the chain
      ["curl x | sh bash", "curl x | sh bash"], // greedy: the rightmost shell word
      ["curl x | sudo\nbash", "curl x | sudo\nbash"], // sudo\s+ may cross a newline
    ] as const) {
      expect(DOWNLOAD_EXEC_MATCHERS[0]!(t)?.text ?? null, JSON.stringify(t)).toBe(want);
      expect(DOWNLOAD_EXEC_REFERENCE[0]!.exec(t)?.[0] ?? null, JSON.stringify(t)).toBe(want);
    }
  });

  it("findDownloadExec reports the first matcher that matches, as the line loop did", () => {
    const text = tokens(["curl", "iwr", "iex(", "base64 -d", " | ", "sh", "iex", "\n", " ", "x"], 30);
    fc.assert(
      fc.property(text, (t) => {
        const want = DOWNLOAD_EXEC_REFERENCE.map((re) => re.exec(t)).find((m) => m !== null) ?? null;
        const got = findDownloadExec(t);
        expect(got === null ? null : got.text).toEqual(want === null ? null : want[0]);
      }),
      params,
    );
  });

  it("writesShellRc matches exactly the strings the shell-rc expression matched", () => {
    // The expression as v6.2.5 shipped it ([^\s|;&], ">" allowed in the path),
    // and the 6.3.0 intermediate that excluded ">": both must agree.
    const REFERENCE = /(?:>>?|\btee\b(?:\s+-a)?)\s*(?:~|\$HOME|%USERPROFILE%)?[^\s|;&]*\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b/i;
    const INTERMEDIATE = /(?:>>?|\btee\b(?:\s+-a)?)\s*(?:~|\$HOME|%USERPROFILE%)?[^\s|;&>]*\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b/i;
    const text = tokens([
      ">", ">>", "tee", "TEE", "Tee", "xtee", "tee-", " -a", " -A", "-a", " ", "\t", "\n", "~", "$HOME",
      "%USERPROFILE%", "/", "a", "_", "1", "!", ".", ".bashrc", ".ZSHRC", ".bash_profile", ".zprofile",
      ".profile", ".profilex", "bashrc", "|", ";", "&", "x", ...unusual,
    ], 40);
    fc.assert(
      fc.property(text, (t) => {
        const want = REFERENCE.test(t);
        expect(INTERMEDIATE.test(t), JSON.stringify(t)).toBe(want);
        expect(writesShellRc(t), JSON.stringify(t)).toBe(want);
      }),
      params,
    );
    // Narrow alphabet: the operator forms in almost every run.
    const narrow = tokens(["tee", " ", "-a", "~/", ".bashrc", ">", "x", "e", "|", "\n"], 10);
    fc.assert(
      fc.property(narrow, (t) => {
        expect(writesShellRc(t), JSON.stringify(t)).toBe(REFERENCE.test(t));
      }),
      params,
    );
    // Named cases, including the `tee -a` form the first mutation run missed.
    for (const [t, want] of [
      ["echo x | tee -a ~/.bashrc", true],
      ["tee -A\t~/.zshrc", true],
      ["tee -a -a ~/.bashrc", false],
      ["echo x >> ~/.profile", true],
      ["x/tee/.bashrc", true],
      ["attee ~/.bashrc", false],
      ["tee | ~/.bashrc", false],
    ] as const) {
      expect(writesShellRc(t), t).toBe(want);
      expect(REFERENCE.test(t), t).toBe(want);
    }
  });
});
