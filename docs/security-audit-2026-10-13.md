# Security audit report - 2026-10-13

## Scope and evidence

An automated review by OpenVuln (zai-org) reported seven findings, all rated
high, against `supply-chain-guard`. The review audited a 6.4.0 snapshot and
compared parts of it with 6.5.2 and 6.5.3. All seven concern how the scanner
starts external tools (`git`, `gh`, `tar`, `bzip2`, `xz`, `unzip`, and the
package manager in `install-guard`) or how it extracted archives.

Each finding was checked against the code of 6.5.5 (`main` at
`7b0f3fc`), not taken over from the report. Six were already fixed in 6.5.2 by
the changes for GHSA-cq59-vmg7-pmqv. One was not, and it was reproduced on the
published 6.5.5 before the fix. Reproductions used harmless stand-in files that
only write a marker; no real malware was used.

Advisory published with this release:

| Advisory | Finding | Summary |
|---|---|---|
| [GHSA-gqpg-9mjx-pv4w](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-gqpg-9mjx-pv4w) | H6 | npx: a tool planted in `node_modules/.bin` of the scanned directory ran during the scan (incomplete fix of GHSA-cq59-vmg7-pmqv) |

## Findings

| ID | Finding | State on 6.5.5 |
|---|---|---|
| H1 | Git provenance ran `git` through a shell with the working directory inside the scanned tree; on Windows a planted `git.bat` or `git.exe` there ran. | Fixed in 6.5.2: `git` is resolved to an absolute path and run without a shell. |
| H2 | `git` and `gh` for clone, history, diff, org and trust checks were started by bare name; on Windows a planted `git.exe` in the current directory ran. | Fixed in 6.5.2: every site goes through `src/safe-exec.ts`. |
| H3 | `tar`, `bzip2` and `xz` for registry package scans were started by bare name. | Fixed in 6.5.2: archives are extracted in-process; only `bzip2` and `xz` decompression still run, through `src/safe-exec.ts`. |
| H4 | `install-guard` ran an `npm.cmd` (or `pnpm.cmd`, `yarn.cmd`, `bun.cmd`) from the current directory on Windows. | Fixed in 6.5.2: the manager is resolved like every other tool. |
| H5 | On Linux and macOS, an empty or relative `PATH` entry made the bare-name lookup search the current directory. | Fixed in 6.5.2: empty and relative entries are skipped. |
| H6 | Started through `npx`, `npm exec` or `npm run`, npm puts `node_modules/.bin` of the start directory and every parent first on `PATH` as absolute entries. The 6.5.2 resolver accepted them, so a tool committed there ran. | **Open on 6.5.5, fixed in 6.5.6** (below). |
| A2-H4 | ZIP extraction on Windows was handed to the system `bsdtar`, which detects the format itself and could extract a tar view that the ZIP checks never saw. | Fixed in 6.5.2: no extractor process; members are written by the scanner exactly as validated, and links are never created. |

The only process starts outside `src/safe-exec.ts` are in `install-guard`, and
both use the path that `resolveExecutable` returned.

## H6 in detail

Reproduced with the published 6.5.5 on Linux (npm 11.19.0, Node 24.21.0). A
checkout contained a committed `node_modules/.bin/git` that wrote a marker and
then handed over to the real `git`:

- `npx supply-chain-guard scan .` started inside the checkout: the planted file
  ran 5 times per scan (four provenance calls and the git history check), and
  the scan finished with exit code 0.
- The same scan with npx started from a neutral directory and the checkout
  passed as a path: 0 runs.
- Calling the planted file directly wrote the marker, so the zero is not a
  broken payload.

The same lookup served `gh`, `bzip2`, `xz` and the `install-guard` package
managers. On Windows the planted file would be `git.exe` or `git.com`.

**Fix.** `resolveExecutable` skips every `PATH` entry that is a
`node_modules/.bin` directory, at any depth, case-insensitively and with either
separator on Windows. The report proposed skipping only the entries npm derives
from the current directory; the broader rule also covers `npm run` started from
a parent directory and programs that embed the library, and none of the tools
the scanner runs is legitimately taken from a `node_modules/.bin`. The cost:
`install-guard` no longer uses a project-local `pnpm` or `yarn` from
`node_modules/.bin`, only an installed one.

## Outside this package: npm runs files from the start directory

Checked in the same setup with npm 11.19.0, before any `supply-chain-guard`
code runs:

- a committed `node_modules/.bin/sh` runs when npx starts the command;
- a committed `node_modules/supply-chain-guard` package (a `package.json` that
  claims the requested version and a `bin` pointing at another script) is run
  by npx instead of the registry package, both for
  `npx -y supply-chain-guard@6.5.5` and for the unversioned name.

This is npm's documented local-first behaviour and no change in this package
can prevent it. The README recommended `npx supply-chain-guard scan .` inside
the checkout, and the MCP guide configured `npx` for agent hosts that start the
server in the workspace. Both now use an installed `supply-chain-guard`, and
npx is described only for a start from outside the scanned directory, with the
reason. Not affected in the first place: the GitHub Action (verified install,
started with `node` directly), the pre-commit hook (pre-commit's own Node
environment), a global install, and the Docker image.

## Verification

- Regression tests in `src/__tests__/safe-exec.test.ts`: the resolver skips
  `node_modules/.bin` entries and still searches look-alike directories, and
  `scan()` and the install guard do not run a tool planted in
  `node_modules/.bin` first on `PATH`. They fail with the new filter removed
  and pass with it restored.
- Full test suite, build and release gates on Linux, and CI on Node 22 and 24.
- The reproduction above repeated against the fixed build.
