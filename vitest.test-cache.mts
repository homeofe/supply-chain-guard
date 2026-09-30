// The per-run directory that stands in for every cache location during tests
// (SCG_CACHE_DIR, LOCALAPPDATA, XDG_CACHE_HOME in vitest.config.mts). One
// definition, so the config and the teardown that removes it cannot drift.
// Keyed on the main vitest process, which evaluates both.
import * as os from "node:os";
import * as path from "node:path";

export const testCacheRoot = path.join(os.tmpdir(), `scg-vitest-cache-${process.pid}`);
