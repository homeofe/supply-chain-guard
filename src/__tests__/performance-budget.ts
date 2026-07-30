/** Keep wall-clock assertions and their test timeouts meaningful under V8 coverage instrumentation. */
export function performanceBudget(milliseconds: number): number {
  return process.env.SCG_VITEST_COVERAGE === "1" ? milliseconds * 5 : milliseconds;
}
