import { expect, test } from "vitest";

test("stderr fixture", () => {
  console.error("intentional stderr fixture");
  expect(true).toBe(true);
});
