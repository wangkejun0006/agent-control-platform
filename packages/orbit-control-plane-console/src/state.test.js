import { describe, expect, it } from "vitest";
import {
  compactDigest,
  routeCanApprove,
  stateFracture,
} from "./state.js";

describe("resource state separation", () => {
  it("exposes an approved but unhealthy route as a state fracture", () => {
    expect(stateFracture({ approval_status: "approved", eligible: false })).toBe(true);
  });

  it("does not permit approval before a ready snapshot exists", () => {
    expect(routeCanApprove({ approval_status: "not_reviewed", health: { status: "blocked" } })).toBe(false);
  });

  it("keeps digest identity visible in compact form", () => {
    expect(compactDigest(`sha256:${"a".repeat(64)}`)).toMatch(/^sha256:aaaaaa…aaaaaa$/);
  });
});

