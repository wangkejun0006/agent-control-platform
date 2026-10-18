import { describe, expect, it } from "vitest";
import { nextTaskRoute, reviewItems } from "./workbench-review.js";

const node = { accessible: true, department_id: "market_center", name: "市场部门",
  attempt_id: "a1", revision: 2, status: "approved" };
const workflow = { workflow_id: "w1", title: "交付", status: "awaiting_final_review", nodes: [node] };

describe("final review projection", () => {
  it("puts one final review in admin cards/count and routes to its actual form", () => {
    const items = reviewItems([workflow], true);
    expect(items).toHaveLength(1);
    expect(items[0].status).toBe("awaiting_final_review");
    expect(items[0].route).toBe(nextTaskRoute(workflow, node));
    expect(items[0].route).toBe("tasks/w1/final-review/market_center");
  });
  it("does not grant final approval to a department owner or ordinary user", () => {
    expect(reviewItems([workflow], false)).toEqual([]);
  });
  it("removes final review after delivery and preserves department review routes", () => {
    expect(reviewItems([{ ...workflow, status: "delivered" }], true)).toEqual([]);
    const planned = { ...workflow, status: "awaiting_approval", nodes: [{ ...node, status: "awaiting_approval" }] };
    expect(reviewItems([planned], false)[0].route).toBe("tasks/w1/planning/market_center");
    const blocked = { ...planned, status: "blocked", nodes: [{ ...node, status: "blocked" }] };
    expect(reviewItems([blocked], true)).toHaveLength(1);
    expect(reviewItems([blocked], true)[0].route).toBe("tasks/w1/review/market_center");
  });
});
