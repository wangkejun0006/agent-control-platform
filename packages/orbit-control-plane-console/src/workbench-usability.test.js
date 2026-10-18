import { describe, expect, it } from "vitest";
import { setupState, departmentTab, proseDiff, uniqueChecks } from "./workbench-usability.js";
import { nextTaskRoute } from "./workbench-review.js";

describe("workbench P1 projections", () => {
  it("does not treat unregistered, suspended, or unread setup as ready", () => {
    expect(setupState(null).ready).toBe(false);
    expect(setupState({ agents: [], tools: [] }).ready).toBe(false);
    const catalog = { agents: [{ status: "active" }], tools: [{ status: "active" }] };
    expect(setupState(catalog).ready).toBe(true);
    expect(setupState({ ...catalog, tools: [{ status: "suspended" }] }).ready).toBe(false);
  });
  it("opens the actionable department stage without implying an upstream grant", () => {
    const node = { accessible: true, status: "not_started", has_documents: true, upstream_ready: true };
    expect(departmentTab({}, node)).toBe("planning");
    expect(departmentTab({}, { ...node, upstream_ready: false })).toBe("overview");
    expect(departmentTab({}, { ...node, has_documents: false })).toBe("documents");
    expect(departmentTab({}, { ...node, status: "running" })).toBe("execution");
    expect(departmentTab({}, { ...node, status: "changes_requested" })).toBe("review");
    const source = { ...node, department_id: "product_center", status: "approved",
      outgoing_handoff: { target_department: "technology_center" } };
    expect(nextTaskRoute({ workflow_id: "w", nodes: [source, { ...node, department_id: "technology_center" }] }, source))
      .toBe("tasks/w/planning/technology_center");
  });
  it("compares repeated lines and actual removed/added prose without modifying inputs", () => {
    const before = "keep\nold\nkeep", after = "keep\nnew\nkeep";
    const diff = proseDiff(before, after);
    expect(diff.added).toBe(1); expect(diff.removed).toBe(1);
    expect(diff.lines.filter(l => l.kind !== "same").map(l => l.text).sort()).toEqual(["new", "old"]);
    expect(before).toBe("keep\nold\nkeep");
    expect(proseDiff(before, before).added).toBe(0);
    expect(proseDiff("a\nb", "a\nb\nc", 2).truncated).toBe(true);
  });
  it("deduplicates labels without hiding any failing independent check", () => {
    expect(uniqueChecks([{ name: "来源", passed: true }, { name: "来源", passed: false },
      { name: "引用", passed: true }])).toEqual([{ name: "来源", passed: false }, { name: "引用", passed: true }]);
  });
});
