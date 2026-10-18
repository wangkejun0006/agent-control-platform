export function setupState(catalog) {
  if (!catalog) return { loading: true, ready: false, agents: 0, tools: 0 };
  const agents = catalog.agents.filter(a => a.status === "active").length;
  const tools = catalog.tools.filter(t => t.status === "active").length;
  return { loading: false, ready: agents === catalog.agents.length && agents > 0
    && tools === catalog.tools.length && tools > 0, agents, tools };
}

export function departmentTab(workflow, node) {
  if (!node.accessible || node.upstream_ready === false && node.status === "not_started") return "overview";
  if (workflow.status === "delivered") return "review";
  if (node.status === "not_started") return node.has_documents ? "planning" : "documents";
  if (["needs_input", "awaiting_approval", "plan_approved"].includes(node.status)) return "planning";
  if (["queued", "running", "cancel_requested", "completed"].includes(node.status)) return "execution";
  return "review";
}

export function uniqueChecks(checks) {
  const grouped = new Map();
  for (const check of checks) {
    const previous = grouped.get(check.name);
    grouped.set(check.name, { ...check, passed: check.passed && (previous?.passed ?? true) });
  }
  return [...grouped.values()];
}

// LCS compares authored prose, leaving source manifests and historical bytes intact.
export function proseDiff(before, after, limit = 500) {
  const allBefore = before.split("\n"), allAfter = after.split("\n");
  const a = allBefore.slice(0, limit), b = allAfter.slice(0, limit);
  const matrix = Array.from({ length: a.length + 1 }, () => new Uint16Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--)
    matrix[i][j] = a[i] === b[j] ? matrix[i + 1][j + 1] + 1 : Math.max(matrix[i + 1][j], matrix[i][j + 1]);
  const lines = []; let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) { lines.push({ kind: "same", text: a[i++] }); j++; }
    else if (j < b.length && (i === a.length || matrix[i][j + 1] >= matrix[i + 1][j]))
      lines.push({ kind: "added", text: b[j++] });
    else lines.push({ kind: "removed", text: a[i++] });
  }
  return { lines, added: lines.filter(l => l.kind === "added").length,
    removed: lines.filter(l => l.kind === "removed").length,
    truncated: allBefore.length > limit || allAfter.length > limit };
}
