import { departmentTab } from "./workbench-usability.js";
// One projection drives review cards, badges, and final-review navigation.
export function finalReviewRoute(workflow) {
  return `tasks/${workflow.workflow_id}/final-review/market_center`;
}

export function nextTaskRoute(workflow, node) {
  if (workflow.status === "awaiting_final_review") return finalReviewRoute(workflow);
  const next = node.outgoing_handoff
    ? workflow.nodes.find(n => n.department_id === node.outgoing_handoff.target_department) : null;
  const target = next || node;
  return `tasks/${workflow.workflow_id}/${departmentTab(workflow, target)}/${target.department_id}`;
}

export function reviewItems(workflows, isAdmin) {
  return workflows.flatMap(workflow => {
    if (workflow.status === "awaiting_final_review") return isAdmin ? [{
      key: `final:${workflow.workflow_id}`, workflow, status: "awaiting_final_review",
      description: "最终交付审核 · 三部门当前版本已批准", route: finalReviewRoute(workflow),
    }] : [];
    if (workflow.status === "delivered") return [];
    return workflow.nodes.filter(n => n.accessible
      && ["awaiting_approval", "awaiting_review", "blocked"].includes(n.status)).map(node => ({
      key: node.attempt_id, workflow, status: node.status,
      description: `${node.name} · v${node.revision} · ${node.next_action}`,
      route: `tasks/${workflow.workflow_id}/${node.status === "awaiting_approval" ? "planning" : "review"}/${node.department_id}`,
    }));
  });
}
