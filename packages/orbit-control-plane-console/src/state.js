export const approvalTone = (status) => ({
  approved: "green",
  rejected: "red",
  revoked: "red",
  not_reviewed: "amber",
}[status] || "slate");

export const healthTone = (status) => ({
  ready: "green",
  blocked: "red",
  not_created: "amber",
  historical: "slate",
}[status] || "slate");

export const stateFracture = (route) =>
  route.approval_status === "approved" && route.eligible !== true;

export const routeCanApprove = (route) =>
  route.approval_status === "not_reviewed" &&
  route.health?.status === "ready" &&
  Boolean(route.health?.snapshot_digest);

export const compactDigest = (digest) =>
  digest ? `${digest.slice(0, 13)}…${digest.slice(-6)}` : "—";

