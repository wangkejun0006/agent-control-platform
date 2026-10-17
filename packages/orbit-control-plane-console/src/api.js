const jsonHeaders = {
  "Content-Type": "application/json",
  "X-Orbit-Request": "control-console",
};

const request = async (path, options = {}) => {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const payload = await response.json().catch(() => ({ detail: "invalid_json_response" }));
  if (!response.ok) {
    const error = new Error(typeof payload.detail === "string" ? payload.detail : "request_failed");
    error.status = response.status;
    throw error;
  }
  return payload;
};

const post = (path, body) => request(path, {
  method: "POST",
  headers: jsonHeaders,
  body: JSON.stringify(body),
});

export const api = {
  liveReport: () => request("/v1/showcase/live-report"),
  offlineReport: () => request("/v1/showcase/report"),
  runOfflineDemo: () => post("/v1/showcase/run", {}),
  bootstrap: () => request("/v1/control-console/bootstrap"),
  routes: () => request("/v1/model-routes"),
  routeEvidence: (routeId) => request(`/v1/model-routes/${encodeURIComponent(routeId)}/evidence`),
  audits: () => request("/v1/task-scope-audits"),
  auditDetail: (taskId, revision) => request(`/v1/task-scope-audits/${encodeURIComponent(taskId)}/revisions/${revision}`),
  submitCandidate: (body) => post("/v1/model-route-candidates", body),
  submitObservation: (body) => post("/v1/provider-observations", body),
  reconcileRoute: (routeId, body) => post(`/v1/model-routes/${encodeURIComponent(routeId)}/reconcile`, body),
  decideRoute: (body) => post("/v1/approval-decisions", body),
  revokeRoute: (routeId, body) => post(`/v1/model-routes/${encodeURIComponent(routeId)}/approval-revocations`, body),
  reconcileAudit: (taskId, body) => post(`/v1/task-scope-audits/${encodeURIComponent(taskId)}/reconcile`, body),
};

export const newIdempotencyKey = (prefix) =>
  `${prefix}:${crypto.randomUUID()}`;

