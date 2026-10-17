import { createHash } from "node:crypto";
import { access, lstat, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML, { parseDocument } from "yaml";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const toolkitRoot = path.resolve(moduleDir, "..");
const defaultContractBundleRoot = path.join(
  toolkitRoot,
  "contract-bundles",
  "contract-v0.1.0-alpha.2"
);
const blueprintSchemaPath = path.join(toolkitRoot, "schemas", "agent-package-blueprint.schema.json");
const runtimeAssessmentBlueprintSchemaPath = path.join(
  toolkitRoot,
  "schemas",
  "runtime-assessment-blueprint.schema.json"
);
const requestSchemaId = "urn:company-ai-os:schema:agent-scaffold-request:0.1";
const runtimeAssessmentSchemaId =
  "urn:company-ai-os:schema:runtime-selection-assessment:0.1";
const expectedKinds = new Map([
  ["AgentDefinition", "urn:company-ai-os:schema:agent-definition:0.1"],
  ["AgentBinding", "urn:company-ai-os:schema:agent-binding:0.1"],
  ["AgentCapabilityProfile", "urn:company-ai-os:schema:agent-capability-profile:0.1"],
  ["AgentRegistryRecord", "urn:company-ai-os:schema:agent-registry:0.3"],
  ["AgentReleaseManifest", "urn:company-ai-os:schema:agent-release-manifest:0.1"]
]);
const forbiddenKey = /^(?:password|passwd|api[_-]?key|credential[_-]?value|secret[_-]?value|token[_-]?value|database[_-]?dsn|nas[_-]?path|filesystem[_-]?path)$/i;
const forbiddenValue = /(?:smb|nfs|file):\/\/|(?:^|[\s"'=(])\/(?!\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*|[A-Za-z]:\\/;

export function sha256(source) {
  return `sha256:${createHash("sha256").update(source).digest("hex")}`;
}

export function assertSafeRelative(relativePath) {
  if (
    typeof relativePath !== "string" ||
    relativePath.length === 0 ||
    path.isAbsolute(relativePath) ||
    relativePath.split(/[\\/]/).includes("..") ||
    relativePath.includes("\\")
  ) {
    throw new Error(`unsafe_relative_path:${relativePath}`);
  }
  return relativePath;
}

export function parseYamlStrict(source, location = "yaml") {
  const errors = [];
  if (/^\s*<<\s*:/m.test(source)) errors.push("yaml_merge_key");
  if (/(?:^|\s)&[A-Za-z0-9_-]+(?:\s|$)/m.test(source)) errors.push("yaml_anchor");
  if (/(?:^|\s)\*[A-Za-z0-9_-]+(?:\s|$)/m.test(source)) errors.push("yaml_alias");
  if (/^\s*[^#\n]*![A-Za-z][A-Za-z0-9_-]*/m.test(source)) errors.push("yaml_custom_tag");
  const document = parseDocument(source, {
    uniqueKeys: true,
    merge: false,
    maxAliasCount: 0,
    prettyErrors: true
  });
  if (document.errors.length > 0) {
    errors.push(...document.errors.map((error) => `${location}:${error.message}`));
  }
  if (errors.length > 0) throw new Error([...new Set(errors)].join(","));
  return document.toJS({ maxAliasCount: 0 });
}

export function collectSafetyErrors(value, codes = new Set()) {
  if (Array.isArray(value)) {
    value.forEach((item) => collectSafetyErrors(item, codes));
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (forbiddenKey.test(key)) codes.add("unsafe_key");
      collectSafetyErrors(item, codes);
    }
  } else if (typeof value === "string" && forbiddenValue.test(value)) {
    codes.add("unsafe_value");
  }
  return codes;
}

function yamlSource(value) {
  return YAML.stringify(value, { indent: 2, lineWidth: 0, defaultStringType: "PLAIN" });
}

async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function assertNoSymlinkPath(root, relativePath) {
  let cursor = path.resolve(root);
  for (const segment of assertSafeRelative(relativePath).split("/")) {
    cursor = path.join(cursor, segment);
    if (!(await exists(cursor))) continue;
    if ((await lstat(cursor)).isSymbolicLink()) throw new Error(`symlink_path_forbidden:${relativePath}`);
  }
}

async function loadJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function assertNoSafetyErrors(value, name) {
  const errors = [...collectSafetyErrors(value)];
  if (errors.length > 0) throw new Error(`${name}:${errors.join(",")}`);
}

function sameRef(left, right) {
  return left?.id === right?.id && left?.version === right?.version && left?.digest === right?.digest;
}

function unique(items) {
  return [...new Set(items)];
}

function exactSet(left, right) {
  return (
    left.length === right.length &&
    left.every((item) => right.includes(item)) &&
    right.every((item) => left.includes(item))
  );
}

export function deriveRuntimeConstraints(definition, binding, request) {
  const definitionTools = definition.spec.permission_requests.tools.flatMap((item) =>
    item.operations.map((operation) => `${item.request_name}:${operation}`)
  );
  const definitionData = definition.spec.permission_requests.data.flatMap((item) =>
    item.operations.map((operation) => `${item.request_name}:${operation}`)
  );
  const agentOperations = definition.spec.permission_requests.agents.rules.map(
    (item) => item.operation
  );
  const memoryClasses = definition.spec.memory.allowed_classes;
  const requestedClassifications = request.spec.business_requirements.data_classifications;
  const bindingClassifications = binding.spec.environment.allowed_data_classifications;
  const modelClassifications = definition.spec.model_requirements.allowed_data_classifications;
  const dataClassifications = requestedClassifications.filter(
    (item) => bindingClassifications.includes(item) && modelClassifications.includes(item)
  );
  const requiredHardGates = [
    "exact_revision",
    "license_review",
    "binding_conformance",
    "idempotency",
    "cancel",
    "timeout",
    "audit_correlation",
    "local_environment_compatibility",
    "resource_fit"
  ];
  const requiredProfiles = ["core_dispatch"];
  if (request.spec.environment.isolation === "container") {
    requiredHardGates.push("container_isolation");
    requiredProfiles.push("isolated_workload");
  }
  if (definitionTools.length > 0) {
    requiredHardGates.push("tool_interception");
    requiredProfiles.push("tool_data_enforced");
  }
  if (definitionData.length > 0) {
    requiredHardGates.push("data_access_enforcement");
    if (!requiredProfiles.includes("tool_data_enforced")) requiredProfiles.push("tool_data_enforced");
  }
  if (agentOperations.length > 0) {
    requiredHardGates.push("agent_interaction_enforcement");
    requiredProfiles.push("delegation_spawn");
  }
  if (memoryClasses.length > 0) requiredHardGates.push("memory_isolation");
  if (definition.spec.model_requirements.usage !== "forbidden") {
    requiredHardGates.push("model_route_compatibility");
  }
  return {
    model_usage: definition.spec.model_requirements.usage,
    model_capabilities: [...definition.spec.model_requirements.capabilities].sort(),
    tool_operations: [...definitionTools].sort(),
    data_operations: [...definitionData].sort(),
    agent_operations: [...new Set(agentOperations)].sort(),
    memory_classes: [...memoryClasses].sort(),
    data_classifications: [...dataClassifications].sort(),
    execution_location: request.spec.environment.execution_location,
    isolation: request.spec.environment.isolation,
    sandbox_filesystem: binding.spec.sandbox.filesystem,
    sandbox_network: binding.spec.sandbox.network,
    workspace_mode: binding.spec.workspace.mode,
    max_tool_calls: binding.spec.resource_limits.max_tool_calls,
    max_concurrency: binding.spec.resource_limits.max_concurrency,
    max_autonomy: definition.spec.max_autonomy,
    required_hard_gates: requiredHardGates,
    required_conformance_profiles: requiredProfiles
  };
}

function findArtifact(release, schemaId) {
  const item = release.artifacts.schemas.find((candidate) => candidate.schema_id === schemaId);
  if (!item) throw new Error(`released_schema_missing:${schemaId}`);
  return item;
}

function findBundleSchema(lock, schemaId, section) {
  const items = section === "authoring_draft.schemas"
    ? lock.authoring_draft.schemas
    : lock[section];
  const item = items.find((candidate) => candidate.schema_id === schemaId);
  if (!item) throw new Error(`contract_bundle_schema_missing:${schemaId}`);
  return item;
}

async function loadBundleSchema(bundle, schemaId, section = "released_schemas") {
  const item = findBundleSchema(bundle.lock, schemaId, section);
  const relativePath = assertSafeRelative(item.bundle_path);
  await assertNoSymlinkPath(bundle.root, relativePath);
  const source = await readFile(path.join(bundle.root, relativePath));
  if (sha256(source) !== item.sha256) {
    throw new Error(`contract_bundle_schema_digest_mismatch:${schemaId}`);
  }
  const schema = JSON.parse(source.toString("utf8"));
  if (schema.$id !== schemaId) throw new Error(`contract_bundle_schema_id_mismatch:${schemaId}`);
  return { item, source, schema };
}

export async function verifyContractBundle(contractBundle) {
  const root = path.resolve(contractBundle ?? defaultContractBundleRoot);
  const lockSource = await readFile(path.join(root, "bundle-lock.json"));
  const manifestSource = await readFile(path.join(root, "manifest.json"));
  const lock = JSON.parse(lockSource.toString("utf8"));
  const release = JSON.parse(manifestSource.toString("utf8"));
  if (lock.lock_version !== "orbit.contract-consumer-bundle/1") {
    throw new Error("contract_bundle_lock_version_invalid");
  }
  if (sha256(manifestSource) !== lock.authority.release_manifest_sha256) {
    throw new Error("contract_bundle_manifest_digest_mismatch");
  }
  if (
    release.release_id !== lock.authority.contract_release_id ||
    release.source_revision.tag !== lock.authority.contract_git_tag
  ) {
    throw new Error("contract_bundle_release_identity_mismatch");
  }
  if (lock.authoring_draft.status !== "draft_non_authoritative") {
    throw new Error("authoring_bundle_status_invalid");
  }
  for (const item of lock.released_schemas) {
    const artifact = findArtifact(release, item.schema_id);
    if (artifact.sha256 !== item.sha256) {
      throw new Error(`contract_bundle_release_digest_mismatch:${item.schema_id}`);
    }
    await loadBundleSchema({ root, lock }, item.schema_id);
  }
  for (const item of lock.authoring_draft.schemas) {
    await loadBundleSchema({ root, lock }, item.schema_id, "authoring_draft.schemas");
  }
  return { root, lock, lockSource, release, manifestSource };
}

async function loadContext(options) {
  const bundle = await verifyContractBundle(options.contractBundle);
  const targetRoot = path.resolve(options.targetRoot);
  const targetLockPath = path.resolve(options.targetLock);
  const targetLockRelative = path.relative(targetRoot, targetLockPath);
  assertSafeRelative(targetLockRelative);
  const requestPath = path.resolve(options.request);
  const blueprintPath = path.resolve(options.blueprint);
  const requestSource = await readFile(requestPath, "utf8");
  const blueprintSource = await readFile(blueprintPath, "utf8");
  const request = parseYamlStrict(requestSource, "AgentScaffoldRequest");
  const blueprint = parseYamlStrict(blueprintSource, "AgentPackageBlueprint");
  assertNoSafetyErrors(request, "request");
  assertNoSafetyErrors(blueprint, "blueprint");

  const commonSchema = (await loadBundleSchema(
    bundle,
    "urn:company-ai-os:schema:agent-common:0.1"
  )).schema;
  const requestSchema = (await loadBundleSchema(
    bundle,
    requestSchemaId,
    "authoring_draft.schemas"
  )).schema;
  const blueprintSchema = await loadJson(blueprintSchemaPath);
  const preflightAjv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(preflightAjv);
  preflightAjv.addSchema(commonSchema);
  preflightAjv.addSchema(requestSchema);
  preflightAjv.addSchema(blueprintSchema);
  const validateRequest = preflightAjv.getSchema(requestSchemaId);
  const validateBlueprint = preflightAjv.getSchema(blueprintSchema.$id);
  if (!validateRequest(request)) throw new Error(`request_schema_invalid:${preflightAjv.errorsText(validateRequest.errors)}`);
  if (!validateBlueprint(blueprint)) throw new Error(`blueprint_schema_invalid:${preflightAjv.errorsText(validateBlueprint.errors)}`);
  if (request.spec.generation_policy.runtime_execution !== "forbidden" || request.spec.generation_policy.git_mutation !== "forbidden") {
    throw new Error("authoring_policy_must_forbid_runtime_and_git");
  }
  if (
    request.spec.target.target_repository_ref.id !== blueprint.spec.target_id ||
    (request.spec.generation_scope === "agent_release" && blueprint.spec.packages.length !== 1)
  ) {
    throw new Error("authoring_target_scope_mismatch");
  }

  const releaseId = request.spec.contract_source.release_id;
  const releaseSource = bundle.manifestSource;
  const release = bundle.release;
  if (sha256(releaseSource) !== request.spec.contract_source.manifest_digest) throw new Error("release_manifest_digest_mismatch");
  if (
    release.release_id !== releaseId ||
    release.contract_api_version !== request.spec.contract_source.contract_api_version ||
    release.contract_version !== request.spec.contract_source.contract_version
  ) throw new Error("release_identity_mismatch");
  const resolvedCommit = bundle.lock.authority.contract_git_commit;
  if (resolvedCommit !== request.spec.contract_source.git_commit) throw new Error("release_git_commit_mismatch");

  for (const lock of request.spec.contract_source.schema_locks) {
    if (findArtifact(release, lock.schema_id).sha256 !== lock.digest) throw new Error(`request_schema_lock_mismatch:${lock.schema_id}`);
  }
  for (const schemaId of blueprint.spec.required_schema_ids) {
    const artifact = findArtifact(release, schemaId);
    const { source } = await loadBundleSchema(bundle, schemaId);
    if (sha256(source) !== artifact.sha256) throw new Error(`company_schema_worktree_mismatch:${schemaId}`);
  }

  const targetLockSource = await readFile(targetLockPath);
  const targetLock = JSON.parse(targetLockSource.toString("utf8"));
  if (
    targetLock.authority?.git_tag !== release.source_revision.tag ||
    targetLock.authority?.git_commit !== resolvedCommit ||
    targetLock.authority?.contract_api_version !== release.contract_api_version ||
    targetLock.authority?.contract_version !== release.contract_version
  ) throw new Error("target_contract_lock_mismatch");
  for (const item of targetLock.schemas) {
    const mirrorSource = await readFile(path.join(targetRoot, assertSafeRelative(item.mirror_path)));
    if (sha256(mirrorSource) !== item.sha256) throw new Error(`target_schema_mirror_mismatch:${item.schema_id}`);
  }
  return {
    bundle,
    targetRoot,
    targetLockPath,
    targetLockRelative,
    requestPath,
    blueprintPath,
    requestSource,
    blueprintSource,
    request,
    blueprint,
    release,
    resolvedCommit,
    targetLock,
    targetLockSource
  };
}

async function buildArtifacts(context) {
  const { bundle, targetRoot, request, blueprint, release } = context;
  const schemaSources = new Map();
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  for (const schemaId of blueprint.spec.required_schema_ids) {
    const artifact = findArtifact(release, schemaId);
    const { source } = await loadBundleSchema(bundle, schemaId);
    schemaSources.set(schemaId, { source, artifact });
    ajv.addSchema(JSON.parse(source.toString("utf8")));
  }

  const desired = new Map();
  const expandedLock = structuredClone(context.targetLock);
  for (const schemaId of blueprint.spec.required_schema_ids) {
    const { source, artifact } = schemaSources.get(schemaId);
    let item = expandedLock.schemas.find((candidate) => candidate.schema_id === schemaId);
    if (!item) {
      item = {
        upstream_path: artifact.path,
        mirror_path: `${path.posix.dirname(context.targetLockRelative)}/schemas/${path.basename(artifact.path)}`,
        schema_id: schemaId,
        sha256: artifact.sha256
      };
      expandedLock.schemas.push(item);
    }
    if (item.sha256 !== artifact.sha256 || item.upstream_path !== artifact.path) throw new Error(`target_lock_schema_conflict:${schemaId}`);
    desired.set(assertSafeRelative(item.mirror_path), source);
  }
  desired.set(context.targetLockRelative, Buffer.from(`${JSON.stringify(expandedLock, null, 2)}\n`));
  desired.set(assertSafeRelative(blueprint.spec.blueprint_target_path), Buffer.from(context.blueprintSource));

  const packageSummaries = [];
  for (const item of blueprint.spec.packages) {
    const definitionPath = path.join(targetRoot, assertSafeRelative(item.definition_path));
    const bindingPath = path.join(targetRoot, assertSafeRelative(item.binding_path));
    const definitionSource = await readFile(definitionPath);
    const bindingSource = await readFile(bindingPath);
    const definition = parseYamlStrict(definitionSource.toString("utf8"), item.definition_path);
    const binding = parseYamlStrict(bindingSource.toString("utf8"), item.binding_path);
    assertNoSafetyErrors(definition, item.definition_path);
    assertNoSafetyErrors(binding, item.binding_path);
    for (const [value, source] of [[definition, definitionSource], [binding, bindingSource]]) {
      const schemaId = expectedKinds.get(value.kind);
      const validate = ajv.getSchema(schemaId);
      if (!validate?.(value)) throw new Error(`${value.kind}_schema_invalid:${ajv.errorsText(validate?.errors)}`);
      if (value.kind === "AgentBinding" && value.spec.definition_ref.digest !== sha256(definitionSource)) throw new Error(`binding_definition_digest_mismatch:${item.package_id}`);
    }
    if (binding.spec.definition_ref.id !== definition.metadata.agent_id || binding.spec.definition_ref.version !== definition.metadata.version) {
      throw new Error(`binding_definition_identity_mismatch:${item.package_id}`);
    }
    if (request.spec.target.agent_target?.agent_id !== definition.metadata.agent_id) {
      throw new Error(`request_agent_target_mismatch:${item.package_id}`);
    }

    const definitionRef = {
      id: definition.metadata.agent_id,
      version: definition.metadata.version,
      digest: sha256(definitionSource)
    };
    const bindingRef = {
      id: binding.metadata.binding_id,
      version: binding.metadata.version,
      digest: sha256(bindingSource)
    };
    const capability = {
      api_version: "company-ai-os/v1alpha1",
      kind: "AgentCapabilityProfile",
      metadata: {
        profile_id: item.capability.profile_id,
        agent_id: definition.metadata.agent_id,
        version: definition.metadata.version,
        status: "draft",
        evidence_status: "synthetic",
        synthetic_only: true
      },
      spec: {
        definition_ref: definitionRef,
        visibility: item.capability.visibility,
        interfaces: item.capability.interfaces.map((entry) => ({
          interface_id: entry.interface_id,
          capability: entry.capability,
          input_contract_refs: entry.input_contract_refs,
          output_contract_refs: entry.output_contract_refs ?? definition.spec.output_contract_refs,
          invocation_modes: entry.invocation_modes,
          side_effect: entry.side_effect,
          allowed_data_classifications: entry.allowed_data_classifications,
          requires_human_approval: entry.requires_human_approval,
          required_model_capabilities: entry.required_model_capabilities ?? definition.spec.model_requirements.capabilities
        })),
        limitations: item.capability.limitations
      }
    };
    const capabilityValidate = ajv.getSchema(expectedKinds.get(capability.kind));
    if (!capabilityValidate(capability)) throw new Error(`capability_schema_invalid:${ajv.errorsText(capabilityValidate.errors)}`);
    const capabilitySource = Buffer.from(yamlSource(capability));
    const capabilityRef = { id: capability.metadata.profile_id, version: capability.metadata.version, digest: sha256(capabilitySource) };

    const registry = {
      api_version: "company-ai-os/v1alpha1",
      kind: "AgentRegistryRecord",
      metadata: {
        record_id: item.registry.record_id,
        agent_id: definition.metadata.agent_id,
        status: "draft",
        evidence_status: "synthetic",
        synthetic_only: true,
        created_at: blueprint.metadata.artifact_time,
        updated_at: blueprint.metadata.artifact_time
      },
      spec: {
        definition_ref: definitionRef,
        binding_refs: [bindingRef],
        owner_role_ref: binding.spec.owner.primary_role_ref,
        hierarchy_node_ref: binding.spec.hierarchy.agent_node_ref,
        approval_policy_refs: binding.spec.approval_policy_refs,
        audit_policy_ref: binding.spec.audit_policy_ref,
        retirement_policy_ref: item.registry.retirement_policy_ref,
        change_reason: item.registry.change_reason
      }
    };
    const registryValidate = ajv.getSchema(expectedKinds.get(registry.kind));
    if (!registryValidate(registry)) throw new Error(`registry_schema_invalid:${ajv.errorsText(registryValidate.errors)}`);
    const registrySource = Buffer.from(yamlSource(registry));

    const modelNotRequired = definition.spec.model_requirements.usage === "forbidden";
    const releaseManifest = {
      api_version: "company-ai-os/v1alpha1",
      kind: "AgentReleaseManifest",
      metadata: {
        release_id: item.release.release_id,
        agent_id: definition.metadata.agent_id,
        version: definition.metadata.version,
        status: "draft",
        evidence_status: "synthetic",
        synthetic_only: true,
        created_at: blueprint.metadata.artifact_time
      },
      spec: {
        registry_ref: { id: registry.metadata.record_id, schema_version: "0.3", digest: sha256(registrySource) },
        definition_ref: definitionRef,
        binding_refs: [bindingRef],
        capability_profile_refs: [capabilityRef],
        model_route_refs: binding.spec.model_route_refs,
        model_selection: { status: modelNotRequired ? "not_required" : "pending", selected_route_refs: [], decision_ref: null },
        runtime_realization_refs: [],
        runtime_selection: {
          status: "pending",
          candidates: item.release.runtime_candidates.map((candidate) => ({
            ...candidate,
            realization_refs: [],
            capability_report_refs: []
          })),
          selected_runtime_family: null,
          selected_realization_refs: [],
          decision_ref: null
        },
        template_refs: [],
        policy_refs: unique([
          ...binding.spec.approval_policy_refs,
          binding.spec.audit_policy_ref,
          definition.spec.lifecycle.review_policy_ref
        ]),
        evaluation_suite_refs: definition.spec.evaluation.suite_refs,
        evaluation_report_refs: [],
        compatibility: {
          contract_api_version: "company-ai-os/v1alpha1",
          minimum_control_plane_revision_ref: item.release.minimum_control_plane_revision_ref,
          adapter_profile_ref: item.release.adapter_profile_ref
        },
        release_gate: {
          policy_ref: item.release.release_gate_policy_ref,
          required_evidence_refs: item.release.required_evidence_refs,
          approval_decision_refs: []
        }
      }
    };
    const releaseValidate = ajv.getSchema(expectedKinds.get(releaseManifest.kind));
    if (!releaseValidate(releaseManifest)) throw new Error(`release_schema_invalid:${ajv.errorsText(releaseValidate.errors)}`);
    const releaseSource = Buffer.from(yamlSource(releaseManifest));

    const outputRoot = assertSafeRelative(blueprint.spec.output_root);
    const capabilityPath = `${outputRoot}/capabilities/${item.artifact_name}`;
    const registryPath = `${outputRoot}/registry/${item.artifact_name}`;
    const releasePath = `${outputRoot}/releases/${item.artifact_name}`;
    desired.set(assertSafeRelative(capabilityPath), capabilitySource);
    desired.set(assertSafeRelative(registryPath), registrySource);
    desired.set(assertSafeRelative(releasePath), releaseSource);
    packageSummaries.push({
      package_id: item.package_id,
      agent_id: definition.metadata.agent_id,
      definition_ref: definitionRef,
      binding_ref: bindingRef,
      generated_paths: [capabilityPath, registryPath, releasePath]
    });
  }

  const record = {
    api_version: "orbit-agent-toolkit/v0alpha1",
    kind: "AgentToolkitGenerationRecord",
    metadata: {
      record_id: `record_${blueprint.metadata.blueprint_id}`,
      version: blueprint.metadata.version,
      status: "synthetic",
      created_at: blueprint.metadata.artifact_time
    },
    spec: {
      target_id: blueprint.spec.target_id,
      authoring_request_ref: {
        id: request.metadata.request_id,
        version: request.metadata.version,
        digest: sha256(context.requestSource)
      },
      blueprint_ref: {
        id: blueprint.metadata.blueprint_id,
        version: blueprint.metadata.version,
        digest: sha256(context.blueprintSource)
      },
      company_contract: {
        release_id: release.release_id,
        git_tag: release.source_revision.tag,
        git_commit: context.resolvedCommit,
        contract_version: release.contract_version
      },
      package_summaries: packageSummaries,
      evidence_boundary: [
        "design_only",
        "synthetic_only",
        "no_runtime_execution",
        "no_effective_grant",
        "no_git_mutation",
        "no_production_authorization"
      ]
    }
  };
  desired.set(assertSafeRelative(blueprint.spec.generation_record_path), Buffer.from(`${JSON.stringify(record, null, 2)}\n`));
  return desired;
}

async function buildPlan(context, desired) {
  const operations = [];
  for (const [relativePath, content] of [...desired].sort(([a], [b]) => a.localeCompare(b))) {
    assertSafeRelative(relativePath);
    const targetPath = path.join(context.targetRoot, relativePath);
    let action = "add";
    let baseDigest = null;
    if (await exists(targetPath)) {
      const current = await readFile(targetPath);
      baseDigest = sha256(current);
      action = baseDigest === sha256(content) ? "unchanged" : "update";
    }
    operations.push({ path: relativePath, action, base_digest: baseDigest, desired_digest: sha256(content) });
  }
  return {
    api_version: "orbit-agent-toolkit/v0alpha1",
    kind: "AgentToolkitPlan",
    metadata: {
      plan_id: `plan_${context.blueprint.metadata.blueprint_id}`,
      version: context.blueprint.metadata.version,
      created_at: context.blueprint.metadata.artifact_time
    },
    spec: {
      target_id: context.blueprint.spec.target_id,
      contract_release_id: context.release.release_id,
      request_digest: sha256(context.requestSource),
      blueprint_digest: sha256(context.blueprintSource),
      operations,
      side_effects: {
        deletes_files: false,
        mutates_git: false,
        runs_runtime: false,
        creates_effective_grant: false,
        uses_secrets: false
      }
    }
  };
}

export async function createPlan(options) {
  const context = await loadContext(options);
  const desired = await buildArtifacts(context);
  const plan = await buildPlan(context, desired);
  return { context, desired, plan };
}

export async function stagePlan(options) {
  const result = await createPlan(options);
  const out = path.resolve(options.out);
  if (await exists(out)) throw new Error("staging_directory_already_exists");
  await mkdir(out, { recursive: true });
  for (const [relativePath, content] of result.desired) {
    const destination = path.join(out, assertSafeRelative(relativePath));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, content, { flag: "wx" });
  }
  await writeFile(path.join(out, "toolkit-plan.json"), `${JSON.stringify(result.plan, null, 2)}\n`, { flag: "wx" });
  return result.plan;
}

export async function applyPlan({ staging, targetRoot, allowWrite }) {
  if (allowWrite !== true) throw new Error("apply_requires_allow_write");
  const stagingRoot = path.resolve(staging);
  const target = path.resolve(targetRoot);
  const plan = await loadJson(path.join(stagingRoot, "toolkit-plan.json"));
  if (
    plan.api_version !== "orbit-agent-toolkit/v0alpha1" ||
    plan.kind !== "AgentToolkitPlan" ||
    Object.values(plan.spec.side_effects ?? {}).some((value) => value !== false)
  ) throw new Error("invalid_or_unsafe_plan");
  const seenPaths = new Set();
  const writes = [];
  for (const operation of plan.spec.operations) {
    const relativePath = assertSafeRelative(operation.path);
    if (seenPaths.has(relativePath)) throw new Error(`duplicate_plan_path:${relativePath}`);
    seenPaths.add(relativePath);
    await assertNoSymlinkPath(target, relativePath);
    await assertNoSymlinkPath(stagingRoot, relativePath);
    if (!["add", "update", "unchanged"].includes(operation.action)) {
      throw new Error(`unsupported_operation:${operation.action}`);
    }
    const stagedPath = path.join(stagingRoot, relativePath);
    const stagedContent = await readFile(stagedPath);
    if (sha256(stagedContent) !== operation.desired_digest) throw new Error(`staging_digest_mismatch:${relativePath}`);
    const targetPath = path.join(target, relativePath);
    const targetExists = await exists(targetPath);
    if (operation.action === "unchanged") {
      if (!targetExists) throw new Error(`target_unchanged_missing:${relativePath}`);
      const current = await readFile(targetPath);
      if (sha256(current) !== operation.desired_digest) throw new Error(`target_concurrent_change:${relativePath}`);
      continue;
    }
    if (operation.action === "add" && targetExists) throw new Error(`target_add_conflict:${relativePath}`);
    if (operation.action === "update") {
      if (!targetExists) throw new Error(`target_update_missing:${relativePath}`);
      const current = await readFile(targetPath);
      if (sha256(current) !== operation.base_digest) throw new Error(`target_concurrent_change:${relativePath}`);
    }
    writes.push({ relativePath, stagedContent, targetPath });
  }

  const applied = [];
  for (const { relativePath, stagedContent, targetPath } of writes) {
    await mkdir(path.dirname(targetPath), { recursive: true });
    const tempPath = path.join(path.dirname(targetPath), `.orbit-agent-toolkit-${process.pid}-${path.basename(targetPath)}`);
    await writeFile(tempPath, stagedContent, { flag: "wx" });
    await rename(tempPath, targetPath);
    applied.push(relativePath);
  }
  return { status: "APPLIED", applied, deleted: [] };
}

export async function validateTarget(options) {
  const { plan } = await createPlan(options);
  const drift = plan.spec.operations.filter((operation) => operation.action !== "unchanged");
  return { status: drift.length === 0 ? "PASS" : "FAIL", drift, checked: plan.spec.operations.length };
}

export function runtimeAssessmentCodes(assessment, request) {
  const codes = collectSafetyErrors(assessment);
  const requiredGates = assessment.spec.requirements.hard_gates;
  const requestedFamilies = request.spec.business_requirements.runtime_candidate_families;
  const candidateFamilies = assessment.spec.candidates.map((candidate) => candidate.runtime_family);
  if (!exactSet(candidateFamilies, requestedFamilies)) codes.add("runtime_candidate_coverage_invalid");
  if (new Set(candidateFamilies).size !== candidateFamilies.length) codes.add("duplicate_runtime_candidate");
  if (
    !sameRef(
      assessment.spec.subject.environment_profile_ref,
      request.spec.environment.environment_ref
    )
  ) {
    codes.add("assessment_environment_mismatch");
  }
  if (
    assessment.spec.subject.model_selection_status !==
    request.spec.business_requirements.model_selection_status
  ) {
    codes.add("model_selection_status_mismatch");
  }
  for (const candidate of assessment.spec.candidates) {
    const results = candidate.hard_gate_results.map((item) => item.result);
    const resultGates = candidate.hard_gate_results.map((item) => item.gate);
    if (!exactSet(resultGates, requiredGates)) codes.add("hard_gate_coverage_invalid");
    if (
      candidate.assessment_status === "eligible_for_evaluation" &&
      results.some((result) => ["fail", "unknown"].includes(result))
    ) {
      codes.add("hard_gate_failure");
    }
    if (
      candidate.evidence_status === "verified_runtime" &&
      (candidate.capability_report_refs.length === 0 ||
        !candidate.hard_gate_results.some(
          (item) => item.result === "pass" && item.evidence_kind === "runtime_test"
        ))
    ) {
      codes.add("verified_runtime_evidence_missing");
    }
    for (const result of candidate.hard_gate_results) {
      if (
        result.result === "pass" &&
        (result.evidence_kind === "none" || result.evidence_ref === null)
      ) {
        codes.add("hard_gate_evidence_missing");
      }
      if (result.result === "unknown" && result.evidence_kind === "runtime_test") {
        codes.add("hard_gate_evidence_invalid");
      }
    }
  }
  const recommendation = assessment.spec.recommendation;
  if (recommendation.status === "preferred_for_evaluation") {
    const candidate = assessment.spec.candidates.find(
      (item) => item.runtime_family === recommendation.recommended_runtime_family
    );
    if (!candidate) {
      codes.add("recommendation_target_missing");
    } else if (candidate.hard_gate_results.some((item) => item.result === "fail")) {
      codes.add("hard_gate_failure");
    }
  }
  if (
    assessment.metadata.evidence_status === "verified_runtime" &&
    !assessment.spec.candidates.some(
      (candidate) => candidate.evidence_status === "verified_runtime"
    )
  ) {
    codes.add("verified_runtime_evidence_missing");
  }
  return codes;
}

export async function createRuntimeAssessment(options) {
  const bundle = await verifyContractBundle(options.contractBundle);
  const requestSource = await readFile(path.resolve(options.request), "utf8");
  const definitionSource = await readFile(path.resolve(options.definition), "utf8");
  const bindingSource = await readFile(path.resolve(options.binding), "utf8");
  const blueprintSource = await readFile(path.resolve(options.assessmentBlueprint), "utf8");
  const request = parseYamlStrict(requestSource, "AgentScaffoldRequest");
  const definition = parseYamlStrict(definitionSource, "AgentDefinition");
  const binding = parseYamlStrict(bindingSource, "AgentBinding");
  const blueprint = parseYamlStrict(blueprintSource, "RuntimeAssessmentBlueprint");
  for (const [name, value] of [
    ["request", request],
    ["definition", definition],
    ["binding", binding],
    ["assessment_blueprint", blueprint]
  ]) {
    assertNoSafetyErrors(value, name);
  }

  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  for (const schemaId of [
    "urn:company-ai-os:schema:agent-common:0.1",
    "urn:company-ai-os:schema:agent-definition:0.1",
    "urn:company-ai-os:schema:agent-binding:0.1",
    "urn:company-ai-os:schema:adapter-capability-report:0.1"
  ]) {
    ajv.addSchema((await loadBundleSchema(bundle, schemaId)).schema);
  }
  for (const schemaId of [requestSchemaId, runtimeAssessmentSchemaId]) {
    ajv.addSchema((await loadBundleSchema(bundle, schemaId, "authoring_draft.schemas")).schema);
  }
  ajv.addSchema(await loadJson(runtimeAssessmentBlueprintSchemaPath));
  for (const [value, schemaId, name] of [
    [request, requestSchemaId, "request"],
    [definition, expectedKinds.get("AgentDefinition"), "definition"],
    [binding, expectedKinds.get("AgentBinding"), "binding"],
    [
      blueprint,
      "urn:orbit-agent-toolkit:schema:runtime-assessment-blueprint:0.1",
      "assessment_blueprint"
    ]
  ]) {
    const validate = ajv.getSchema(schemaId);
    if (!validate?.(value)) {
      throw new Error(`${name}_schema_invalid:${ajv.errorsText(validate?.errors)}`);
    }
  }
  if (
    request.spec.generation_policy.runtime_execution !== "forbidden" ||
    request.spec.generation_policy.git_mutation !== "forbidden" ||
    request.spec.generation_policy.secret_material !== "forbidden"
  ) {
    throw new Error("runtime_assessment_policy_must_be_non_executing");
  }
  if (!request.spec.requested_outputs.includes("runtime_selection_assessment")) {
    throw new Error("runtime_assessment_not_requested");
  }

  const releaseId = request.spec.contract_source.release_id;
  const releaseSource = bundle.manifestSource;
  const release = bundle.release;
  if (sha256(releaseSource) !== request.spec.contract_source.manifest_digest) {
    throw new Error("release_manifest_digest_mismatch");
  }
  const resolvedCommit = bundle.lock.authority.contract_git_commit;
  if (
    resolvedCommit !== request.spec.contract_source.git_commit ||
    release.release_id !== releaseId ||
    release.contract_api_version !== request.spec.contract_source.contract_api_version ||
    release.contract_version !== request.spec.contract_source.contract_version
  ) {
    throw new Error("release_identity_mismatch");
  }
  for (const lock of request.spec.contract_source.schema_locks) {
    const artifact = findArtifact(release, lock.schema_id);
    if (artifact.sha256 !== lock.digest) {
      throw new Error(`request_schema_lock_mismatch:${lock.schema_id}`);
    }
    const { source: schemaSource } = await loadBundleSchema(bundle, lock.schema_id);
    if (sha256(schemaSource) !== artifact.sha256) {
      throw new Error(`company_schema_worktree_mismatch:${lock.schema_id}`);
    }
  }

  const definitionRef = {
    id: definition.metadata.agent_id,
    version: definition.metadata.version,
    digest: sha256(definitionSource)
  };
  const bindingRef = {
    id: binding.metadata.binding_id,
    version: binding.metadata.version,
    digest: sha256(bindingSource)
  };
  if (!sameRef(binding.spec.definition_ref, definitionRef)) {
    throw new Error("binding_definition_ref_mismatch");
  }
  const requestedAgent = request.spec.target.agent_target;
  if (!requestedAgent || requestedAgent.agent_id !== definition.metadata.agent_id) {
    throw new Error("assessment_agent_target_mismatch");
  }
  const derivedConstraints = deriveRuntimeConstraints(definition, binding, request);
  if (
    JSON.stringify(blueprint.spec.requirements.derived_constraints) !==
    JSON.stringify(derivedConstraints)
  ) {
    throw new Error("derived_runtime_constraints_mismatch");
  }
  if (!exactSet(blueprint.spec.requirements.hard_gates, derivedConstraints.required_hard_gates)) {
    throw new Error("derived_hard_gates_mismatch");
  }
  if (!exactSet(blueprint.spec.requirements.required_conformance_profiles, derivedConstraints.required_conformance_profiles)) {
    throw new Error("derived_conformance_profiles_mismatch");
  }
  if (!exactSet(blueprint.spec.requirements.data_classifications, derivedConstraints.data_classifications)) {
    throw new Error("derived_data_classifications_mismatch");
  }

  const evidenceRoot = options.evidenceRoot ? path.resolve(options.evidenceRoot) : null;
  const capabilityValidate = ajv.getSchema("urn:company-ai-os:schema:adapter-capability-report:0.1");
  for (const input of blueprint.spec.evidence_inputs) {
    if (!evidenceRoot) throw new Error("runtime_evidence_root_required");
    const relativePath = assertSafeRelative(input.relative_path);
    await assertNoSymlinkPath(evidenceRoot, relativePath);
    const source = await readFile(path.join(evidenceRoot, relativePath));
    const report = JSON.parse(source.toString("utf8"));
    if (!capabilityValidate?.(report)) {
      throw new Error(`capability_report_schema_invalid:${ajv.errorsText(capabilityValidate?.errors)}`);
    }
    const actualRef = {
      id: report.metadata.report_id,
      version: report.metadata.version,
      digest: sha256(source)
    };
    if (!sameRef(actualRef, input.report_ref)) throw new Error("capability_report_ref_mismatch");
    const candidate = blueprint.spec.candidates.find(
      (item) => item.runtime_family === input.runtime_family
    );
    if (!candidate) throw new Error("capability_report_candidate_missing");
    if (!candidate.capability_report_refs.some((item) => sameRef(item, actualRef))) {
      throw new Error("candidate_capability_report_ref_missing");
    }
    if (!sameRef(candidate.runtime_revision_ref, report.spec.runtime_revision_ref)) {
      throw new Error("candidate_runtime_revision_mismatch");
    }
    if (!sameRef(candidate.adapter_ref, report.spec.runtime_adapter_ref)) {
      throw new Error("candidate_adapter_ref_mismatch");
    }
  }

  const assessment = {
    api_version: "company-ai-os/v1alpha1",
    kind: "RuntimeSelectionAssessment",
    metadata: {
      assessment_id: blueprint.metadata.assessment_id,
      agent_id: definition.metadata.agent_id,
      version: blueprint.metadata.version,
      status: blueprint.metadata.status,
      evidence_status: blueprint.metadata.evidence_status,
      synthetic_only: true,
      observed_at: blueprint.metadata.observed_at
    },
    spec: {
      subject: {
        definition_ref: definitionRef,
        binding_ref: bindingRef,
        scaffold_request_ref: {
          id: request.metadata.request_id,
          version: request.metadata.version,
          digest: sha256(requestSource)
        },
        environment_profile_ref: request.spec.environment.environment_ref,
        model_selection_status: request.spec.business_requirements.model_selection_status
      },
      requirements: blueprint.spec.requirements,
      candidates: blueprint.spec.candidates,
      recommendation: blueprint.spec.recommendation
    }
  };
  const validateAssessment = ajv.getSchema(runtimeAssessmentSchemaId);
  if (!validateAssessment(assessment)) {
    throw new Error(`assessment_schema_invalid:${ajv.errorsText(validateAssessment.errors)}`);
  }
  const codes = [...runtimeAssessmentCodes(assessment, request)];
  if (codes.length > 0) throw new Error(`assessment_invariant_invalid:${codes.join(",")}`);
  return { assessment, source: yamlSource(assessment) };
}

export async function writeRuntimeAssessment(options) {
  if (options.allowWrite !== true) throw new Error("assessment_write_requires_allow_write");
  const targetRoot = path.resolve(options.targetRoot);
  const relativePath = assertSafeRelative(options.outPath);
  await assertNoSymlinkPath(targetRoot, relativePath);
  const targetPath = path.join(targetRoot, relativePath);
  if (await exists(targetPath)) throw new Error(`assessment_target_exists:${relativePath}`);
  const result = await createRuntimeAssessment(options);
  await mkdir(path.dirname(targetPath), { recursive: true });
  await writeFile(targetPath, result.source, { flag: "wx" });
  return {
    status: "CREATED",
    path: relativePath,
    digest: sha256(result.source),
    note: "This assessment records evidence and evaluation priority only; it does not select or run a Runtime."
  };
}

function parseArgs(argv) {
  const [group, action, ...rest] = argv;
  const options = { group, action };
  for (let index = 0; index < rest.length; index += 1) {
    const key = rest[index];
    if (key === "--allow-write") {
      options.allowWrite = true;
      continue;
    }
    if (!key.startsWith("--") || index + 1 >= rest.length) throw new Error(`invalid_argument:${key}`);
    const value = rest[++index];
    const name = key.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    options[name] = value;
  }
  return options;
}

function requireOptions(options, names) {
  for (const name of names) if (!options[name]) throw new Error(`missing_option:${name}`);
}

export async function runCli(argv) {
  try {
    const options = parseArgs(argv);
    if (["help", "--help", "-h", undefined].includes(options.group)) {
      console.log("orbit-agent-author <contract verify|package plan|package stage|package apply|package validate|runtime assess> [options]");
      return 0;
    }
    if (options.group === "contract" && options.action === "verify") {
      const bundle = await verifyContractBundle(options.contractBundle);
      console.log(JSON.stringify({
        status: "PASS",
        release_id: bundle.release.release_id,
        released_schema_count: bundle.lock.released_schemas.length,
        authoring_schema_count: bundle.lock.authoring_draft.schemas.length,
        authoring_status: bundle.lock.authoring_draft.status
      }, null, 2));
      return 0;
    }
    if (options.group === "package" && options.action === "apply") {
      requireOptions(options, ["staging", "targetRoot"]);
      console.log(JSON.stringify(await applyPlan(options), null, 2));
      return 0;
    }
    if (options.group === "runtime" && options.action === "assess") {
      requireOptions(options, [
        "request",
        "definition",
        "binding",
        "assessmentBlueprint"
      ]);
      if (options.targetRoot || options.outPath) {
        requireOptions(options, ["targetRoot", "outPath"]);
        console.log(JSON.stringify(await writeRuntimeAssessment(options), null, 2));
      } else {
        console.log((await createRuntimeAssessment(options)).source.trimEnd());
      }
      return 0;
    }
    if (options.group !== "package") throw new Error(`unknown_command_group:${options.group}`);
    requireOptions(options, ["targetRoot", "targetLock", "request", "blueprint"]);
    if (options.action === "plan") {
      console.log(JSON.stringify((await createPlan(options)).plan, null, 2));
      return 0;
    }
    if (options.action === "stage") {
      requireOptions(options, ["out"]);
      console.log(JSON.stringify(await stagePlan(options), null, 2));
      return 0;
    }
    if (options.action === "validate") {
      const result = await validateTarget(options);
      console.log(JSON.stringify(result, null, 2));
      return result.status === "PASS" ? 0 : 1;
    }
    throw new Error(`unknown_package_command:${options.action}`);
  } catch (error) {
    console.error(JSON.stringify({ status: "FAIL", error: error.message }, null, 2));
    return 1;
  }
}

