import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import {
  applyPlan,
  assertSafeRelative,
  createPlan,
  deriveRuntimeConstraints,
  parseYamlStrict,
  runtimeAssessmentCodes,
  sha256,
  stagePlan,
  validateTarget,
  verifyContractBundle,
  writeRuntimeAssessment
} from "../src/toolkit.mjs";

async function prepareSyntheticTarget() {
  const toolkitRoot = path.resolve(import.meta.dirname, "..");
  const bundleRoot = path.join(
    toolkitRoot,
    "contract-bundles",
    "contract-v0.1.0-alpha.2"
  );
  const root = await mkdtemp(path.join(os.tmpdir(), "orbit-agent-toolkit-e2e-"));
  const targetRoot = path.join(root, "target");
  const request = path.join(toolkitRoot, "examples", "company-task-router", "agent-scaffold-request.synthetic.yaml");
  const blueprint = path.join(toolkitRoot, "examples", "company-task-router", "agent-package-blueprint.synthetic.yaml");
  const requestValue = parseYamlStrict(await readFile(request, "utf8"));
  const blueprintValue = parseYamlStrict(await readFile(blueprint, "utf8"));
  const release = JSON.parse(await readFile(path.join(bundleRoot, "manifest.json"), "utf8"));
  const lock = {
    authority: {
      git_tag: release.source_revision.tag,
      git_commit: requestValue.spec.contract_source.git_commit,
      contract_api_version: release.contract_api_version,
      contract_version: release.contract_version
    },
    schemas: []
  };
  for (const schemaId of blueprintValue.spec.required_schema_ids) {
    const artifact = release.artifacts.schemas.find((item) => item.schema_id === schemaId);
    assert(artifact, `missing released schema ${schemaId}`);
    const mirrorPath = `contracts/company-agent-contract/schemas/${path.basename(artifact.path)}`;
    lock.schemas.push({
      upstream_path: artifact.path,
      mirror_path: mirrorPath,
      schema_id: schemaId,
      sha256: artifact.sha256
    });
    await mkdir(path.dirname(path.join(targetRoot, mirrorPath)), { recursive: true });
    await writeFile(
      path.join(targetRoot, mirrorPath),
      await readFile(path.join(bundleRoot, "schemas", path.basename(artifact.path)))
    );
  }
  const lockPath = path.join(targetRoot, "contracts", "company-agent-contract", "lock.json");
  await mkdir(path.dirname(lockPath), { recursive: true });
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  for (const item of blueprintValue.spec.packages) {
    for (const [kind, relativeTarget] of [
      ["definition", item.definition_path],
      ["binding", item.binding_path]
    ]) {
      const targetPath = path.join(targetRoot, relativeTarget);
      await mkdir(path.dirname(targetPath), { recursive: true });
      await writeFile(
        targetPath,
        await readFile(
          path.join(toolkitRoot, "test", "fixtures", "company-task-router-target", relativeTarget)
        )
      );
    }
  }
  return { root, targetRoot, targetLock: lockPath, request, blueprint };
}

test("embedded contract bundle verifies without an Architecture checkout", async () => {
  const bundle = await verifyContractBundle();
  assert.equal(bundle.release.release_id, "contract-v0.1.0-alpha.2");
  assert.equal(bundle.lock.released_schemas.length, 30);
  assert.equal(bundle.lock.authoring_draft.status, "draft_non_authoritative");
});

test("sha256 is deterministic", () => {
  assert.equal(sha256("same"), sha256(Buffer.from("same")));
  assert.match(sha256("same"), /^sha256:[a-f0-9]{64}$/);
});

test("safe paths reject traversal and absolute paths", () => {
  assert.equal(assertSafeRelative("contracts/agents/test.yaml"), "contracts/agents/test.yaml");
  assert.throws(() => assertSafeRelative("../outside"), /unsafe_relative_path/);
  assert.throws(() => assertSafeRelative("/absolute"), /unsafe_relative_path/);
});

test("strict YAML rejects duplicate keys, aliases and merge keys", () => {
  assert.throws(() => parseYamlStrict("a: 1\na: 2\n"), /yaml/);
  assert.throws(() => parseYamlStrict("a: &x 1\nb: *x\n"), /yaml_anchor|yaml_alias/);
  assert.throws(() => parseYamlStrict("a:\n  <<: {b: 1}\n"), /yaml_merge_key/);
});

test("apply requires explicit write flag", async () => {
  await assert.rejects(() => applyPlan({ staging: "missing", targetRoot: "missing", allowWrite: false }), /allow_write/);
});

test("apply rejects concurrent target changes", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "orbit-agent-toolkit-test-"));
  const staging = path.join(root, "staging");
  const target = path.join(root, "target");
  await mkdir(path.join(staging, "contracts"), { recursive: true });
  await mkdir(path.join(target, "contracts"), { recursive: true });
  await writeFile(path.join(staging, "contracts", "item.txt"), "desired");
  await writeFile(path.join(target, "contracts", "item.txt"), "changed");
  const plan = {
    api_version: "orbit-agent-toolkit/v0alpha1",
    kind: "AgentToolkitPlan",
    spec: {
      side_effects: {
        deletes_files: false,
        mutates_git: false,
        runs_runtime: false,
        creates_effective_grant: false,
        uses_secrets: false
      },
      operations: [{
        path: "contracts/item.txt",
        action: "update",
        base_digest: sha256("original"),
        desired_digest: sha256("desired")
      }]
    }
  };
  await writeFile(path.join(staging, "toolkit-plan.json"), JSON.stringify(plan));
  await assert.rejects(
    () => applyPlan({ staging, targetRoot: target, allowWrite: true }),
    /target_concurrent_change/
  );
  assert.equal(await readFile(path.join(target, "contracts", "item.txt"), "utf8"), "changed");
});

test("apply preflights every operation before writing", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "orbit-agent-toolkit-preflight-"));
  const staging = path.join(root, "staging");
  const target = path.join(root, "target");
  await mkdir(path.join(staging, "contracts"), { recursive: true });
  await mkdir(path.join(target, "contracts"), { recursive: true });
  await writeFile(path.join(staging, "contracts", "first.txt"), "desired-first");
  await writeFile(path.join(staging, "contracts", "second.txt"), "desired-second");
  await writeFile(path.join(target, "contracts", "first.txt"), "original-first");
  await writeFile(path.join(target, "contracts", "second.txt"), "concurrent-second");
  const plan = {
    api_version: "orbit-agent-toolkit/v0alpha1",
    kind: "AgentToolkitPlan",
    spec: {
      side_effects: {
        deletes_files: false,
        mutates_git: false,
        runs_runtime: false,
        creates_effective_grant: false,
        uses_secrets: false
      },
      operations: [
        {
          path: "contracts/first.txt",
          action: "update",
          base_digest: sha256("original-first"),
          desired_digest: sha256("desired-first")
        },
        {
          path: "contracts/second.txt",
          action: "update",
          base_digest: sha256("original-second"),
          desired_digest: sha256("desired-second")
        }
      ]
    }
  };
  await writeFile(path.join(staging, "toolkit-plan.json"), JSON.stringify(plan));
  await assert.rejects(
    () => applyPlan({ staging, targetRoot: target, allowWrite: true }),
    /target_concurrent_change/
  );
  assert.equal(await readFile(path.join(target, "contracts", "first.txt"), "utf8"), "original-first");
});

test("plan, stage, apply and validate are deterministic end to end", async () => {
  const fixture = await prepareSyntheticTarget();
  const options = {
    targetRoot: fixture.targetRoot,
    targetLock: fixture.targetLock,
    request: fixture.request,
    blueprint: fixture.blueprint
  };
  const first = await createPlan(options);
  const second = await createPlan(options);
  assert.deepEqual(first.plan, second.plan);
  assert.deepEqual(
    [...first.desired].map(([relativePath, content]) => [relativePath, sha256(content)]),
    [...second.desired].map(([relativePath, content]) => [relativePath, sha256(content)])
  );

  const staging = path.join(fixture.root, "staging");
  const stagedPlan = await stagePlan({ ...options, out: staging });
  assert.deepEqual(stagedPlan, first.plan);
  const applied = await applyPlan({ staging, targetRoot: fixture.targetRoot, allowWrite: true });
  assert.equal(applied.status, "APPLIED");
  assert(applied.applied.length > 0);
  assert.deepEqual(applied.deleted, []);

  const validated = await validateTarget(options);
  assert.equal(validated.status, "PASS");
  assert.deepEqual(validated.drift, []);
});

test("runtime assessment rejects eligibility with unknown hard gates", () => {
  const request = {
    spec: {
      business_requirements: {
        runtime_candidate_families: ["hermes_agent"],
        model_selection_status: "pending"
      },
      environment: {
        environment_ref: {
          id: "env_test_syn",
          version: "0.1.0",
          digest: `sha256:${"1".repeat(64)}`
        }
      }
    }
  };
  const assessment = {
    metadata: { evidence_status: "architecture_reference" },
    spec: {
      subject: {
        environment_profile_ref: request.spec.environment.environment_ref,
        model_selection_status: "pending"
      },
      requirements: { hard_gates: ["exact_revision"] },
      candidates: [
        {
          runtime_family: "hermes_agent",
          assessment_status: "eligible_for_evaluation",
          evidence_status: "architecture_reference",
          capability_report_refs: [],
          hard_gate_results: [
            {
              gate: "exact_revision",
              result: "unknown",
              evidence_kind: "none",
              evidence_ref: null
            }
          ]
        }
      ],
      recommendation: {
        status: "no_selection",
        recommended_runtime_family: null
      }
    }
  };
  assert(runtimeAssessmentCodes(assessment, request).has("hard_gate_failure"));
});

test("runtime constraints are derived from Definition, Binding and environment", () => {
  const constraints = deriveRuntimeConstraints(
    {
      spec: {
        model_requirements: {
          usage: "optional",
          capabilities: ["structured_output"],
          allowed_data_classifications: ["public"]
        },
        permission_requests: {
          tools: [{ request_name: "report_writer", operations: ["create"] }],
          data: [],
          agents: { rules: [] }
        },
        memory: { allowed_classes: ["working"] },
        max_autonomy: "L1"
      }
    },
    {
      spec: {
        environment: { allowed_data_classifications: ["public"] },
        sandbox: { filesystem: "deny", network: "deny" },
        workspace: { mode: "none" },
        resource_limits: { max_tool_calls: 2, max_concurrency: 1 }
      }
    },
    {
      spec: {
        business_requirements: { data_classifications: ["public"] },
        environment: { execution_location: "local_workstation", isolation: "container" }
      }
    }
  );
  assert.deepEqual(constraints.tool_operations, ["report_writer:create"]);
  assert.deepEqual(constraints.data_classifications, ["public"]);
  assert(constraints.required_hard_gates.includes("tool_interception"));
  assert(constraints.required_hard_gates.includes("memory_isolation"));
  assert(constraints.required_hard_gates.includes("resource_fit"));
  assert.deepEqual(constraints.required_conformance_profiles, [
    "core_dispatch",
    "isolated_workload",
    "tool_data_enforced"
  ]);
});

test("runtime assessment write requires explicit permission", async () => {
  await assert.rejects(
    () => writeRuntimeAssessment({ allowWrite: false }),
    /assessment_write_requires_allow_write/
  );
});

test("runtime assessment write rejects traversal and overwrite", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "orbit-runtime-assessment-write-"));
  await assert.rejects(
    () =>
      writeRuntimeAssessment({
        allowWrite: true,
        targetRoot: root,
        outPath: "../outside.yaml"
      }),
    /unsafe_relative_path/
  );
  await mkdir(path.join(root, "contracts"), { recursive: true });
  await writeFile(path.join(root, "contracts", "assessment.yaml"), "existing");
  await assert.rejects(
    () =>
      writeRuntimeAssessment({
        allowWrite: true,
        targetRoot: root,
        outPath: "contracts/assessment.yaml"
      }),
    /assessment_target_exists/
  );
});

test("runtime observation schema validates the sanitized local evidence", async () => {
  const toolkitRoot = path.resolve(import.meta.dirname, "..");
  const schema = JSON.parse(
    await readFile(
      path.join(toolkitRoot, "schemas", "runtime-environment-observation.schema.json"),
      "utf8"
    )
  );
  const observation = JSON.parse(
    await readFile(
      path.join(
        toolkitRoot,
        "test",
        "fixtures",
        "legacy-runtime-assessment",
        "orbit-local-workstation-runtime-observation.architecture-reference.json"
      ),
      "utf8"
    )
  );
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  assert.equal(validate(observation), true, JSON.stringify(validate.errors));
});

test("runtime assessment blueprint and generated example pass draft schemas", async () => {
  const toolkitRoot = path.resolve(import.meta.dirname, "..");
  const bundleRoot = path.join(toolkitRoot, "contract-bundles", "contract-v0.1.0-alpha.2");
  const commonSchema = JSON.parse(
    await readFile(path.join(bundleRoot, "schemas", "agent-common.schema.json"), "utf8")
  );
  const assessmentSchema = JSON.parse(
    await readFile(
      path.join(bundleRoot, "authoring-schemas", "runtime-selection-assessment.schema.json"),
      "utf8"
    )
  );
  const blueprintSchema = JSON.parse(
    await readFile(
      path.join(toolkitRoot, "schemas", "runtime-assessment-blueprint.schema.json"),
      "utf8"
    )
  );
  const blueprint = parseYamlStrict(
    await readFile(
      path.join(
        toolkitRoot,
        "test",
        "fixtures",
        "legacy-runtime-assessment",
        "orbit-research-evaluator-runtime-assessment-blueprint.synthetic.yaml"
      ),
      "utf8"
    )
  );
  const assessment = parseYamlStrict(
    await readFile(
      path.join(
        toolkitRoot,
        "test",
        "fixtures",
        "legacy-runtime-assessment",
        "orbit-research-evaluator-runtime-assessment.synthetic.yaml"
      ),
      "utf8"
    )
  );
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  ajv.addSchema(commonSchema);
  ajv.addSchema(assessmentSchema);
  ajv.addSchema(blueprintSchema);
  const validateBlueprint = ajv.getSchema(blueprintSchema.$id);
  const validateAssessment = ajv.getSchema(assessmentSchema.$id);
  assert.equal(validateBlueprint(blueprint), true, JSON.stringify(validateBlueprint.errors));
  assert.equal(validateAssessment(assessment), true, JSON.stringify(validateAssessment.errors));
});

