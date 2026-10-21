import assert from "node:assert/strict";
import test from "node:test";
import {
  EXPECTED,
  validateAnonymousHealth,
  validateArtifactRepository,
  validateFunctionState,
  validateGoogleApiUrl,
  validateRunServiceState
} from "../scripts/validate-admin-api-deployment.mjs";

const functionState = {
  name: `projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/functions/${EXPECTED.functionName}`,
  environment: "GEN_2",
  state: "ACTIVE",
  serviceConfig: {
    serviceAccountEmail: EXPECTED.runtimeServiceAccount,
    uri: "https://adminapi-example-uc.a.run.app"
  }
};

const runState = {
  name: `projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/services/${EXPECTED.runService}`,
  invokerIamDisabled: true,
  reconciling: false,
  terminalCondition: { state: "CONDITION_SUCCEEDED" }
};

const gcloudRunV1State = {
  apiVersion: "serving.knative.dev/v1",
  kind: "Service",
  metadata: {
    name: EXPECTED.runService,
    namespace: "465339579029",
    labels: { "cloud.googleapis.com/location": EXPECTED.region },
    annotations: { "run.googleapis.com/invoker-iam-disabled": "true" }
  },
  status: {
    conditions: [{ type: "Ready", status: "True" }]
  }
};

const artifactState = {
  name: `projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/repositories/${EXPECTED.artifactRepository}`,
  cleanupPolicyDryRun: false,
  cleanupPolicies: {
    [EXPECTED.cleanupPolicy]: {
      action: "DELETE",
      condition: { olderThan: "604800s" }
    }
  }
};

test("accepts the expected effective cloud state", () => {
  assert.equal(validateFunctionState(functionState).uri, "https://adminapi-example-uc.a.run.app");
  assert.equal(validateRunServiceState(runState), undefined);
  assert.equal(validateArtifactRepository(artifactState), undefined);
});

test("rejects a non-active, Gen 1, or differently identified function", () => {
  for (const invalid of [
    { ...functionState, state: "FAILED" },
    { ...functionState, environment: "GEN_1" },
    {
      ...functionState,
      serviceConfig: { ...functionState.serviceConfig, serviceAccountEmail: "wrong@example.com" }
    }
  ]) {
    assert.throws(() => validateFunctionState(invalid));
  }
});

test("requires the effective Cloud Run v2 invoker setting and ready state", () => {
  assert.throws(() => validateRunServiceState({ ...runState, invokerIamDisabled: false }));
  assert.throws(() => validateRunServiceState({ ...runState, invokerIamDisabled: undefined }));
  assert.throws(() => validateRunServiceState({ ...runState, reconciling: true }));
  assert.throws(() => validateRunServiceState({ ...runState, reconciling: undefined }));
  assert.throws(() => validateRunServiceState(gcloudRunV1State));
});

test("accepts only the three exact read-only Google Cloud API resource URLs", () => {
  for (const url of [
    `https://cloudfunctions.googleapis.com/v2/projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/functions/${EXPECTED.functionName}`,
    `https://run.googleapis.com/v2/projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/services/${EXPECTED.runService}`,
    `https://artifactregistry.googleapis.com/v1/projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/repositories/${EXPECTED.artifactRepository}`
  ]) {
    assert.equal(validateGoogleApiUrl(url).href, url);
  }
  for (const invalid of [
    "http://run.googleapis.com/v2/projects/plcocina-apps/locations/us-central1/services/adminapi",
    "https://run.googleapis.com/v1/projects/plcocina-apps/locations/us-central1/services/adminapi",
    "https://run.googleapis.com/v2/projects/otro/locations/us-central1/services/adminapi",
    "https://example.com/"
  ]) {
    assert.throws(() => validateGoogleApiUrl(invalid));
  }
});

test("requires an active seven-day DELETE cleanup policy", () => {
  assert.throws(() => validateArtifactRepository({ ...artifactState, cleanupPolicyDryRun: true }));
  assert.throws(() => validateArtifactRepository({ ...artifactState, cleanupPolicyDryRun: undefined }));
  assert.throws(() => validateArtifactRepository({ ...artifactState, cleanupPolicies: {} }));
  assert.throws(() => validateArtifactRepository({
    ...artifactState,
    cleanupPolicies: {
      [EXPECTED.cleanupPolicy]: { action: "DELETE", condition: { olderThan: "86400s" } }
    }
  }));
});

test("accepts only the backend 401 JSON contract for anonymous health", async () => {
  let requestedUrl;
  await validateAnonymousHealth(functionState.serviceConfig.uri, async (url, options) => {
    requestedUrl = url;
    assert.equal(options.method, "GET");
    assert.deepEqual(options.headers, { Accept: "application/json" });
    assert.equal(Object.hasOwn(options.headers, "Authorization"), false);
    return new Response(JSON.stringify({ ok: false, error: { code: "AUTH_REQUIRED" } }), {
      status: 401,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  });
  assert.equal(requestedUrl.href, "https://adminapi-example-uc.a.run.app/api/admin/health");
});

test("rejects Cloud Run 403 and misleading health responses", async () => {
  for (const [status, body, contentType] of [
    [403, "Forbidden", "text/html"],
    [200, JSON.stringify({ ok: true }), "application/json"],
    [401, JSON.stringify({ ok: false, error: { code: "OTHER" } }), "application/json"]
  ]) {
    await assert.rejects(
      validateAnonymousHealth(functionState.serviceConfig.uri, async () =>
        new Response(body, { status, headers: { "content-type": contentType } })
      )
    );
  }
});
