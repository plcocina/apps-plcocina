import assert from "node:assert/strict";
import test from "node:test";
import {
  ADMIN_ME_URL,
  AdminApiError,
  verifySuperAdminSession
} from "../public/assets/admin-api-client.js";

const UID = "admin-uid";
const TOKEN = "sensitive-id-token";

function user() {
  return {
    uid: UID,
    getIdToken: async () => TOKEN
  };
}

function response(status, body) {
  return {
    status,
    json: async () => body
  };
}

test("verifies the backend principal using the Firebase ID token", async () => {
  let captured;
  const principal = await verifySuperAdminSession(user(), {
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(200, {
        ok: true,
        data: { uid: UID, email: "admin@plcocina.com", superAdmin: true }
      });
    }
  });

  assert.equal(captured.url, ADMIN_ME_URL);
  assert.equal(captured.options.method, "GET");
  assert.equal(captured.options.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(captured.options.cache, "no-store");
  assert.equal(captured.options.credentials, "omit");
  assert.equal(principal.superAdmin, true);
});

for (const [name, body] of [
  ["ok false", { ok: false, data: { uid: UID, superAdmin: true } }],
  ["role false", { ok: true, data: { uid: UID, superAdmin: false } }],
  ["different uid", { ok: true, data: { uid: "another-uid", superAdmin: true } }]
]) {
  test(`rejects a 200 response with ${name}`, async () => {
    await assert.rejects(
      verifySuperAdminSession(user(), {
        fetchImpl: async () => response(200, body)
      }),
      (error) => error instanceof AdminApiError && error.code === "INVALID_RESPONSE"
    );
  });
}

for (const [status, code] of [[401, "AUTH_REQUIRED"], [403, "ADMIN_REQUIRED"]]) {
  test(`rejects HTTP ${status} without exposing the token`, async () => {
    await assert.rejects(
      verifySuperAdminSession(user(), {
        fetchImpl: async () => response(status, {})
      }),
      (error) => {
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        assert.equal(String(error).includes(TOKEN), false);
        return true;
      }
    );
  });
}

test("keeps network failures retryable without exposing the token", async () => {
  await assert.rejects(
    verifySuperAdminSession(user(), {
      fetchImpl: async () => {
        throw new Error("offline");
      }
    }),
    (error) => {
      assert.equal(error.code, "NETWORK_ERROR");
      assert.equal(error.status, null);
      assert.equal(String(error).includes(TOKEN), false);
      return true;
    }
  );
});

test("treats a server error as retryable", async () => {
  await assert.rejects(
    verifySuperAdminSession(user(), {
      fetchImpl: async () => response(503, {})
    }),
    (error) => error.code === "SERVICE_UNAVAILABLE" && error.status === 503
  );
});
