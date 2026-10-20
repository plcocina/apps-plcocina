const DISPLAYED_CLAIMS = ["sub", "repository", "ref", "environment"];

function decodePayload(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("GitHub no devolvió un OIDC JWT válido.");
  }

  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

export function selectDiagnosticClaims(jwt) {
  const payload = decodePayload(jwt);
  return Object.fromEntries(
    DISPLAYED_CLAIMS.map((claim) => [
      claim,
      typeof payload[claim] === "string" ? payload[claim] : null
    ])
  );
}

function claimsMatchExpected(claims) {
  return (
    claims.sub === process.env.EXPECTED_OIDC_SUBJECT &&
    claims.repository === process.env.EXPECTED_OIDC_REPOSITORY &&
    claims.ref === process.env.EXPECTED_OIDC_REF &&
    claims.environment === process.env.EXPECTED_OIDC_ENVIRONMENT
  );
}

async function main() {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const provider = process.env.WORKLOAD_IDENTITY_PROVIDER;
  if (!requestUrl || !requestToken || !provider) {
    throw new Error("El runner no expuso la configuración OIDC requerida.");
  }

  const url = new URL(requestUrl);
  url.searchParams.set("audience", `https://iam.googleapis.com/${provider}`);
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${requestToken}` }
  });
  if (!response.ok) {
    throw new Error(`GitHub OIDC respondió con HTTP ${response.status}.`);
  }

  const body = await response.json();
  if (typeof body.value !== "string") {
    throw new Error("GitHub OIDC no devolvió un JWT.");
  }

  const claims = selectDiagnosticClaims(body.value);
  process.stdout.write(`${JSON.stringify(claims, null, 2)}\n`);
  if (!claimsMatchExpected(claims)) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file:").href) {
  await main();
}
