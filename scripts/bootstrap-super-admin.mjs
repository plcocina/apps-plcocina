import { applicationDefault, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";

const PROJECT_ID = "plcocina-apps";
const EXPECTED_EMAIL = "hector@plcocina.com";
const CONFIRMATION_TEXT = `assign:${EXPECTED_EMAIL}`;
const apply = process.argv.includes("--apply");
const unknownArguments = process.argv.slice(2).filter((argument) => argument !== "--apply");

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

if (unknownArguments.length > 0) {
  fail(`Argumento no reconocido: ${unknownArguments.join(", ")}`);
} else {
  const expectedUid = process.env.EXPECTED_SUPER_ADMIN_UID?.trim();

  if (!expectedUid) {
    fail("Define EXPECTED_SUPER_ADMIN_UID con el UID validado fuera del repositorio.");
  } else if (apply && process.env.CONFIRM_SUPER_ADMIN !== CONFIRMATION_TEXT) {
    fail(`Para aplicar, define CONFIRM_SUPER_ADMIN=${CONFIRMATION_TEXT}`);
  } else {
    await run({ expectedUid, apply });
  }
}

async function run({ expectedUid, apply: shouldApply }) {
  const app = initializeApp({ credential: applicationDefault(), projectId: PROJECT_ID });
  const auth = getAuth(app);
  const target = await auth.getUser(expectedUid);

  if (target.email?.toLowerCase() !== EXPECTED_EMAIL) {
    throw new Error("El UID indicado no corresponde a la cuenta inicial aprobada.");
  }

  if (target.disabled) {
    throw new Error("La cuenta inicial está deshabilitada.");
  }

  const hasPasswordProvider = target.providerData.some(
    ({ providerId }) => providerId === "password"
  );

  if (!hasPasswordProvider) {
    throw new Error("La cuenta inicial no tiene habilitado el proveedor de contraseña.");
  }

  const existingSuperAdmins = await listSuperAdmins(auth);
  const unexpectedSuperAdmins = existingSuperAdmins.filter(({ uid }) => uid !== expectedUid);

  if (unexpectedSuperAdmins.length > 0) {
    throw new Error(
      "Se detectó super_admin en otra cuenta. No se realizará ninguna modificación."
    );
  }

  const alreadyAssigned = target.customClaims?.super_admin === true;

  console.log(JSON.stringify({
    mode: shouldApply ? "apply" : "inspect",
    projectId: PROJECT_ID,
    uid: target.uid,
    email: target.email,
    disabled: target.disabled,
    passwordProvider: hasPasswordProvider,
    superAdminAlreadyAssigned: alreadyAssigned,
    otherSuperAdmins: unexpectedSuperAdmins.length
  }, null, 2));

  if (!shouldApply) {
    console.log("Inspección finalizada. No se realizaron cambios.");
    return;
  }

  if (!alreadyAssigned) {
    await auth.setCustomUserClaims(target.uid, {
      ...(target.customClaims ?? {}),
      super_admin: true
    });
  }

  const verified = await auth.getUser(target.uid);
  if (verified.customClaims?.super_admin !== true) {
    throw new Error("No fue posible verificar el Custom Claim después de escribirlo.");
  }

  console.log("Custom Claim verificado para el UID aprobado.");
}

async function listSuperAdmins(auth) {
  const matches = [];
  let pageToken;

  do {
    const page = await auth.listUsers(1000, pageToken);
    for (const user of page.users) {
      if (user.customClaims?.super_admin === true) {
        matches.push({ uid: user.uid, email: user.email ?? null });
      }
    }
    pageToken = page.pageToken;
  } while (pageToken);

  return matches;
}
