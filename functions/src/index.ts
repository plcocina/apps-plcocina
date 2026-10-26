import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { onRequest } from "firebase-functions/v2/https";
import { defineBoolean, defineSecret } from "firebase-functions/params";
import { createAdminApp } from "./app.js";
import { SimulatedInvitationEmailProvider } from "./invitations/invitation-email-provider.js";
import { InvitationTokenKeyring } from "./invitations/invitation-token.js";
import { ResendInvitationEmailProvider } from "./invitations/resend-invitation-email-provider.js";
import { FirestoreWebhookReplayStore } from "./invitations/firestore-webhook-replay-store.js";
import {
  allowedOrigins,
  protectedSuperAdminUid,
  REGION,
  RUNTIME_SERVICE_ACCOUNT
} from "./config.js";

initializeApp();
const auth = getAuth();
const firestore = getFirestore();
const emulatorMode = process.env.FUNCTIONS_EMULATOR === "true";
const resendEnabledParameter = defineBoolean("RESEND_INVITATIONS_ENABLED", { default: false });
const resendApiKey = defineSecret("RESEND_API_KEY");
const resendWebhookSigningSecret = defineSecret("RESEND_WEBHOOK_SIGNING_SECRET");
const invitationTokenKeyV1 = defineSecret("INVITATION_TOKEN_KEY_V1");
const resendEnabled = !emulatorMode && resendEnabledParameter.value() === true;

function productionKeyring() {
  if (!resendEnabled) return null;
  const decoded = Buffer.from(invitationTokenKeyV1.value(), "base64");
  return decoded.length === 32 ? new InvitationTokenKeyring(new Map([[1, decoded]]), 1) : null;
}

const emulatorKeyring = emulatorMode
  ? new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 0x5a)]]), 1)
  : productionKeyring();
const invitationEmailProvider = emulatorMode
  ? new SimulatedInvitationEmailProvider()
  : new ResendInvitationEmailProvider({
    enabled: resendEnabled,
    ...(resendEnabled ? { apiKey: resendApiKey.value() } : {})
  });

const app = createAdminApp({
  verifyIdToken: (token, checkRevoked) => auth.verifyIdToken(token, checkRevoked),
  userDirectory: {
    listUsers: (maxResults, pageToken) => auth.listUsers(maxResults, pageToken),
    getUser: (uid) => auth.getUser(uid),
    getUserByEmail: (email) => auth.getUserByEmail(email),
    getUsers: (identifiers) => auth.getUsers(identifiers),
    updateUser: (uid, properties) => auth.updateUser(uid, properties),
    revokeRefreshTokens: (uid) => auth.revokeRefreshTokens(uid),
    createUser: (properties) => auth.createUser(properties)
  },
  protectedSuperAdminUid: emulatorMode ? "emulator-protected-super-admin" : protectedSuperAdminUid(),
  invitationTokens: emulatorKeyring,
  invitationEmailProvider,
  resendWebhook: {
    enabled: resendEnabled,
    ...(resendEnabled ? {
      secret: resendWebhookSigningSecret.value(),
      replayStore: new FirestoreWebhookReplayStore(firestore)
    } : {})
  },
  origins: allowedOrigins(),
  firestore
});

export const adminApi = onRequest(
  {
    region: REGION,
    serviceAccount: RUNTIME_SERVICE_ACCOUNT,
    minInstances: 0,
    maxInstances: 10,
    timeoutSeconds: 30,
    memory: "256MiB",
    secrets: [resendApiKey, resendWebhookSigningSecret, invitationTokenKeyV1]
  },
  app
);
