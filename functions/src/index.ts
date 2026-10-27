import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { onRequest } from "firebase-functions/v2/https";
import { createAdminApp } from "./app.js";
import {
  DisabledInvitationEmailProvider,
  SimulatedInvitationEmailProvider
} from "./invitations/invitation-email-provider.js";
import { InvitationTokenKeyring } from "./invitations/invitation-token.js";
import {
  allowedOrigins,
  protectedSuperAdminUid,
  REGION,
  RUNTIME_SERVICE_ACCOUNT
} from "./config.js";

initializeApp();
const auth = getAuth();
const firestore = getFirestore();
const emulatorMode =
  process.env.FUNCTIONS_EMULATOR === "true"
  && process.env.GCLOUD_PROJECT === "demo-plcocina-apps";

const invitationTokens = emulatorMode
  ? new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 0x5a)]]), 1)
  : null;
const invitationEmailProvider = emulatorMode
  ? new SimulatedInvitationEmailProvider()
  : new DisabledInvitationEmailProvider();

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
  invitationTokens,
  invitationEmailProvider,
  resendWebhook: { enabled: false },
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
    memory: "256MiB"
  },
  app
);
