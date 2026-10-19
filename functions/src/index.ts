import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { onRequest } from "firebase-functions/v2/https";
import { createAdminApp } from "./app.js";
import { allowedOrigins, REGION } from "./config.js";

initializeApp();

const app = createAdminApp({
  verifyIdToken: (token, checkRevoked) => getAuth().verifyIdToken(token, checkRevoked),
  origins: allowedOrigins()
});

export const adminApi = onRequest(
  {
    region: REGION,
    minInstances: 0,
    maxInstances: 10,
    timeoutSeconds: 30,
    memory: "256MiB"
  },
  app
);
