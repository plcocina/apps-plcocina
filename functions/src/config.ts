export const PROJECT_ID = "plcocina-apps";
export const REGION = "us-central1";
export const RUNTIME_SERVICE_ACCOUNT =
  "portal-admin-api@plcocina-apps.iam.gserviceaccount.com";
export const ADMIN_API_VERSION = "2A";

const PRODUCTION_ORIGINS = ["https://apps.plcocina.com"];
const EMULATOR_ORIGINS = [
  "http://127.0.0.1:5000",
  "http://localhost:5000",
  "http://127.0.0.1:5002",
  "http://localhost:5002"
];

export function allowedOrigins(): ReadonlySet<string> {
  const origins = [...PRODUCTION_ORIGINS];
  if (process.env.FUNCTIONS_EMULATOR === "true" || process.env.NODE_ENV === "test") {
    origins.push(...EMULATOR_ORIGINS);
  }
  return new Set(origins);
}
