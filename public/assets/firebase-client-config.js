export const firebaseConfig = Object.freeze({
  apiKey: "AIzaSyDikisZF9JGhawLDZhLv-HIakBkxTU98w8",
  authDomain: "plcocina-apps.firebaseapp.com",
  projectId: "plcocina-apps",
  storageBucket: "plcocina-apps.firebasestorage.app",
  messagingSenderId: "465339579029",
  googleIdentityClientId: "897508921555-gu0c5l6gi9o7hhokpimor6rvdtng5gko.apps.googleusercontent.com"
});

const LOCAL_PILOT_ORIGIN = "https://localhost:8443";

export function isLocalPilot(locationRef = globalThis.location) {
  return locationRef?.origin === LOCAL_PILOT_ORIGIN;
}

export function firebaseConfigForLocation(locationRef = globalThis.location) {
  if (!isLocalPilot(locationRef)) return firebaseConfig;
  return Object.freeze({
    ...firebaseConfig,
    authDomain: "demo-plcocina-apps.firebaseapp.com",
    projectId: "demo-plcocina-apps"
  });
}
