import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/invitation-emulator.test.ts", "test/access-grant-emulator.test.ts", "test/identity-reservation.emulator.test.ts"],
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 20_000
  }
});
