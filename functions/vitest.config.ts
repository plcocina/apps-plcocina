import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    exclude: ["test/**/*.rules.test.ts", "test/**/*.emulator.test.ts", "test/invitation-emulator.test.ts", "test/access-grant-emulator.test.ts"],
    coverage: {
      enabled: false
    }
  }
});
