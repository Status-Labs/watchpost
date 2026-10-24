import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const alias = { "@": fileURLToPath(new URL("./src", import.meta.url)) };

export default defineConfig({
  resolve: { alias },
  test: {
    exclude: ["**/node_modules/**", "logo/**", ".claude/**"],
    projects: [
      {
        resolve: { alias },
        test: {
          name: "unit",
          include: ["src/**/*.test.ts"],
          exclude: ["src/**/*.int.test.ts"],
          setupFiles: ["test/setup.ts"],
        },
      },
      {
        resolve: { alias },
        test: {
          name: "integration",
          include: ["src/**/*.int.test.ts", "test/**/*.int.test.ts"],
          setupFiles: ["test/setup.ts"],
          globalSetup: ["test/global-setup.ts"],
          testTimeout: 60_000,
          hookTimeout: 120_000,
          // Tests share one database, so files run one at a time.
          fileParallelism: false,
        },
      },
    ],
  },
});
