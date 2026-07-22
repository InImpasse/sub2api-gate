import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser-tests",
  outputDir: "../.local/browser-ui-gate/playwright-output",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: [
    ["line"],
    ["html", { outputFolder: "../.local/browser-ui-gate/report", open: "never" }],
  ],
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
    reducedMotion: "reduce",
    launchOptions: {
      args: [
        "--host-resolver-rules=MAP api.example.test 127.0.0.1",
        "--ignore-certificate-errors",
        "--no-proxy-server",
      ],
    },
  },
});
