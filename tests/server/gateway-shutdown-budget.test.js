// Shutdown stop budget: ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT, default 6 s
// (process deadline 10 s, upstream's fixed values), clamped 6..900, deployment
// env only, read at module load. The process deadline is the budget + 4 s.
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { kDeploymentOnlyEnvKeys } = require("../../lib/server/deployment-only-env");

const kConstantsPath = require.resolve("../../lib/server/constants");
const loadBudgets = (value) => {
  delete require.cache[kConstantsPath];
  if (value === undefined) vi.stubEnv("ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT", undefined);
  else vi.stubEnv("ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT", value);
  const { kGatewayShutdownStopBudgetMs, kProcessShutdownDeadlineMs } = require("../../lib/server/constants");
  return [kGatewayShutdownStopBudgetMs, kProcessShutdownDeadlineMs];
};

describe("shutdown stop budget", () => {
  let warn;
  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    delete require.cache[kConstantsPath];
  });

  it("defaults to 6 s with a 10 s process deadline and honours a value inside 6..900", () => {
    expect(loadBudgets(undefined)).toEqual([6_000, 10_000]);
    expect(loadBudgets("335")).toEqual([335_000, 339_000]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("clamps to 6..900 and warns; junk falls back to 6 s and warns", () => {
    expect(loadBudgets("2")).toEqual([6_000, 10_000]);
    expect(loadBudgets("1200")).toEqual([900_000, 904_000]);
    expect(loadBudgets("five")).toEqual([6_000, 10_000]);
    expect(warn.mock.calls.map(([line]) => line)).toEqual([
      "[alphaclaw] ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT=2 clamped to 6s (valid range 6-900)",
      "[alphaclaw] ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT=1200 clamped to 900s (valid range 6-900)",
      "[alphaclaw] ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT=five not a positive integer — falling back to 6s (valid range 6-900)",
    ]);
  });

  it("treats empty and whitespace as unset and honours the bounds silently", () => {
    expect(loadBudgets("")).toEqual([6_000, 10_000]);
    expect(loadBudgets("  ")).toEqual([6_000, 10_000]);
    expect(loadBudgets(" 335 ")).toEqual([335_000, 339_000]);
    expect(loadBudgets("6")).toEqual([6_000, 10_000]);
    expect(loadBudgets("900")).toEqual([900_000, 904_000]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("warns when a written value is normalized", () => {
    expect(loadBudgets("335s")).toEqual([335_000, 339_000]);
    expect(warn.mock.calls.map(([line]) => line)).toEqual([
      "[alphaclaw] ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT=335s normalized to 335s (valid range 6-900)",
    ]);
  });

  it("is deployment env only", () => {
    expect(kDeploymentOnlyEnvKeys).toContain("ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT");
  });
});

// server.js is not unit-loadable; without these two lines the lifecycle and the
// self-update drain fall back to their fixed 10 s defaults and the gateway is
// SIGKILLed mid-shutdown again whatever the env says.
describe("shutdown deadline wiring (lib/server.js)", () => {
  const source = readFileSync(path.join(__dirname, "..", "..", "lib", "server.js"), "utf8");
  it("passes the derived deadline to the lifecycle and to the self-update drain", () => {
    expect(source).toContain("shutdownDeadlineMs: constants.kProcessShutdownDeadlineMs");
    expect(source).toContain("drainDeadlineMs: constants.kProcessShutdownDeadlineMs");
  });
});

describe("shutdown ladder split (gateway.js shutdownLadderGraces)", () => {
  const { shutdownLadderGraces } = require("../../lib/server/gateway");
  it("keeps upstream's 3.6 s / 1.8 s split for the 6 s default", () => {
    expect(shutdownLadderGraces(6_000)).toEqual({ termGraceMs: 3_600, killGraceMs: 1_800 });
  });
  it("gives a long budget to SIGTERM so OpenClaw's 325 s stop budget fits before any SIGKILL", () => {
    const { termGraceMs, killGraceMs } = shutdownLadderGraces(335_000);
    expect(killGraceMs).toBe(5_000);
    expect(termGraceMs).toBe(329_000);
    expect(termGraceMs).toBeGreaterThanOrEqual(325_000);
  });
  it("never lets the stages outrun the budget and keeps the old floors", () => {
    for (const budgetMs of [1_000, 6_000, 20_000, 335_000, 900_000]) {
      const { termGraceMs, killGraceMs } = shutdownLadderGraces(budgetMs);
      expect(termGraceMs + killGraceMs).toBeLessThanOrEqual(Math.max(budgetMs, 1_500));
    }
    expect(shutdownLadderGraces(1_000)).toEqual({ termGraceMs: 1_000, killGraceMs: 500 });
  });
});
