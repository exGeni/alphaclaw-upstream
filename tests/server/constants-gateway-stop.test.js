// Gateway stop budgets (OpenClaw 2026.9.6+ drain model, refuter finding M2):
// ALPHACLAW_GATEWAY_STOP_TIMEOUT (restart) and
// ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT (AlphaClaw exiting) are read at
// module load, clamped 10-900s. Restart default 345s = upstream's 330s
// service stop budget (gateway-shutdown-budget.mjs
// GATEWAY_SERVICE_STOP_TIMEOUT_MS) + 15s; shutdown default 335s = 330 + 5,
// so the process deadline is 345s and the platform grace floor 360s.
// Every number that CONTAINS a stop must be derived from them.
const constantsModulePath = "../../lib/server/constants";
const { kDeploymentOnlyEnvKeys } = require("../../lib/server/deployment-only-env");

const kKeys = ["ALPHACLAW_GATEWAY_STOP_TIMEOUT", "ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT"];

const loadConstants = () => {
  vi.resetModules();
  delete require.cache[require.resolve(constantsModulePath)];
  return require(constantsModulePath);
};

describe("gateway stop budgets (module-load read)", () => {
  let saved = null;
  beforeEach(() => {
    saved = Object.fromEntries(kKeys.map((key) => [key, process.env[key]]));
    for (const key of kKeys) delete process.env[key];
  });
  afterEach(() => {
    for (const key of kKeys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    delete require.cache[require.resolve(constantsModulePath)];
  });

  it("defaults: restart 330s + 15s, shutdown 330s + 5s (deadline chain 330 < 335 < 345 < 360), silently", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const c = loadConstants();
    expect(c.kOpenclawGatewayServiceStopBudgetMs).toBe(330_000);
    expect(c.kGatewayStopBudgetMs).toBe(345_000);
    expect(c.kGatewayShutdownStopBudgetMs).toBe(335_000);
    expect(c.kProcessShutdownDeadlineMs).toBe(345_000);
    expect(c.kPlatformStopGraceFloorMs).toBe(360_000);
    expect(c.kGatewayDrainingReadinessBudgetMs).toBe(345_000);
    expect(
      warn.mock.calls.map(([line]) => String(line)).filter((line) => line.includes("STOP_TIMEOUT")),
    ).toEqual([]);
  });

  it("derives the process shutdown deadline and the restart operation budget from the stop budgets", () => {
    const c = loadConstants();
    // The shutdown deadline must outlive the gateway stop it contains.
    expect(c.kProcessShutdownDeadlineMs).toBe(c.kGatewayShutdownStopBudgetMs + 10_000);
    expect(c.kProcessShutdownDeadlineMs).toBeGreaterThan(c.kGatewayShutdownStopBudgetMs);
    // The restart operation (lock lease, record lifetime, suppression
    // windows) must cover preflight + stop/release wait + ready wait.
    expect(c.kGatewayRestartOperationBudgetMs).toBeGreaterThanOrEqual(
      c.kGatewayRestartReadyTimeoutMs + 240_000 + c.kGatewayStopBudgetMs,
    );
  });

  it("honours operator values, each knob independently", () => {
    process.env.ALPHACLAW_GATEWAY_STOP_TIMEOUT = "120";
    process.env.ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT = "25";
    const c = loadConstants();
    expect(c.kGatewayStopBudgetMs).toBe(120_000);
    expect(c.kGatewayShutdownStopBudgetMs).toBe(25_000);
    expect(c.kProcessShutdownDeadlineMs).toBe(35_000);
  });

  it("clamps out-of-range values into 10-900s and warns", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.ALPHACLAW_GATEWAY_STOP_TIMEOUT = "2";
    process.env.ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT = "5000";
    const c = loadConstants();
    expect(c.kGatewayStopBudgetMs).toBe(10_000);
    expect(c.kGatewayShutdownStopBudgetMs).toBe(900_000);
    const lines = warn.mock.calls.map(([line]) => String(line));
    expect(lines).toContain("[alphaclaw] ALPHACLAW_GATEWAY_STOP_TIMEOUT=2 clamped to 10s (valid range 10-900)");
    expect(lines).toContain(
      "[alphaclaw] ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT=5000 clamped to 900s (valid range 10-900)",
    );
  });

  it("falls back to the default on junk and says so", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.ALPHACLAW_GATEWAY_STOP_TIMEOUT = "five minutes";
    const c = loadConstants();
    expect(c.kGatewayStopBudgetMs).toBe(345_000);
    expect(warn.mock.calls.map(([line]) => String(line))).toContain(
      "[alphaclaw] ALPHACLAW_GATEWAY_STOP_TIMEOUT=five minutes not a positive integer — falling back to 345s (valid range 10-900)",
    );
  });

  it("both knobs are deployment-env only (an agent-writable .env must not shrink them)", () => {
    for (const key of kKeys) expect(kDeploymentOnlyEnvKeys).toContain(key);
  });
});
