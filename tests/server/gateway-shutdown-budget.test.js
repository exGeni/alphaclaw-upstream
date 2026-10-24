// Shutdown stop budget: ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT, default 6 s
// (process deadline 10 s, upstream's fixed values), clamped 6..900, deployment
// env only, read at module load. The process deadline is the budget + 4 s.
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

  it("is deployment env only", () => {
    expect(kDeploymentOnlyEnvKeys).toContain("ALPHACLAW_GATEWAY_SHUTDOWN_STOP_TIMEOUT");
  });
});
