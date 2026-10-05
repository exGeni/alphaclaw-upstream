// Refuter round 2 (M3/i, M3/j): the deadlines that CONTAIN the gateway stop
// must be wired from constants.js in lib/server.js, which boots the whole
// process on require — so its composition is pinned at the SOURCE level here
// (the idiom server-wiring-gateway-seams.test.js uses), and the derived
// values are checked against the constants themselves.
const fs = require("fs");
const path = require("path");
const constants = require("../../lib/server/constants");

const serverSource = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "server.js"), "utf8");

const callArgs = (source, callee) => {
  const start = source.indexOf(`${callee}({`);
  expect(start, `${callee}({ not found in lib/server.js`).toBeGreaterThan(-1);
  let depth = 0;
  for (let i = start + callee.length; i < source.length; i += 1) {
    if (source[i] === "(") depth += 1;
    if (source[i] === ")") {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`unbalanced ${callee} call`);
};

describe("gateway stop deadline wiring (lib/server.js)", () => {
  it("createServerLifecycle gets shutdownDeadlineMs = kProcessShutdownDeadlineMs (outlives the shutdown stop)", () => {
    const args = callArgs(serverSource, "createServerLifecycle");
    expect(args).toMatch(/\bshutdownDeadlineMs:\s*constants\.kProcessShutdownDeadlineMs\b/);
    expect(args).toMatch(/\bstopGateway:\s*stopGatewayForShutdown\b/);
    expect(constants.kProcessShutdownDeadlineMs).toBeGreaterThan(constants.kGatewayShutdownStopBudgetMs);
  });

  it("the self-update drain race gets drainDeadlineMs = kProcessShutdownDeadlineMs", () => {
    const args = callArgs(serverSource, "createAlphaclawVersionService");
    expect(args).toMatch(/\bdrainDeadlineMs:\s*constants\.kProcessShutdownDeadlineMs\b/);
  });

  it("deadline chain with defaults: launcher 330s < shutdown stop 335s < process deadline 345s < platform grace floor 360s", () => {
    expect(constants.kOpenclawGatewayServiceStopBudgetMs).toBe(330_000);
    expect(constants.kGatewayShutdownStopBudgetMs).toBe(335_000);
    expect(constants.kProcessShutdownDeadlineMs).toBe(345_000);
    expect(constants.kPlatformStopGraceFloorMs).toBe(360_000);
  });
});
