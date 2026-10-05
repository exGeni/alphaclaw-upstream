// Refuter blocker B1 (OpenClaw 2026.9.6+ drain model): during a shutdown the
// gateway may drain for minutes while AlphaClaw keeps logging progress. When
// the reader of AlphaClaw's stdout dies first (start.sh's `| tee` takes the
// same SIGTERM), every console.log raises EPIPE. Unhandled, that became
// uncaughtException → gracefulExit re-entry → killGatewayNow, i.e. a SIGKILL
// of the draining gateway within milliseconds. This drives the REAL
// server-lifecycle module in a real child process whose stdout is a pipe
// whose reader is gone, and checks the drain runs to its end.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const kLifecyclePath = path.resolve(__dirname, "../../lib/server/init/server-lifecycle.js");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const pollUntil = async (predicate, { timeoutMs = 10_000, label = "condition" } = {}) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await sleep(50);
  }
  throw new Error(`Timed out waiting for ${label}`);
};

describe("server-lifecycle: stdout EPIPE during a shutdown drain (B1)", () => {
  let dir = null;
  let shell = null;
  afterEach(() => {
    try {
      process.kill(-shell.pid, "SIGKILL");
    } catch {}
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("keeps draining and never SIGKILLs the gateway when stdout's reader died", async () => {
    if (process.platform === "win32") return;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "alphaclaw-epipe-"));
    const notes = path.join(dir, "notes.txt");
    const pidFile = path.join(dir, "node.pid");
    const script = path.join(dir, "child.js");
    fs.writeFileSync(
      script,
      [
        'const fs = require("fs");',
        `const note = (s) => fs.appendFileSync(${JSON.stringify(notes)}, s + "\\n");`,
        `const { createServerLifecycle } = require(${JSON.stringify(kLifecyclePath)});`,
        `fs.writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));`,
        "const lc = createServerLifecycle({",
        "  server: null,",
        "  stopGateway: async () => {",
        "    // stands in for stopGatewayForShutdown: progress logs during a 1.5s drain",
        "    const t = setInterval(() => console.log('[alphaclaw] gateway shutdown stop: still draining'), 20);",
        "    await new Promise((r) => setTimeout(r, 1500));",
        "    clearInterval(t);",
        "    note('drain completed');",
        "  },",
        "  killGatewayNow: () => note('killGatewayNow'),",
        "  exitImpl: (code) => { note('exit ' + code); process.exit(code); },",
        "  shutdownDeadlineMs: 60_000,",
        "});",
        "lc.installCrashGuards();",
        "console.log('ready');",
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );
    // `head -c 1` reads the first byte and exits: from then on the node
    // process writes into a pipe without a reader (EPIPE on every write).
    shell = spawn("bash", ["-c", `${JSON.stringify(process.execPath)} ${JSON.stringify(script)} | head -c 1 > /dev/null; sleep 30`], {
      stdio: "ignore",
      detached: true,
    });
    await pollUntil(() => fs.existsSync(pidFile), { label: "child pid file" });
    const nodePid = Number(fs.readFileSync(pidFile, "utf8"));
    await sleep(300); // head has consumed "ready" and exited
    process.kill(nodePid, "SIGTERM");
    await pollUntil(() => fs.existsSync(notes) && fs.readFileSync(notes, "utf8").includes("exit "), {
      label: "child exit note",
    });
    const lines = fs.readFileSync(notes, "utf8").trim().split("\n");
    expect(lines).toEqual(["drain completed", "exit 0"]);
  }, 20_000);
});
