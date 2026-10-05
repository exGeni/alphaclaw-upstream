// Real-process gateway reap e2e: the REAL lib/server/gateway.js module
// (required in-process, child_process NOT mocked) driving REAL child
// processes through a PATH-shimmed fake `openclaw` CLI. This is the
// real-process proof for three shutdown behaviors that unit tests only
// model:
//   1. stopGatewayChildAndWait SIGKILL escalation past Node's `.killed`
//      flag (set on SIGTERM SEND) against a child that really ignores
//      SIGTERM — the v0.9.36 escalation fix.
//   2. stopGatewayForShutdown cancelling an in-flight execOpenclaw CLI
//      call: the lifecycle-lock abort must SIGTERM the real execFile child
//      and complete well inside the 10s shutdown deadline.
//   3. runGatewayRestartCmd abort wiring: a SIGTERM-trapping restart
//      supervisor spawn must be reaped by the 3s SIGKILL escalation timer
//      after shutdown aborts the lifecycle signal.
//   4. resolveServingIdentity against the REAL /proc: a launcher→worker tree
//      resolves to its root, worker and start ticks, and the ticks change
//      when the child is replaced (the watchdog's pid-reuse guard).
//
// gatewayEnv() spreads process.env at spawn/exec time, so prepending a tmp
// bin dir holding an executable `openclaw` script to process.env.PATH makes
// every real spawn/execFile resolve the shim. ALPHACLAW_ROOT_DIR must be set
// before ANY lib/server require — constants.js captures kRootDir at load.

const fs = require("fs");
const os = require("os");
const path = require("path");

const kTmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "alphaclaw-gw-reap-"));
process.env.ALPHACLAW_ROOT_DIR = kTmpRoot;
// The restart stop budget at its 10s floor so the over-budget cold-restart
// cases run in seconds (explicit budgetMs drives the direct stop cases).
process.env.ALPHACLAW_GATEWAY_STOP_TIMEOUT = "10";

const { OPENCLAW_DIR, kGatewayStopBudgetMs } = require("../../lib/server/constants");
// constants.js read it at load; never leak it into another file's process.
delete process.env.ALPHACLAW_GATEWAY_STOP_TIMEOUT;
const lockContention = require("../../lib/server/openclaw-lock-contention");
const {
  readProcStartTicks,
  readProcParentPid,
} = lockContention;

if (!OPENCLAW_DIR.startsWith(kTmpRoot)) {
  // constants.js was already loaded with a different root — the tests below
  // would touch a real ~/.alphaclaw. Fail loudly instead of proceeding.
  throw new Error(
    `constants.js captured OPENCLAW_DIR=${OPENCLAW_DIR}; expected it under ${kTmpRoot}. ` +
      "ALPHACLAW_ROOT_DIR must be set before any lib/server require.",
  );
}

// Module-level gateway state (gatewayChild, the lifecycle lock's cancelled
// latch) persists per require — every test gets a fresh module instance.
const kGatewayModulePath = require.resolve("../../lib/server/gateway");
const loadGateway = () => {
  delete require.cache[kGatewayModulePath];
  return require(kGatewayModulePath);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const pollUntil = async (
  predicate,
  { timeoutMs = 8000, intervalMs = 50, label = "condition" } = {},
) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(intervalMs);
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`);
};

const isPidAlive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const readPid = (file) => {
  try {
    const pid = Number.parseInt(fs.readFileSync(file, "utf8").trim(), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
};

describe("gateway reap e2e (real child processes via PATH-shimmed openclaw)", () => {
  let caseDir = null;
  let originalPath = null;
  let gateway = null;
  let trackedPids = null;

  const trackPid = (pid) => {
    if (Number.isInteger(pid) && pid > 0) trackedPids.push(pid);
    return pid;
  };

  // Writes an executable fake `openclaw` into a per-test bin dir and
  // prepends it to process.env.PATH; gatewayEnv() reads process.env at call
  // time, so every subsequent spawn/execFile resolves this shim.
  const installOpenclawShim = (scriptBody) => {
    const binDir = path.join(caseDir, "bin");
    fs.mkdirSync(binDir, { recursive: true });
    const shimPath = path.join(binDir, "openclaw");
    fs.writeFileSync(shimPath, scriptBody, { mode: 0o755 });
    process.env.PATH = `${binDir}${path.delimiter}${process.env.PATH}`;
    return shimPath;
  };

  // Scope the real /proc scan to this fixture's argv while retaining the
  // real scan, ancestry and start-tick reads: a user's gateway (or the live
  // stack) may share the host and must never enter a fixture's evidence.
  const scopeProcessScanToCase = () => {
    const scanProcesses = lockContention.listLiveOpenclawProcesses;
    vi.spyOn(lockContention, "listLiveOpenclawProcesses").mockImplementation((options = {}) =>
      scanProcesses({
        ...options,
        match: (argv) => argv.some((arg) => arg.startsWith(`${caseDir}${path.sep}`)) &&
          (!options.match || options.match(argv)),
      }),
    );
  };

  beforeEach(() => {
    originalPath = process.env.PATH;
    trackedPids = [];
    caseDir = fs.mkdtempSync(path.join(kTmpRoot, "case-"));
    // Minimal openclaw.json: no enabled channels (plugin preflight — the
    // only other CLI traffic — is skipped) and a unique high gateway port
    // that nothing listens on, so isGatewayRunning()/waitForGatewayReady
    // poll a connection-refused loopback port instead of the shared 18789.
    fs.mkdirSync(OPENCLAW_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(OPENCLAW_DIR, "openclaw.json"),
      JSON.stringify({
        gateway: { port: 39000 + Math.floor(Math.random() * 2000) },
        channels: {},
      }),
    );
  });

  afterEach(async () => {
    // Belt and braces: reap the managed child through the module, then
    // SIGKILL every shim pid the test recorded. SIGKILL is the last resort —
    // a passing test has already observed each pid dead.
    if (gateway) {
      try {
        gateway.stopGatewayChild({ signal: "SIGKILL", force: true });
      } catch {}
      gateway = null;
    }
    for (const pid of trackedPids) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {}
    }
    // Last resort for fixture grandchildren no pidfile named (a listener
    // re-parented after its worker died): every process whose argv lives
    // under this file's private tmp root is ours to reap.
    if (process.platform === "linux") {
      for (const name of fs.readdirSync("/proc")) {
        if (!/^\d+$/.test(name) || Number(name) === process.pid) continue;
        let cmdline = "";
        try {
          cmdline = fs.readFileSync(`/proc/${name}/cmdline`, "utf8");
        } catch {
          continue;
        }
        if (cmdline.includes(kTmpRoot)) {
          try {
            process.kill(Number(name), "SIGKILL");
          } catch {}
        }
      }
    }
    process.env.PATH = originalPath;
    delete require.cache[kGatewayModulePath];
  });

  afterAll(() => {
    fs.rmSync(kTmpRoot, { recursive: true, force: true });
  });

  it("SIGKILL-escalates a managed gateway child that ignores SIGTERM (stopGatewayChildAndWait)", async () => {
    // The fake `gateway run` execs (same PID) into a node process that
    // installs a SIGTERM no-op handler BEFORE writing its pidfile — pidfile
    // presence guarantees the trap is armed when the test sends SIGTERM.
    const pidFile = path.join(caseDir, "run.pid");
    const helperPath = path.join(caseDir, "ignore-sigterm.js");
    fs.writeFileSync(
      helperPath,
      [
        'process.on("SIGTERM", () => {});',
        `require("fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));`,
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );
    installOpenclawShim(
      [
        "#!/bin/sh",
        'if [ "$1" = "gateway" ] && [ "$2" = "run" ]; then',
        `  exec ${JSON.stringify(process.execPath)} ${JSON.stringify(helperPath)}`,
        "fi",
        "exit 0",
        "",
      ].join("\n"),
    );

    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    expect(child).toBeTruthy();
    trackPid(child.pid);

    // The shim resolved via gatewayEnv()'s PATH and exec'd in place: the
    // pidfile the helper writes must carry the exact spawned pid.
    await pollUntil(() => readPid(pidFile) === child.pid, {
      label: "gateway-run shim pidfile with the spawned pid",
    });
    expect(isPidAlive(child.pid)).toBe(true);

    const startedAt = Date.now();
    // budgetMs stands in for the 345s production stop budget.
    const stopped = await gateway.stopGatewayChildAndWait({ budgetMs: 300 });
    const elapsedMs = Date.now() - startedAt;

    // child.kill("SIGTERM") set `.killed` on SEND; the pre-fix guard would
    // have skipped the SIGKILL entirely and left the SIGTERM-ignoring child
    // alive. A dead real pid whose exit was BY SIGKILL is the proof the
    // escalation actually delivered — and exited() observes signal deaths
    // (signalCode, not just exitCode), so the reap reports success instead
    // of polling out its budget.
    expect(isPidAlive(child.pid)).toBe(false);
    await pollUntil(() => child.signalCode === "SIGKILL", {
      timeoutMs: 2000,
      label: "exit event with signalCode SIGKILL",
    });
    expect(child.signalCode).toBe("SIGKILL");
    expect(stopped).toBe(true);
    // SIGTERM alone cannot have done it: the stop budget had to elapse
    // first (the helper ignores SIGTERM), and the whole stop stays bounded.
    expect(elapsedMs).toBeGreaterThanOrEqual(250);
    expect(elapsedMs).toBeLessThan(5000);
  });

  it("stopGatewayForShutdown aborts an in-flight CLI call and the real execFile child dies", async () => {
    // First `gateway stop` records its pid and sleeps 60s (exec keeps the
    // pid). Any later `gateway stop` — stopGatewayForShutdown's best-effort
    // trailing exec — sees the pidfile and exits 0 immediately, so the
    // measured shutdown time is the abort path, not a second hang.
    const pidFile = path.join(caseDir, "stop.pid");
    installOpenclawShim(
      [
        "#!/bin/sh",
        'if [ "$1" = "gateway" ] && [ "$2" = "stop" ]; then',
        `  if [ -f ${JSON.stringify(pidFile)} ]; then exit 0; fi`,
        `  echo $$ > ${JSON.stringify(pidFile)}`,
        "  exec sleep 60",
        "fi",
        "exit 0",
        "",
      ].join("\n"),
    );

    gateway = loadGateway();
    const cmdPromise = gateway.runGatewayCmd("stop");

    await pollUntil(() => readPid(pidFile) !== null, {
      label: "in-flight gateway-stop shim pidfile",
    });
    const cliPid = trackPid(readPid(pidFile));
    expect(isPidAlive(cliPid)).toBe(true);

    const startedAt = Date.now();
    await gateway.stopGatewayForShutdown();
    const elapsedMs = Date.now() - startedAt;

    // The lock cancel aborted the op's signal; Node's native execFile abort
    // SIGTERMed the shim, and the callback (and therefore the cancel await)
    // only fires after the child closed — the 60s sleep never ran out.
    expect(elapsedMs).toBeLessThan(5000);
    expect(isPidAlive(cliPid)).toBe(false);
    // The op promise settles cleanly (execOpenclaw resolves ok:false on
    // abort — never rejects into an unhandled rejection).
    await expect(cmdPromise).resolves.toBeUndefined();
  });

  it("reaps a SIGTERM-trapping restart supervisor via the 3s SIGKILL escalation timer", async () => {
    // `gateway --force` (the cold-start supervisor spawn) ignores SIGTERM:
    // `trap '' TERM` sets SIG_IGN, which survives exec into sleep. The
    // abort's immediate child.kill("SIGTERM") is therefore a no-op and only
    // the 3s unref'd killTimer's SIGKILL can reap it. `gateway stop` (issued
    // by runGatewayColdStart before the spawn and by the best-effort
    // shutdown exec after) exits 0 immediately.
    // The cold restart's release wait scans /proc for the OLD gateway's
    // serving processes; scope it to this fixture so a real gateway sharing
    // the host is never taken for the incumbent.
    scopeProcessScanToCase();
    const pidFile = path.join(caseDir, "supervisor.pid");
    installOpenclawShim(
      [
        "#!/bin/sh",
        'if [ "$1" = "gateway" ] && [ "$2" = "--force" ]; then',
        "  trap '' TERM",
        `  echo $$ > ${JSON.stringify(pidFile)}`,
        "  exec sleep 60",
        "fi",
        "exit 0",
        "",
      ].join("\n"),
    );

    gateway = loadGateway();
    const restartPromise = gateway.restartGateway(() => {});

    await pollUntil(() => readPid(pidFile) !== null, {
      label: "restart supervisor shim pidfile",
    });
    const supervisorPid = trackPid(readPid(pidFile));
    expect(isPidAlive(supervisorPid)).toBe(true);

    const startedAt = Date.now();
    await gateway.stopGatewayForShutdown();
    const shutdownMs = Date.now() - startedAt;

    // Shutdown must not wait for the supervisor: the abort check inside
    // waitForGatewayReady ends the 120s ready poll within one 500ms tick.
    expect(shutdownMs).toBeLessThan(5000);
    // The cancelled restart settles deterministically — as an HONEST failure
    // carrying abort evidence, never a silent success over a dead gateway
    // (this branch's restart contract: outcomes are never fabricated).
    await expect(restartPromise).rejects.toMatchObject({
      name: "GatewayRestartError",
      evidence: expect.objectContaining({ aborted: true }),
    });

    // The killTimer fires 3s after abort — the supervisor survived SIGTERM
    // (proving the trap held) and must then die to the real SIGKILL.
    if (shutdownMs < 2500) {
      expect(isPidAlive(supervisorPid)).toBe(true);
    }
    await pollUntil(() => !isPidAlive(supervisorPid), {
      timeoutMs: 6000,
      intervalMs: 100,
      label: "supervisor reaped by SIGKILL escalation",
    });
  });

  it("resolveServingIdentity sees the real launcher→worker tree with start ticks, and the ticks change when the child is replaced", async () => {
    if (process.platform !== "linux") return;
    // Scope discovery to this fixture's real argv while retaining the real
    // /proc scan, ancestry and start-tick reads. A user's gateway or the live
    // memory suite may share the host: production correctly refuses their
    // multiple roots, but they are not part of this isolated tree fixture.
    scopeProcessScanToCase();
    // The fake `gateway run` mirrors the real launcher shape: the shim (sh,
    // argv "…/bin/openclaw gateway run" — a serving-pattern root) stays alive
    // as the process-tree root and forwards TERM to its worker, a second
    // shell script also NAMED `openclaw` (argv "…/worker/openclaw gateway
    // run"), so the worker satisfies both the serving-pattern scan and
    // resolveFirstChildPid's kernel-comm filter (`Name: openclaw` — a shebang
    // script's comm is its basename; a node worker would read `MainThread`).
    const workerDir = path.join(caseDir, "worker");
    fs.mkdirSync(workerDir, { recursive: true });
    const workerScript = path.join(workerDir, "openclaw");
    const pidFile = path.join(caseDir, "worker.pid");
    fs.writeFileSync(
      workerScript,
      [
        "#!/bin/sh",
        `echo $$ > ${JSON.stringify(pidFile)}`,
        "sleep 60 &",
        "trap 'kill $! 2>/dev/null; exit 0' TERM INT",
        "wait",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    installOpenclawShim(
      [
        "#!/bin/sh",
        'if [ "$1" = "gateway" ] && [ "$2" = "run" ]; then',
        `  ${JSON.stringify(workerScript)} gateway run &`,
        "  worker=$!",
        "  trap 'kill $worker 2>/dev/null' TERM INT",
        "  wait $worker",
        "  exit 0",
        "fi",
        "exit 0",
        "",
      ].join("\n"),
    );
    const launchAndResolve = async () => {
      fs.rmSync(pidFile, { force: true });
      const child = await gateway.launchGatewayProcess();
      expect(child).toBeTruthy();
      trackPid(child.pid);
      await pollUntil(() => readPid(pidFile) !== null, { label: "worker pidfile" });
      const workerPid = trackPid(readPid(pidFile));
      return { child, workerPid, identity: gateway.resolveServingIdentity() };
    };

    gateway = loadGateway();
    const first = await launchAndResolve();

    expect(first.identity).toEqual({
      rootPid: first.child.pid,
      workerPid: first.workerPid,
      startTicks: expect.any(Number),
      pids: expect.arrayContaining([first.child.pid, first.workerPid]),
    });
    expect(first.identity.pids).toHaveLength(2);
    // The root's ticks come from the real /proc/<pid>/stat; the worker's
    // parent really is the launcher.
    expect(readProcStartTicks(first.child.pid)).toBe(first.identity.startTicks);
    expect(readProcParentPid(first.workerPid)).toBe(first.child.pid);
    // A managed launch through the compat wrapper consumed generation 1.
    expect(gateway.getLaunchGeneration()).toBe(1);

    // Replace: SIGTERM the launcher (its trap takes the worker down), then
    // launch again. ≥ one 100 Hz clock tick apart so the successor's start
    // ticks are strictly greater — a reused pid number could never pass as
    // the same process.
    expect(await gateway.stopGatewayChildAndWait({ graceMs: 2000 })).toBe(true);
    await pollUntil(() => !isPidAlive(first.workerPid), {
      label: "worker reaped through the launcher's TERM trap",
    });
    expect(readProcStartTicks(first.child.pid)).toBeNull();
    await sleep(50);

    const second = await launchAndResolve();
    expect(second.child.pid).not.toBe(first.child.pid);
    expect(second.identity).toMatchObject({
      rootPid: second.child.pid,
      workerPid: second.workerPid,
    });
    expect(second.identity.startTicks).toBeGreaterThan(first.identity.startTicks);
    expect(gateway.getLaunchGeneration()).toBe(2);
  });

  // ── OpenClaw 2026.9.6+ drain model (refuter finding M2) ─────────────────
  // A fake launcher that behaves like 2026.9.8's `runRespawnedChild`: it
  // forwards SIGTERM to its worker (named `openclaw`, like the serving
  // gateway) and keeps waiting until the worker exits, then exits with the
  // worker's code. The worker "drains" for DRAIN seconds after SIGTERM
  // (DRAIN=never: it ignores SIGTERM) and, when LISTEN=1, holds the gateway
  // port through a node listener until it exits.
  const readGatewayPort = () =>
    JSON.parse(fs.readFileSync(path.join(OPENCLAW_DIR, "openclaw.json"), "utf8")).gateway.port;

  const stateLockPath = path.join(
    OPENCLAW_DIR,
    "tmp",
    typeof process.getuid === "function" ? `openclaw-${process.getuid()}` : "openclaw",
    "gateway.state.lock",
  );

  const installDrainingGateway = ({
    runDrain = "1",
    runListen = false,
    runHoldsState = false,
    forceDrain = "1",
    forceListen = true,
    // false: the launcher forwards SIGTERM and exits at once, leaving its
    // worker to drain alone (the worker outlives the launcher).
    launcherWaits = true,
    // Seconds the launcher waits before forking its worker (the window right
    // after spawn in which a stop finds no worker yet).
    workerDelay = null,
  } = {}) => {
    const port = readGatewayPort();
    fs.rmSync(stateLockPath, { force: true });
    const listenerPath = path.join(caseDir, "listen.js");
    fs.writeFileSync(
      listenerPath,
      [
        'const server = require("net").createServer((s) => s.destroy());',
        `server.listen(${port}, "127.0.0.1");`,
        'process.on("SIGTERM", () => server.close(() => process.exit(0)));',
      ].join("\n"),
    );
    const workerDir = path.join(caseDir, "worker");
    fs.mkdirSync(workerDir, { recursive: true });
    const workerScript = path.join(workerDir, "openclaw");
    fs.writeFileSync(
      workerScript,
      [
        "#!/bin/sh",
        // $3 = tag (run|force), $4 = drain seconds or "never", $5 = listen
        // 0|1, $6 = publish the state-ownership projection 0|1
        `echo $$ > ${JSON.stringify(caseDir)}/worker-$3.pid`,
        "listener=",
        `if [ "$5" = "1" ]; then ${JSON.stringify(process.execPath)} ${JSON.stringify(listenerPath)} & listener=$!; echo $listener > ${JSON.stringify(caseDir)}/listener-$3.pid; fi`,
        'if [ "$4" = "never" ]; then',
        "  trap '' TERM",
        // Orphan tell: if the launcher dies while this worker still lives
        // (a launcher-first SIGKILL), the worker's parent changes.
        "  while :; do",
        "    p=$(cut -d' ' -f4 /proc/$$/stat)",
        `    [ "$p" != "$PPID" ] && echo orphaned >> ${JSON.stringify(caseDir)}/worker-$3.orphaned`,
        "    sleep 0.05",
        "  done",
        "fi",
        // Upstream's state-ownership projection (docs/gateway/gateway-lock.md):
        // published at start, removed only AFTER the drain settles, while the
        // listener closes at once — exactly the order 2026.9.8 documents.
        `lockfile=${JSON.stringify(stateLockPath)}`,
        'if [ "$6" = "1" ]; then mkdir -p "$(dirname "$lockfile")"; printf \'{"pid":%s}\' $$ > "$lockfile"; fi',
        "sleep 60 & sleeper=$!",
        `trap '[ -n "$listener" ] && kill $listener 2>/dev/null; sleep "$4"; [ "$6" = "1" ] && rm -f "$lockfile"; kill $sleeper 2>/dev/null; date +%s%N > ${JSON.stringify(caseDir)}/worker-$3.exited; exit 0' TERM`,
        "wait $sleeper",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    installOpenclawShim(
      [
        "#!/bin/sh",
        'if [ "$1" = "gateway" ] && { [ "$2" = "run" ] || [ "$2" = "--force" ]; }; then',
        '  if [ "$2" = "run" ]; then tag=run; drain=' + JSON.stringify(runDrain) + "; listen=" + (runListen ? "1" : "0") + "; else tag=force; drain=" + JSON.stringify(forceDrain) + "; listen=" + (forceListen ? "1" : "0") + "; fi",
        ...(workerDelay !== null ? ["  trap 'term=1' TERM INT"] : []),
        `  date +%s%N > ${JSON.stringify(caseDir)}/launch-$tag.at`,
        '  if [ "$tag" = "run" ]; then state=' + (runHoldsState ? "1" : "0") + "; else state=0; fi",
        ...(workerDelay !== null ? [`  sleep ${workerDelay}`] : []),
        `  ${JSON.stringify(workerScript)} gateway run "$tag" "$drain" "$listen" "$state" &`,
        "  worker=$!",
        launcherWaits
          ? "  trap 'kill -TERM $worker 2>/dev/null' TERM INT"
          : "  trap 'kill -TERM $worker 2>/dev/null; exit 143' TERM INT",
        "  wait $worker; rc=$?",
        "  while kill -0 $worker 2>/dev/null; do wait $worker; rc=$?; done",
        "  exit $rc",
        "fi",
        "exit 0",
        "",
      ].join("\n"),
    );
    return { port };
  };

  const readNs = (file) => {
    try {
      return BigInt(fs.readFileSync(file, "utf8").trim());
    } catch {
      return null;
    }
  };

  it("non-adopted `gateway run` launcher: SIGTERM, then drain, then exit — no SIGKILL inside the budget, worker waited on", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    // 2.5s: longer than 9.5's 2s SIGKILL backstop the stop used to assume.
    installDrainingGateway({ runDrain: "2.5" });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "worker-run.pid")) !== null, { label: "worker pidfile" });
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    expect(gateway.isManagedGatewayChildSupervisor()).toBe(false);

    const startedAt = Date.now();
    const stopped = await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
    const elapsedMs = Date.now() - startedAt;

    expect(stopped).toBe(true);
    // The drain ran to completion (9.5's 2s SIGKILL would have cut it, and
    // the launcher alone exiting is not enough — the worker is waited on).
    expect(elapsedMs).toBeGreaterThanOrEqual(2400);
    expect(elapsedMs).toBeLessThan(8000);
    expect(fs.existsSync(path.join(caseDir, "worker-run.exited"))).toBe(true);
    expect(isPidAlive(workerPid)).toBe(false);
    await pollUntil(() => child.exitCode !== null || child.signalCode !== null, { label: "launcher exit event" });
    expect(child.signalCode).toBeNull();
    expect(child.exitCode).toBe(0);
  });

  it("non-adopted launcher: a drain longer than the budget is SIGKILLed after it — worker first, nothing orphaned", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ runDrain: "never" });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "worker-run.pid")) !== null, { label: "worker pidfile" });
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-run.pid")));

    const startedAt = Date.now();
    const stopped = await gateway.stopGatewayChildAndWait({ budgetMs: 1_000 });
    const elapsedMs = Date.now() - startedAt;

    expect(stopped).toBe(true);
    expect(elapsedMs).toBeGreaterThanOrEqual(950);
    expect(elapsedMs).toBeLessThan(8000);
    // The worker that ignored SIGTERM is dead too: killing only the launcher
    // (the pre-fix behaviour) would have left it orphaned and alive.
    expect(isPidAlive(workerPid)).toBe(false);
    // Worker FIRST: it never saw its launcher die (its parent never changed).
    await sleep(200);
    expect(fs.existsSync(path.join(caseDir, "worker-run.orphaned"))).toBe(false);
    await pollUntil(() => child.exitCode !== null || child.signalCode !== null, { label: "launcher exit event" });
    // The launcher either died BY our SIGKILL or exited on its own the moment
    // its worker was SIGKILLed first (the worker-first order).
    expect(child.signalCode === "SIGKILL" || child.exitCode !== null).toBe(true);
  });

  it("adopted cold-restart launcher (issue #56): SIGTERM, drain, exit — no SIGKILL inside the budget", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    // 2.5s drain: past 9.5's 2s backstop, where the old stop gave up (false)
    // and left the launcher alive.
    installDrainingGateway({ forceDrain: "2.5", forceListen: true });
    gateway = loadGateway();
    await gateway.runGatewayCmd("--force");
    expect(gateway.isManagedGatewayChildSupervisor()).toBe(true);
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(gateway.getManagedGatewayWorkerPid()).toBe(workerPid);

    const startedAt = Date.now();
    const stopped = await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
    const elapsedMs = Date.now() - startedAt;
    expect(stopped).toBe(true);
    expect(elapsedMs).toBeGreaterThanOrEqual(2400);
    expect(isPidAlive(workerPid)).toBe(false);
    expect(fs.existsSync(path.join(caseDir, "worker-force.exited"))).toBe(true);
  });

  it("adopted cold-restart launcher (issue #56): past the budget the worker is SIGKILLed first, then the launcher — nothing orphaned on the port", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceDrain: "never", forceListen: true });
    gateway = loadGateway();
    await gateway.runGatewayCmd("--force");
    expect(gateway.isManagedGatewayChildSupervisor()).toBe(true);
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    const listenerPid = trackPid(readPid(path.join(caseDir, "listener-force.pid")));

    const startedAt = Date.now();
    // Pre-fix: false after 2s with the launcher (and its gateway) left alive.
    const stopped = await gateway.stopGatewayChildAndWait({ budgetMs: 1_000 });
    const elapsedMs = Date.now() - startedAt;
    expect(stopped).toBe(true);
    expect(elapsedMs).toBeGreaterThanOrEqual(950);
    expect(isPidAlive(workerPid)).toBe(false);
    await sleep(200);
    expect(fs.existsSync(path.join(caseDir, "worker-force.orphaned"))).toBe(false);
    // The fixture's listener is the worker's own child (a real gateway's
    // helpers die with it); reap it so the port is free for later cases.
    try {
      process.kill(listenerPid, "SIGKILL");
    } catch {}
  });

  it("cold restart waits for the old gateway to release the port before spawning the replacement", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    // The managed `gateway run` holds the port and the state-ownership
    // projection; on SIGTERM it closes the port AT ONCE but keeps draining
    // (and owning state) for 2s — the 2026.9.8 order. A port-only wait (9.5's
    // 15s stop-settle) would spawn the replacement into that drain.
    installDrainingGateway({ runDrain: "2", runListen: true, runHoldsState: true, forceListen: true });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "listener-run.pid")) !== null, { label: "old listener" });
    trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    trackPid(readPid(path.join(caseDir, "listener-run.pid")));
    await pollUntil(() => gateway.isGatewayRunning(), { label: "old gateway port answering" });

    const result = await gateway.restartGateway(() => {});
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));

    expect(result).toMatchObject({ ok: true });
    const oldExitedAt = readNs(path.join(caseDir, "worker-run.exited"));
    const replacementAt = readNs(path.join(caseDir, "launch-force.at"));
    expect(oldExitedAt).not.toBeNull();
    expect(replacementAt).not.toBeNull();
    // The replacement was spawned only AFTER the old gateway finished its
    // drain and exited — never raced against it with `--force`.
    expect(replacementAt > oldExitedAt).toBe(true);
    expect(result.downtimeMs).toBeGreaterThanOrEqual(1900);
    expect(fs.existsSync(stateLockPath)).toBe(false);
    // Clean up the adopted replacement through the same stop contract.
    expect(await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 })).toBe(true);
  });

  // ── Refuter round 2 (M1/M3): kill the surviving mutants ─────────────────
  // A process that writes a VERIFIED projection (pid + its own /proc start
  // ticks + this canonical state dir), like 2026.9.8's acquireGatewayLock.
  const writeOwnerScript = ({ name, argvTail, mode, holdSeconds = "2" }) => {
    const dir = path.join(caseDir, name);
    fs.mkdirSync(dir, { recursive: true });
    const script = path.join(dir, "openclaw");
    const stateDir = fs.realpathSync(OPENCLAW_DIR);
    fs.writeFileSync(
      script,
      [
        "#!/bin/sh",
        `echo $$ > ${JSON.stringify(caseDir)}/${name}.pid`,
        `lockfile=${JSON.stringify(stateLockPath)}`,
        'mkdir -p "$(dirname "$lockfile")"',
        "st=$(cut -d' ' -f22 /proc/$$/stat)",
        `printf '{"pid":%s,"startTime":%s,"stateDir":"%s","role":"gateway"}' $$ "$st" ${JSON.stringify(stateDir)} > "$lockfile"`,
        ...(mode === "maintenance"
          ? [
              `sleep ${holdSeconds}`,
              `date +%s%N > ${JSON.stringify(caseDir)}/${name}.released`,
              'rm -f "$lockfile"',
              "exit 0",
            ]
          : mode === "graceful"
            ? [
                "sleep 60 & s=$!",
                `trap 'echo got-term >> ${JSON.stringify(caseDir)}/${name}.term; rm -f "$lockfile"; kill $s 2>/dev/null; date +%s%N > ${JSON.stringify(caseDir)}/${name}.released; exit 0' TERM`,
                "wait $s",
              ]
            : [
                // ignores SIGTERM (records it) and never releases
                `trap 'echo got-term >> ${JSON.stringify(caseDir)}/${name}.term' TERM`,
                "while :; do sleep 0.1; done",
              ]),
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    const proc = require("child_process").spawn(script, argvTail, { stdio: "ignore" });
    trackPid(proc.pid);
    return proc;
  };

  it("M3/a: the worker outlives its launcher — the stop waits for the worker, not just the launcher", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ runDrain: "2.5", launcherWaits: false });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "worker-run.pid")) !== null, { label: "worker pidfile" });
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    const startedAt = Date.now();
    expect(await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 })).toBe(true);
    const elapsedMs = Date.now() - startedAt;
    // The launcher exited at once (143); the stop still waited out the drain.
    expect(child.exitCode).toBe(143);
    expect(elapsedMs).toBeGreaterThanOrEqual(2400);
    expect(isPidAlive(workerPid)).toBe(false);
    expect(fs.existsSync(path.join(caseDir, "worker-run.exited"))).toBe(true);
  });

  it("M3: a launcher stopped before it forked its worker — the late worker is found, waited on and SIGKILLed first; nothing orphaned", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ runDrain: "never", workerDelay: "0.7" });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    // Stop as soon as the launcher runs (its TERM trap is armed) — no worker
    // exists yet.
    await pollUntil(() => fs.existsSync(path.join(caseDir, "launch-run.at")), { label: "launcher started" });
    expect(readPid(path.join(caseDir, "worker-run.pid"))).toBeNull();
    const pending = gateway.stopGatewayChildAndWait({ budgetMs: 2_500 });
    await pollUntil(() => readPid(path.join(caseDir, "worker-run.pid")) !== null, { label: "late worker pidfile" });
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    expect(await pending).toBe(true);
    expect(isPidAlive(workerPid)).toBe(false);
    await sleep(200);
    expect(fs.existsSync(path.join(caseDir, "worker-run.orphaned"))).toBe(false);
  });

  it("M3/n: AlphaClaw's shutdown stop waits for the gateway's drain (kGatewayShutdownStopBudgetMs), no SIGKILL", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ runDrain: "2.5" });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "worker-run.pid")) !== null, { label: "worker pidfile" });
    trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    const startedAt = Date.now();
    await gateway.stopGatewayForShutdown();
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(2400);
    expect(fs.existsSync(path.join(caseDir, "worker-run.exited"))).toBe(true);
    await pollUntil(() => child.exitCode !== null || child.signalCode !== null, { label: "launcher exit" });
    expect(child.signalCode).toBeNull();
    expect(child.exitCode).toBe(0);
  });

  it("M3/d,m: the state-ownership check is part of the release wait — no spawn while a (non-serving) OpenClaw process still owns the state", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    // No gateway at all; an OpenClaw maintenance process owns the state for
    // 2s. Without /proc pid evidence the wait is port closed AND projection
    // unheld.
    writeOwnerScript({ name: "maint", argvTail: ["doctor"], mode: "maintenance", holdSeconds: "2" });
    await pollUntil(() => fs.existsSync(stateLockPath), { label: "maintenance projection" });
    gateway = loadGateway();
    const result = await gateway.restartGateway(() => {});
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(result).toMatchObject({ ok: true });
    const releasedAt = readNs(path.join(caseDir, "maint.released"));
    const spawnedAt = readNs(path.join(caseDir, "launch-force.at"));
    expect(releasedAt).not.toBeNull();
    expect(spawnedAt > releasedAt).toBe(true);
    await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
  });

  it("M3/g: a verified state-owning gateway AlphaClaw did not spawn gets SIGTERM (graceful) and the restart proceeds once it released", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    const ext = writeOwnerScript({ name: "ext", argvTail: ["gateway", "run"], mode: "graceful" });
    await pollUntil(() => fs.existsSync(stateLockPath), { label: "external projection" });
    gateway = loadGateway();
    const result = await gateway.restartGateway(() => {});
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(result).toMatchObject({ ok: true });
    expect(fs.readFileSync(path.join(caseDir, "ext.term"), "utf8")).toContain("got-term");
    await pollUntil(() => ext.exitCode !== null || ext.signalCode !== null, { label: "external exit" });
    expect(ext.signalCode).toBeNull();
    expect(ext.exitCode).toBe(0);
    await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
  });

  it("M3/g: an external owner that ignores SIGTERM is NEVER SIGKILLed — past the budget the restart fails (stop_release) and spawns nothing", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    const ext = writeOwnerScript({ name: "ext", argvTail: ["gateway", "run"], mode: "never" });
    await pollUntil(() => fs.existsSync(stateLockPath), { label: "external projection" });
    gateway = loadGateway();
    expect(kGatewayStopBudgetMs).toBe(10_000);
    const error = await gateway.restartGateway(() => {}).then(() => null, (e) => e);
    expect(error).toBeInstanceOf(gateway.GatewayIncumbentRestartError);
    expect(error.evidence).toMatchObject({ phase: "stop_release", stateOwnerPid: ext.pid });
    expect(fs.existsSync(path.join(caseDir, "launch-force.at"))).toBe(false);
    expect(fs.readFileSync(path.join(caseDir, "ext.term"), "utf8")).toContain("got-term");
    expect(isPidAlive(ext.pid)).toBe(true);
    expect(ext.signalCode).toBeNull();
  }, 30_000);

  it("M1 (P1): a STALE projection whose pid now belongs to another state dir's gateway is neither waited on nor signalled", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    // A foreign isolated gateway (its own state dir), serving argv.
    const foreignDir = path.join(caseDir, "foreign");
    fs.mkdirSync(foreignDir, { recursive: true });
    const foreignScript = path.join(foreignDir, "openclaw");
    fs.writeFileSync(foreignScript, "#!/bin/sh\ntrap 'echo got-term >> " + JSON.stringify(path.join(caseDir, "foreign.term")) + "; exit 0' TERM\nwhile :; do sleep 0.1; done\n", { mode: 0o755 });
    const foreign = require("child_process").spawn(foreignScript, ["gateway", "run"], { stdio: "ignore" });
    trackPid(foreign.pid);
    await sleep(200);
    // OUR projection, left by a dead previous owner whose pid number the
    // foreign gateway now has: different start time, different state dir.
    fs.mkdirSync(path.dirname(stateLockPath), { recursive: true });
    fs.writeFileSync(stateLockPath, JSON.stringify({ pid: foreign.pid, startTime: 1, stateDir: "/data/other-session/.openclaw", role: "gateway" }));
    gateway = loadGateway();
    const result = await gateway.restartGateway(() => {});
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(result).toMatchObject({ ok: true });
    expect(fs.existsSync(path.join(caseDir, "foreign.term"))).toBe(false);
    expect(isPidAlive(foreign.pid)).toBe(true);
    await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
  });

  it("M2: past the budget AlphaClaw SIGKILLs its OWN wedged gateway (worker first) and, release now confirmed, starts the replacement", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    // The managed gateway holds the port and ignores SIGTERM forever.
    installDrainingGateway({ runDrain: "never", runListen: true, forceListen: true });
    gateway = loadGateway();
    const child = await gateway.launchGatewayProcess();
    trackPid(child.pid);
    await pollUntil(() => readPid(path.join(caseDir, "listener-run.pid")) !== null, { label: "old listener" });
    const workerPid = trackPid(readPid(path.join(caseDir, "worker-run.pid")));
    const oldListener = trackPid(readPid(path.join(caseDir, "listener-run.pid")));
    // The fixture's listener is the worker's own child; a real gateway's
    // socket dies with the gateway. Close it as soon as the worker is gone.
    const reaper = setInterval(() => {
      if (!isPidAlive(workerPid)) {
        try {
          process.kill(oldListener, "SIGKILL");
        } catch {}
      }
    }, 50);
    let result;
    const startedAt = Date.now();
    try {
      result = await gateway.restartGateway(() => {});
    } finally {
      clearInterval(reaper);
    }
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(kGatewayStopBudgetMs - 500);
    expect(result).toMatchObject({ ok: true });
    expect(isPidAlive(workerPid)).toBe(false);
    expect(fs.existsSync(path.join(caseDir, "worker-run.orphaned"))).toBe(false);
    expect(fs.existsSync(path.join(caseDir, "launch-force.at"))).toBe(true);
    await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
  }, 30_000);

  // M1, one identity field at a time (each check must stand on its own).
  const spawnForeignGateway = (name) => {
    const dir = path.join(caseDir, name);
    fs.mkdirSync(dir, { recursive: true });
    const script = path.join(dir, "openclaw");
    fs.writeFileSync(script, "#!/bin/sh\ntrap 'echo got-term >> " + JSON.stringify(path.join(caseDir, `${name}.term`)) + "; exit 0' TERM\nwhile :; do sleep 0.1; done\n", { mode: 0o755 });
    const proc = require("child_process").spawn(script, ["gateway", "run"], { stdio: "ignore" });
    trackPid(proc.pid);
    return proc;
  };
  const writeProjection = (payload) => {
    fs.mkdirSync(path.dirname(stateLockPath), { recursive: true });
    fs.writeFileSync(stateLockPath, JSON.stringify(payload));
  };

  it.each([
    ["startTime differs (right stateDir)", (pid) => ({ pid, startTime: 1, stateDir: fs.realpathSync(OPENCLAW_DIR), role: "gateway" })],
    ["stateDir differs (right startTime)", (pid) => ({ pid, startTime: readProcStartTicks(pid), stateDir: "/data/other-session/.openclaw", role: "gateway" })],
  ])("M1: a projection whose %s is stale — not waited on, not signalled, the restart proceeds", async (_label, payloadFor) => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    const foreign = spawnForeignGateway("foreign");
    await sleep(200);
    writeProjection(payloadFor(foreign.pid));
    gateway = loadGateway();
    const result = await gateway.restartGateway(() => {});
    trackPid(readPid(path.join(caseDir, "worker-force.pid")));
    trackPid(readPid(path.join(caseDir, "listener-force.pid")));
    expect(result).toMatchObject({ ok: true });
    expect(fs.existsSync(path.join(caseDir, "foreign.term"))).toBe(false);
    expect(isPidAlive(foreign.pid)).toBe(true);
    await gateway.stopGatewayChildAndWait({ budgetMs: 10_000 });
  });

  it("M1: an UNVERIFIED projection (older payload: pid only) still blocks the restart but never earns the external SIGTERM", async () => {
    if (process.platform !== "linux") return;
    scopeProcessScanToCase();
    installDrainingGateway({ forceListen: true });
    const foreign = spawnForeignGateway("legacy");
    await sleep(200);
    writeProjection({ pid: foreign.pid });
    gateway = loadGateway();
    const error = await gateway.restartGateway(() => {}).then(() => null, (e) => e);
    expect(error).toBeInstanceOf(gateway.GatewayIncumbentRestartError);
    expect(error.evidence).toMatchObject({ phase: "stop_release", stateOwnerPid: foreign.pid });
    expect(fs.existsSync(path.join(caseDir, "legacy.term"))).toBe(false);
    expect(isPidAlive(foreign.pid)).toBe(true);
    expect(fs.existsSync(path.join(caseDir, "launch-force.at"))).toBe(false);
  }, 30_000);
});
