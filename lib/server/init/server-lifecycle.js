const HttpTerminator = require("lil-http-terminator");

// Single owner of process lifecycle: listen (with EADDRINUSE retry), crash
// guards, and ONE graceful shutdown path used by signals, crash guards, and
// self-update restarts alike.
//
//   signal/crash/update ──▶ gracefulExit(code)
//                             │ (reentrancy-guarded; 2nd entry exits hard)
//                             ▼
//        clear keep-alives ─ terminator.terminate() ─ stopGateway()
//              ─ gmailWatch.stop() ─ terminal.dispose() ─ flushLogs()
//                             │ (every step try/catch'd)
//                             ▼
//                  exit(code)   [hard deadline regardless: shutdownDeadlineMs —
//                                server.js passes kProcessShutdownDeadlineMs,
//                                the gateway shutdown stop budget + 10s]
const kListenRetryAttempts = 5;
const kListenRetryDelayMs = 3000;
const kDrainGraceMs = 3000;
// Injected default only (tests, bare callers). The real server passes
// kProcessShutdownDeadlineMs so the deadline outlives the gateway's drain.
const kShutdownDeadlineMs = 10000;
const kRejectionStormWindowMs = 5 * 60 * 1000;
const kRejectionStormThreshold = 50;
// stdout/stderr write failures that only mean "nobody reads our logs any
// more": the pipe's reader died (start.sh's `| tee` killed by the same
// SIGTERM that started the shutdown), the stream was already torn down, or
// the terminal went away. Without a listener Node raises them as an
// 'error' event → uncaughtException → gracefulExit re-entry → SIGKILL of a
// gateway that is still draining. They are swallowed: losing log lines is
// recoverable, killing in-flight agent turns is not.
const kBenignStdioErrorCodes = new Set([
  "EPIPE",
  "ECONNRESET",
  "EIO",
  "ERR_STREAM_DESTROYED",
  "ERR_STREAM_WRITE_AFTER_END",
]);
const isBenignStdioError = (error) => kBenignStdioErrorCodes.has(error?.code);

const createServerLifecycle = ({
  server,
  PORT,
  isOnboarded = () => false,
  runOnboardedBootSequence = () => {},
  // Listening hook for the NOT-onboarded branch (issue #76 A7/A1): the port
  // bind just proved single-instance, so the dangling-record closers may run
  // and the boot report's server phase is marked not_reached — an onboarded
  // box does the same work as the first steps of runOnboardedBootSequence.
  // Best-effort: a throw is logged and never affects listening.
  onListening = null,
  stopGateway = async () => {},
  stopWatchdog = () => {},
  killGatewayNow = () => {},
  gmailWatchService = null,
  watchdogTerminal = null,
  disposeServices = () => {},
  flushLogs = () => {},
  exitImpl = (code) => process.exit(code),
  logger = console,
  // Streams whose write errors must never become an uncaughtException
  // (injectable for tests).
  stdioStreams = [process.stdout, process.stderr],
  listenRetryDelayMs = kListenRetryDelayMs,
  shutdownDeadlineMs = kShutdownDeadlineMs,
  rejectionStormThreshold = kRejectionStormThreshold,
  rejectionStormWindowMs = kRejectionStormWindowMs,
}) => {
  const state = {
    terminator: null,
    exiting: false,
    exitCode: 0,
    stdioErrors: 0,
    listenAttempts: 0,
    rejectionTimestamps: [],
    rejectionTotal: 0,
  };

  // Behind a platform LB (Render/Railway), keep-alive must outlive the LB's
  // ~60s idle timeout or the LB races a socket the server is closing into a
  // 502; headersTimeout must exceed keepAliveTimeout so header parsing never
  // loses that race. requestTimeout pins Node's default (it bounds receipt of
  // the request, not long-lived responses like SSE) explicitly.
  if (server) {
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
    server.requestTimeout = 300000;
  }

  const drain = async () => {
    const steps = [
      // Watchdog first: otherwise the gateway stop below triggers its
      // expected-exit path, which restarts health probes and logs spurious
      // restart-failed events against the already-cancelled lifecycle lock.
      ["watchdog stop", () => stopWatchdog()],
      ["http terminator", () => state.terminator?.terminate()],
      ["gateway stop", () => stopGateway()],
      ["gmail watch stop", () => gmailWatchService?.stop?.()],
      ["watchdog terminal dispose", () => watchdogTerminal?.disposeSession?.()],
      ["service dispose", () => disposeServices()],
      ["log flush", () => flushLogs()],
    ];
    for (const [label, step] of steps) {
      try {
        await step();
      } catch (error) {
        logger.error(`[alphaclaw] shutdown step failed (${label}): ${error?.message || error}`);
      }
    }
  };

  const gracefulExit = async (code = 0, reason = "", { source = "signal" } = {}) => {
    if (state.exiting) {
      if (source === "crash") {
        // An uncaught exception while the drain is running (typically a log
        // write into a dead pipe that slipped past the stdio guard) is NOT an
        // operator asking for a hard exit. Abandoning the drain here used to
        // SIGKILL a gateway that was finishing in-flight turns (OpenClaw
        // 2026.9.6+ drains for up to 330s). Keep draining; the process
        // deadline still bounds it.
        return;
      }
      // An explicit second signal while draining: the operator wants out
      // NOW. Exit immediately rather than re-entering cleanup. A benign
      // repeated SIGTERM keeps the ORIGINAL exit code (a duplicate signal
      // during a clean shutdown must not flip 0 into a failure). Last-ditch:
      // the drain being abandoned may not have reaped the gateway child yet
      // — an orphan keeping the port makes the successor process treat the
      // OLD version as healthy and skip its own start.
      try {
        killGatewayNow();
      } catch {}
      exitImpl(code === 0 ? state.exitCode : code);
      return;
    }
    state.exiting = true;
    state.exitCode = code;
    if (reason) logger.log(`[alphaclaw] Shutting down: ${reason}`);
    const deadline = setTimeout(() => {
      logger.error("[alphaclaw] Shutdown deadline exceeded — exiting now");
      try {
        killGatewayNow();
      } catch {}
      exitImpl(code || 1);
    }, shutdownDeadlineMs);
    try {
      await drain();
    } finally {
      clearTimeout(deadline);
      exitImpl(code);
    }
  };

  const markExiting = (code = 0) => {
    // Latch for restart paths that run their OWN bounded drain (restartProcess
    // in alphaclaw-version.js) instead of going through gracefulExit. Without
    // the latch, a SIGTERM/uncaughtException landing inside that bounded drain
    // window enters gracefulExit fresh, starts a second concurrent drain, and
    // can exit before the successor process is spawned. Latched, such a
    // re-entry hits the already-draining fast path above: immediate exit,
    // keeping the intended restart code for benign (code 0) signals.
    if (state.exiting) return;
    state.exiting = true;
    state.exitCode = code;
  };

  const recordUnhandledRejection = (reason) => {
    const now = Date.now();
    state.rejectionTotal += 1;
    state.rejectionTimestamps.push(now);
    state.rejectionTimestamps = state.rejectionTimestamps.filter(
      (ts) => now - ts <= rejectionStormWindowMs,
    );
    const message = reason?.stack || reason?.message || String(reason);
    logger.error(`[alphaclaw] Unhandled rejection (continuing): ${message}`);
    // A storm keeps rejecting while the drain runs — re-entering gracefulExit
    // here would hit the reentrancy branch and hard-exit mid-drain, skipping
    // gateway reap and log flush. Log-only once an exit is in progress.
    if (!state.exiting && state.rejectionTimestamps.length >= rejectionStormThreshold) {
      // A rejection storm means some subsystem is failing continuously; the
      // process state is suspect. Bounded restart instead of zombie-serving.
      void gracefulExit(1, "unhandled rejection storm");
      return true;
    }
    return false;
  };

  const installCrashGuards = () => {
    // Single-owner guarantee: any earlier boot-time guards (bin/alphaclaw.js
    // installs primitive ones before the server loads) are replaced here.
    for (const event of ["unhandledRejection", "uncaughtException", "SIGTERM", "SIGINT"]) {
      process.removeAllListeners(event);
    }
    process.on("unhandledRejection", (reason) => {
      recordUnhandledRejection(reason);
    });
    for (const stream of stdioStreams) {
      if (!stream || typeof stream.on !== "function" || stream.__alphaclawStdioGuard) continue;
      stream.__alphaclawStdioGuard = true;
      // Never rethrown, never logged to the (possibly dead) stream itself.
      stream.on("error", () => {
        state.stdioErrors += 1;
      });
    }
    process.on("uncaughtException", (error) => {
      // During a drain any crash re-entry is a no-op (gracefulExit, source
      // "crash"); a benign stdio error is merely counted, not logged into
      // the stream that just failed.
      if (state.exiting && isBenignStdioError(error)) {
        state.stdioErrors += 1;
        return;
      }
      try {
        logger.error(
          `[alphaclaw] Uncaught exception: ${error?.stack || error?.message || error}`,
        );
      } catch {}
      void gracefulExit(1, "uncaught exception", { source: "crash" });
    });
    process.on("SIGTERM", () => {
      void gracefulExit(0, "SIGTERM");
    });
    process.on("SIGINT", () => {
      void gracefulExit(0, "SIGINT");
    });
  };

  const startListening = () => {
    server.on("error", (error) => {
      if (error?.code === "EADDRINUSE" && state.listenAttempts < kListenRetryAttempts) {
        state.listenAttempts += 1;
        logger.warn(
          `[alphaclaw] Port ${PORT} in use — retry ${state.listenAttempts}/${kListenRetryAttempts} in ${Math.round(listenRetryDelayMs / 1000)}s`,
        );
        setTimeout(() => {
          try {
            server.listen(PORT, "0.0.0.0");
          } catch (listenError) {
            logger.error(`[alphaclaw] Listen retry failed: ${listenError.message}`);
          }
        }, listenRetryDelayMs);
        return;
      }
      // Loud exit — a silent zombie (the old behavior: unhandled 'error'
      // event) is the one unacceptable outcome. The platform restarts us.
      logger.error(`[alphaclaw] Server failed to listen on :${PORT}: ${error?.message || error}`);
      exitImpl(1);
    });
    server.on("listening", () => {
      if (!state.terminator) {
        state.terminator = HttpTerminator({
          server,
          gracefulTerminationTimeout: kDrainGraceMs,
          maxWaitTimeout: shutdownDeadlineMs,
          logger: { ...console, warn: () => {} },
        });
      }
      logger.log(`[alphaclaw] Express listening on :${PORT}`);
      if (isOnboarded()) {
        // Fire-and-forget with an explicit catch: the boot sequence reports
        // its own failures via boot-phase, but a rejection escaping it must
        // never feed the rejection storm brake (or, without crash guards
        // installed, kill the process).
        Promise.resolve(runOnboardedBootSequence()).catch((error) => {
          logger.error(
            `[alphaclaw] Boot sequence error: ${error?.message || error}`,
          );
        });
      } else {
        logger.log("[alphaclaw] Awaiting onboarding via Setup UI");
        if (typeof onListening === "function") {
          Promise.resolve()
            .then(() => onListening({ onboarded: false }))
            .catch((error) => {
              logger.error(
                `[alphaclaw] Listening hook error: ${error?.message || error}`,
              );
            });
        }
      }
    });
    server.listen(PORT, "0.0.0.0");
  };

  const getRejectionStats = () => ({
    total: state.rejectionTotal,
    inWindow: state.rejectionTimestamps.length,
  });
  const getStdioErrorCount = () => state.stdioErrors;

  return {
    startListening,
    installCrashGuards,
    gracefulExit,
    markExiting,
    drain,
    getRejectionStats,
    getStdioErrorCount,
    // exposed for tests
    __recordUnhandledRejection: recordUnhandledRejection,
  };
};

module.exports = {
  createServerLifecycle,
};
