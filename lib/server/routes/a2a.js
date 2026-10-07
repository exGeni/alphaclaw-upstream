const { wrapAsync } = require("../utils/wrap-async");
const { sendIfConfigUnreadable } = require("../utils/config-unreadable");
const { logRejectedInput } = require("../utils/input-audit");
const { A2aChannelError } = require("../a2a-channel");

// channels.a2a administration (README "A2A peers through AlphaClaw"). Admin
// only: members are default-deny on /api/channels, and the agent actor passes
// requireAdmin solely through the agent-admin enforcement grant. No response,
// log line or audit row carries a token value: the service reports tokens by
// kind (env/literal) and env presence only.
// "<type>" or "<string:classes>" — the character classes present, never the
// characters and never the length.
const describeValueShape = (value) => {
  if (typeof value !== "string") return `<${value === null ? "null" : typeof value}>`;
  const classes = [
    [/[A-Z]/, "upper"],
    [/[a-z]/, "lower"],
    [/[0-9]/, "digit"],
    [/_/, "underscore"],
    [/[^A-Za-z0-9_]/, "other"],
  ]
    .filter(([pattern]) => pattern.test(value))
    .map(([, name]) => name);
  return `<string:${classes.join("+") || "empty"}>`;
};

const sendError = (req, res, error) => {
  if (error instanceof A2aChannelError) {
    if (error.code === "invalid_peer_id") {
      logRejectedInput({ req, field: "peerId", reason: "pattern", value: req.params?.peerId });
    } else if (error.code === "invalid_token_env") {
      // Shape only: a caller that pastes a token VALUE into tokenEnv must not
      // see it land in the server log.
      logRejectedInput({
        req,
        field: "tokenEnv",
        reason: "pattern",
        value: describeValueShape(req.body?.tokenEnv),
      });
    }
    return res.status(error.status).json({
      ok: false,
      code: error.code,
      error: error.message,
      hint: error.hint,
    });
  }
  if (sendIfConfigUnreadable(res, error)) return undefined;
  if (error?.code === "ELOCKTIMEOUT") {
    return res.status(503).json({
      ok: false,
      code: "config_busy",
      error: "openclaw.json or .env is locked by another writer",
      hint: "Retry shortly.",
    });
  }
  return res.status(500).json({
    ok: false,
    code: "a2a_write_failed",
    error: error?.message || "A2A channel operation failed",
    hint: null,
  });
};

const registerA2aRoutes = ({ app, requireAdmin, a2aChannel }) => {
  app.get("/api/channels/a2a", requireAdmin, (req, res) => {
    try {
      res.json({ ok: true, ...a2aChannel.read() });
    } catch (error) {
      sendError(req, res, error);
    }
  });

  app.put("/api/channels/a2a", requireAdmin, wrapAsync(async (req, res) => {
    try {
      res.json({ ok: true, ...(await a2aChannel.update(req.body)) });
    } catch (error) {
      sendError(req, res, error);
    }
  }));

  app.put("/api/channels/a2a/peers/:peerId", requireAdmin, wrapAsync(async (req, res) => {
    try {
      const { status, ...result } = await a2aChannel.upsertPeer(req.params.peerId, req.body);
      res.status(status).json({ ok: true, ...result });
    } catch (error) {
      sendError(req, res, error);
    }
  }));

  app.delete("/api/channels/a2a/peers/:peerId", requireAdmin, wrapAsync(async (req, res) => {
    try {
      res.json({ ok: true, ...(await a2aChannel.removePeer(req.params.peerId, req.body)) });
    } catch (error) {
      sendError(req, res, error);
    }
  }));
};

module.exports = { registerA2aRoutes, describeValueShape };
