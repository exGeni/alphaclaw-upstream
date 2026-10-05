const crypto = require("crypto");
const {
  insertConfirm,
  findActiveConfirm,
  countPending,
  listPending,
  redeemConfirm,
  pruneExpired,
} = require("../db/agent-admin");

const {
  kConfirmHeader,
  kRequestContextHeader: kContextHeader,
} = require("./constants");
const { sanitizeLabel } = require("../utils/sanitize-label");
const { redactSecretShapes } = require("../utils/redact");

// Optional per-op detail for the confirm summary: an op may define
// confirmSummary({ method, path, pathParams, query, body }) returning one
// line that tells the approving admin WHAT the call changes (the title alone
// says only which op). The line is house-format neutralised (` * [ ]),
// secret-shape scrubbed, control-stripped and clamped; a throw or a
// non-string falls back to the title. Put the high-consequence facts first:
// the clamp cuts the tail.
const kMaxConfirmSummaryLength = 400;

const extractPathParams = (opPath, fullPath) => {
  const out = {};
  const template = String(opPath || "").split("/");
  const actual = String(fullPath || "").split("/");
  template.forEach((segment, index) => {
    if (!segment.startsWith(":") || actual[index] === undefined) return;
    try {
      out[segment.slice(1)] = decodeURIComponent(actual[index]);
    } catch {
      out[segment.slice(1)] = actual[index];
    }
  });
  return out;
};

const buildConfirmSummary = (op, req) => {
  const title = op?.title || op?.id;
  if (typeof op?.confirmSummary !== "function" || !req) return title;
  try {
    const fullPath = `${req.baseUrl || ""}${req.path || ""}`;
    const detail = op.confirmSummary({
      method: String(req.method || "").toUpperCase(),
      path: fullPath,
      pathParams: extractPathParams(op.path, fullPath),
      query: req.query || {},
      body: req.body ?? null,
    });
    if (typeof detail !== "string" || !detail.trim()) return title;
    // The summary is delivered in the house notification format, where
    // `code`, *bold* and [label](url) are markup: an op's detail line is
    // data, so those characters are neutralised before it is appended.
    const inert = detail.replace(/[`*]/g, "'").replace(/\[/g, "(").replace(/\]/g, ")");
    return sanitizeLabel(redactSecretShapes(`${title}: ${inert}`), {
      maxLength: kMaxConfirmSummaryLength,
    });
  } catch {
    return title;
  }
};

const kTtlMs = 10 * 60 * 1000; // 10-minute expiry (fixes the doctor-token gap)
const kMaxPending = 10; // backlog cap (A8)
const kMaxRedeemAttempts = 3;
// base32 without 0/O/1/I — human-typable, unambiguous (settled decision).
const kAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const genCode = () => {
  const bytes = crypto.randomBytes(8);
  let out = "";
  for (let i = 0; i < 8; i += 1) out += kAlphabet[bytes[i] % kAlphabet.length];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
};

// paramsHash binds a code to one exact mutation: canonical method + full path +
// normalized query + body + the request-context header (A10/A28). A code can
// never be replayed against a different call.
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
};

const computeParamsHash = (req) => {
  const payload = canonicalJson({
    method: String(req.method || "").toUpperCase(),
    path: req.baseUrl + req.path,
    query: req.query || {},
    body: req.body ?? null,
    context: req.headers?.[kContextHeader] || "",
  });
  return crypto.createHash("sha256").update(payload).digest("hex");
};

const createConfirmService = ({
  now = () => Date.now(),
  deliver = null, // ({op, code, summary, expiresAt, confirmId, req}) => void
  hasAdminTargets = () => false,
} = {}) => {
  const buildSummary = (op, req) => buildConfirmSummary(op, req);

  // Called by the enforcement middleware for every dangerous-tier request.
  // Returns { ok:true, confirmId } to proceed, or { ok:false, status, body }.
  const gate = ({ req, op, confirmCode }) => {
    const nowMs = now();
    const nowIso = new Date(nowMs).toISOString();

    // Dangerous ops need an admin channel for the code to reach (KTD5).
    if (!hasAdminTargets()) {
      return {
        ok: false,
        status: 409,
        body: {
          ok: false,
          error: "No admin notification target configured",
          code: "no_admin_targets",
          hint: "Set an admin notification target (Setup UI → Notifications) before running dangerous operations.",
        },
      };
    }

    const paramsHash = computeParamsHash(req);
    const headerCode = confirmCode || req.headers?.[kConfirmHeader];

    // Retry path: a code was supplied — redeem it.
    if (headerCode) {
      const result = redeemConfirm({
        code: headerCode,
        opId: op.id,
        paramsHash,
        nowIso,
        maxAttempts: kMaxRedeemAttempts,
      });
      if (result.ok) return { ok: true, confirmId: result.confirmId };
      return {
        ok: false,
        phase: "denied",
        status: 403,
        body: {
          ok: false,
          error: "Confirmation failed",
          code:
            result.reason === "confirm_expired"
              ? "confirm_expired"
              : result.reason === "confirm_attempts_exhausted"
                ? "confirm_attempts_exhausted"
                : "confirm_invalid",
          hint: "Ask an admin for a fresh code, or check that the request exactly matches what was approved.",
        },
      };
    }

    // First contact: reuse an active confirm for the identical op+params
    // (dedup, A8) or mint one, then deliver and 428. Prune only here — never
    // before a redeem, or an expired-but-pending row would be deleted before
    // redeemConfirm could classify it, collapsing confirm_expired into the
    // generic confirm_invalid. Pruning on the mint path keeps countPending and
    // dedup accurate without touching that signal.
    pruneExpired({ nowIso });
    let existing = findActiveConfirm({ opId: op.id, paramsHash, nowIso });
    let code;
    let confirmId;
    let expiresAtIso;
    if (existing) {
      code = existing.code;
      confirmId = existing.id;
      expiresAtIso = existing.expires_at;
    } else {
      if (countPending({ nowIso }) >= kMaxPending) {
        return {
          ok: false,
          status: 429,
          body: {
            ok: false,
            error: "Too many pending confirmations",
            code: "confirm_backlog_full",
            hint: "Resolve or wait for existing pending confirmations to expire.",
          },
        };
      }
      code = genCode();
      confirmId = crypto.randomUUID();
      expiresAtIso = new Date(nowMs + kTtlMs).toISOString();
      insertConfirm({
        id: confirmId,
        opId: op.id,
        paramsHash,
        code,
        summary: buildSummary(op, req),
        expiresAt: expiresAtIso,
      });
    }

    let delivered = false;
    if (typeof deliver === "function") {
      try {
        deliver({
          op,
          code,
          summary: buildSummary(op, req),
          expiresAt: expiresAtIso,
          confirmId,
          req,
        });
        delivered = true;
      } catch {
        // Delivery failure is non-fatal: the dashboard chip is the source of
        // truth (the message below names it as the fallback).
      }
    }

    return {
      ok: false,
      phase: "confirm_required",
      status: 428,
      confirmId,
      body: {
        ok: false,
        error: "Operator confirmation required",
        code: "confirm_required",
        confirmId,
        summary: buildSummary(op, req),
        expiresAt: expiresAtIso,
        // Prose, not a literal command (B4): the confirm is bound to the exact
        // method+path+query+body+context, so a templated path (with :params) or
        // a dropped --data/--context would produce a different paramsHash and
        // fail redemption. Re-run the SAME command with --confirm appended.
        retryWith:
          "Re-run your exact previous command with `--confirm <code>` appended (same method, path, --data, and --context — the code is bound to them).",
        // F073: on a dedup hit the code was delivered on the FIRST attempt and
        // the notifier de-duplicates the re-send, so never claim "was sent"
        // again — say the earlier code is still the one to use.
        delivery: existing
          ? "Your earlier code is still valid (not re-sent); it appears in the dashboard (General tab), and the admin channel received it on the first attempt."
          : delivered
            ? "A code was sent to your admin channel; it also appears in the dashboard (General tab)."
            : "The code appears in the dashboard (General tab); ask an operator to relay it.",
      },
    };
  };

  const listPendingConfirms = () => {
    const nowIso = new Date(now()).toISOString();
    return listPending({ nowIso }).map((row) => ({
      confirmId: row.id,
      op: row.op_id,
      code: row.code, // plaintext by design (A3) so the dashboard can show it
      summary: row.summary,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    }));
  };

  const pendingCount = () => countPending({ nowIso: new Date(now()).toISOString() });

  return { gate, listPending: listPendingConfirms, pendingCount, computeParamsHash };
};

module.exports = {
  buildConfirmSummary,
  extractPathParams,
  createConfirmService,
  kTtlMs,
  kMaxPending,
  kConfirmHeader,
};
