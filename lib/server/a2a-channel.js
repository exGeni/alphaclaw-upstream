const crypto = require("crypto");
const fs = require("fs");
const {
  readOpenclawConfigForWrite,
  updateOpenclawConfig,
} = require("./openclaw-config");
const envStore = require("./env");
const { kA2aPeerTokenEnvPattern } = require("./gateway-env-policy");
const { kReservedIdentifierNames } = require("./agents/shared");
const launchEnvSnapshot = require("./gateway-launch-env-snapshot");

// A2A channel administration (channels.a2a in openclaw.json) for the
// `alphaclaw admin` surface: read the channel without ever exposing a token
// value, add/rotate a peer as an env reference, remove a peer, and set the
// advertised origin. The channel itself is never created here: an absent
// channels.a2a is refused, so enabling A2A stays an explicit operator act.
//
// Contract source: the bundled OpenClaw docs/channels/a2a.md ("Quick setup",
// "Configuration reference") and the a2a plugin manifest schema
// (dist/extensions/a2a/openclaw.plugin.json, channels.a2a.peers
// propertyNames pattern).

// Peer names: the a2a plugin schema's propertyNames pattern, verbatim.
const kA2aPeerIdPattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;
// A whole-string `${VAR}` reference, in OpenClaw's substitution grammar
// (uppercase names only: docs/gateway/configuration/environment-variables.md).
const kEnvRefPattern = /^\$\{([A-Z_][A-Z0-9_]*)\}$/;
const kTokenBytes = 32;
const kUpsertBodyKeys = new Set(["tokenEnv", "generate"]);
const kRemoveBodyKeys = new Set(["removeEnv"]);
const kUpdateBodyKeys = new Set(["advertisedUrl"]);

class A2aChannelError extends Error {
  constructor(status, code, message, hint = null) {
    super(message);
    this.name = "A2aChannelError";
    this.status = status;
    this.code = code;
    this.hint = hint;
  }
}

const isPlainObject = (value) =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

const isValidA2aPeerId = (value) =>
  typeof value === "string" &&
  kA2aPeerIdPattern.test(value) &&
  !kReservedIdentifierNames.has(value);

const defaultTokenEnvForPeer = (peerId) =>
  `A2A_${String(peerId).toUpperCase().replace(/[^A-Z0-9]/g, "_")}_TOKEN`;

const isValidA2aTokenEnv = (value) =>
  typeof value === "string" && kA2aPeerTokenEnvPattern.test(value);

const parseEnvRef = (token) => {
  if (typeof token !== "string") return null;
  const match = kEnvRefPattern.exec(token);
  return match ? match[1] : null;
};

// Every ${VAR} OpenClaw would substitute anywhere in a string (inline
// references too; `$${VAR}` is OpenClaw's escape for a literal and is not a
// reference: docs/gateway/configuration/environment-variables.md).
const kInlineEnvRefPattern = /(\$?)\$\{([A-Z_][A-Z0-9_]*)\}/g;

// Walks the whole config and yields {name, path} for each env reference, so
// "is VAR still used" sees every peer's token AND outboundToken as well as
// any other subsystem that resolves the same variable.
const collectEnvRefs = (node, pathParts = [], out = []) => {
  if (typeof node === "string") {
    for (const match of node.matchAll(kInlineEnvRefPattern)) {
      if (match[1] === "$") continue;
      out.push({ name: match[2], path: pathParts.join(".") });
    }
  } else if (Array.isArray(node)) {
    node.forEach((item, index) => collectEnvRefs(item, [...pathParts, String(index)], out));
  } else if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      collectEnvRefs(value, [...pathParts, key], out);
    }
  }
  return out;
};

const rejectUnknownKeys = (body, allowed) => {
  const unknown = Object.keys(body).filter((key) => !allowed.has(key));
  if (!unknown.length) return;
  const mentionsToken = unknown.some((key) => /token/i.test(key) && key !== "tokenEnv");
  throw new A2aChannelError(
    400,
    "invalid_body",
    `Unsupported field(s): ${unknown.slice(0, 5).join(", ")}`,
    mentionsToken
      ? "Token values are never accepted in the body: pass generate:true, or set the variable with env.update first."
      : `Allowed fields: ${Array.from(allowed).join(", ")}.`,
  );
};

// https origin only: scheme + host (+ port), no userinfo, path, query or
// fragment. The card appends /a2a/v1 itself (README "A2A peers through
// AlphaClaw").
const normalizeAdvertisedUrl = (value) => {
  if (value === null) return null;
  const invalid = () =>
    new A2aChannelError(
      400,
      "invalid_advertised_url",
      "advertisedUrl must be an https origin such as https://claw.example.com, or null to unset",
      "Give the externally reachable origin only, without /openclaw or /a2a/v1; the Agent Card appends /a2a/v1.",
    );
  if (typeof value !== "string") throw invalid();
  const raw = value.trim();
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw invalid();
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    /[?#]/.test(raw) ||
    !/^https:\/\/[^/]+\/?$/i.test(raw)
  ) {
    throw invalid();
  }
  return parsed.origin;
};

const createA2aChannelService = ({
  fsModule = fs,
  openclawDir,
  readEnvFile = envStore.readEnvFile,
  updateEnvFile = envStore.updateEnvFile,
  reloadEnv = envStore.reloadEnv,
  processEnv = process.env,
  randomBytes = crypto.randomBytes,
  restartRequiredState = null,
  gatewayLifecycleLock = null,
  // Names of the env the RUNNING gateway was spawned with (null = unknown,
  // e.g. an incumbent AlphaClaw adopted rather than spawned).
  getGatewayLaunchEnvKeys = launchEnvSnapshot.getGatewayLaunchEnvKeys,
} = {}) => {
  const envFileValue = (key) => {
    const entry = readEnvFile().find((v) => v.key === key);
    return String(entry?.value || "");
  };

  const isEnvSet = (key) =>
    Boolean(String(processEnv[key] || "").trim()) || Boolean(envFileValue(key).trim());

  const readA2a = () => {
    const cfg = readOpenclawConfigForWrite({ fsModule, openclawDir });
    const a2a = cfg?.channels?.a2a;
    return isPlainObject(a2a) ? a2a : null;
  };

  const requireA2a = (cfg) => {
    const a2a = cfg?.channels?.a2a;
    if (!isPlainObject(a2a)) {
      throw new A2aChannelError(
        409,
        "a2a_channel_absent",
        "channels.a2a is not configured in openclaw.json",
        "This operation never creates the A2A channel. Enable channels.a2a first (README \"A2A peers through AlphaClaw\").",
      );
    }
    return a2a;
  };

  const describePeer = (id, peer) => {
    const token = isPlainObject(peer) ? peer.token : undefined;
    if (token === undefined || token === null || token === "") {
      return { id, tokenRef: "missing", tokenEnv: null, tokenEnvSet: null };
    }
    const envName = parseEnvRef(token);
    if (envName) {
      return { id, tokenRef: "env", tokenEnv: envName, tokenEnvSet: isEnvSet(envName) };
    }
    // A literal token or a non-string value: reported by kind, never by value.
    return {
      id,
      tokenRef: typeof token === "string" ? "literal" : "unsupported",
      tokenEnv: null,
      tokenEnvSet: null,
    };
  };

  const read = () => {
    const a2a = readA2a();
    if (!a2a) return { configured: false };
    const peers = isPlainObject(a2a.peers) ? a2a.peers : {};
    const out = {
      configured: true,
      enabled: typeof a2a.enabled === "boolean" ? a2a.enabled : null,
      exposeAgents: Array.isArray(a2a.exposeAgents)
        ? a2a.exposeAgents.filter((v) => typeof v === "string")
        : null,
      advertisedUrl: typeof a2a.advertisedUrl === "string" ? a2a.advertisedUrl : null,
      peers: Object.keys(peers)
        .sort()
        .map((id) => describePeer(id, peers[id])),
    };
    if (hasOwn(a2a, "replyTimeoutMs")) out.replyTimeoutMs = a2a.replyTimeoutMs;
    if (hasOwn(a2a, "rateLimitPerMinute")) out.rateLimitPerMinute = a2a.rateLimitPerMinute;
    return out;
  };

  // Serialize against PUT /api/env (which holds the same "env_sync" hold
  // across its .env + openclaw.json read-modify-write) and gateway restarts.
  const withEnvSyncLock = async (fn) => {
    const release = gatewayLifecycleLock?.acquire
      ? await gatewayLifecycleLock.acquire("env_sync")
      : null;
    try {
      return fn();
    } finally {
      release?.();
    }
  };

  const markRestart = (reason) => {
    try {
      restartRequiredState?.markRequired?.(reason);
    } catch {}
  };

  const validatePeerId = (peerId) => {
    if (!isValidA2aPeerId(peerId)) {
      throw new A2aChannelError(
        400,
        "invalid_peer_id",
        "Invalid A2A peer id",
        "Peer ids follow the OpenClaw a2a schema: ^[a-z0-9][a-z0-9._-]{0,63}$.",
      );
    }
  };

  const upsertPeer = async (peerId, rawBody) => {
    validatePeerId(peerId);
    const body = rawBody ?? {};
    if (!isPlainObject(body)) {
      throw new A2aChannelError(400, "invalid_body", "Body must be a JSON object");
    }
    rejectUnknownKeys(body, kUpsertBodyKeys);
    if (hasOwn(body, "generate") && typeof body.generate !== "boolean") {
      throw new A2aChannelError(400, "invalid_body", "generate must be a boolean");
    }
    const generate = body.generate === true;
    const tokenEnv =
      body.tokenEnv === undefined || body.tokenEnv === null
        ? defaultTokenEnvForPeer(peerId)
        : body.tokenEnv;
    if (!isValidA2aTokenEnv(tokenEnv)) {
      throw new A2aChannelError(
        400,
        "invalid_token_env",
        "tokenEnv must match ^A2A_[A-Z0-9_]+_TOKEN$",
        `Omit tokenEnv to use ${defaultTokenEnvForPeer(peerId)}.`,
      );
    }
    const tokenRefValue = `\${${tokenEnv}}`;
    const ownTokenPath = `channels.a2a.peers.${peerId}.token`;

    return withEnvSyncLock(() => {
      // Pre-checks on a strict read so a refused request writes nothing —
      // not even a generated env value.
      const before = readOpenclawConfigForWrite({ fsModule, openclawDir });
      requireA2a(before);
      const otherUse = collectEnvRefs(before).find(
        (ref) => ref.name === tokenEnv && ref.path !== ownTokenPath,
      );
      if (otherUse) {
        throw new A2aChannelError(
          409,
          "token_env_in_use",
          `${tokenEnv} is already referenced at ${otherUse.path}`,
          "Each peer needs its own token (OpenClaw a2a docs, Security). Pick another tokenEnv.",
        );
      }

      let tokenGenerated = false;
      if (!isEnvSet(tokenEnv)) {
        if (!generate) {
          throw new A2aChannelError(
            409,
            "token_env_unset",
            `${tokenEnv} is not set`,
            "Pass generate:true to create a token in AlphaClaw's env store, or set the variable first (env.update).",
          );
        }
        const token = randomBytes(kTokenBytes).toString("base64url");
        let wrote = false;
        updateEnvFile((current) => {
          // Re-checked under the file lock: never overwrite a value that
          // appeared since the pre-check.
          if (current.some((v) => v.key === tokenEnv && String(v.value || "").trim())) {
            return current;
          }
          wrote = true;
          return [...current.filter((v) => v.key !== tokenEnv), { key: tokenEnv, value: token }];
        });
        reloadEnv();
        tokenGenerated = wrote;
      }

      const peerView = {
        id: peerId,
        tokenRef: "env",
        tokenEnv,
        tokenEnvSet: isEnvSet(tokenEnv),
      };

      // Two-phase gate. OpenClaw hot-reloads channels.a2a (the a2a plugin
      // declares reload configPrefixes ["channels.a2a"]) and resolves
      // ${VAR} from the RUNNING gateway's env; a VAR that is not in that env
      // stays the unresolved literal "${VAR}", which the channel then
      // accepts as the bearer. So the reference is written only once the
      // gateway was spawned with VAR. Until then the variable is staged in
      // AlphaClaw's env and a restart is marked; openclaw.json is untouched.
      const launchKeys = getGatewayLaunchEnvKeys();
      const runningHasVar = launchKeys instanceof Set && launchKeys.has(tokenEnv);
      if (!runningHasVar) {
        markRestart("a2a_token_env_staged");
        return {
          status: 202,
          state: tokenGenerated ? "token_staged" : "restart_required",
          reason: tokenGenerated
            ? "token_env_generated"
            : launchKeys instanceof Set
              ? "token_env_not_in_running_gateway"
              : "running_gateway_env_unknown",
          next: "Restart the gateway, then call channels.a2a.peer-upsert again with the same body.",
          peer: peerView,
          created: false,
          tokenGenerated,
          changed: tokenGenerated,
          restartRequired: true,
        };
      }

      const result = updateOpenclawConfig({
        fsModule,
        openclawDir,
        mutate: (cfg) => {
          const a2a = requireA2a(cfg);
          if (!isPlainObject(a2a.peers)) a2a.peers = {};
          const existing = hasOwn(a2a.peers, peerId) && isPlainObject(a2a.peers[peerId])
            ? a2a.peers[peerId]
            : null;
          if (existing && existing.token === tokenRefValue) {
            return { skipWrite: true, created: false, configChanged: false };
          }
          a2a.peers[peerId] = { ...(existing || {}), token: tokenRefValue };
          return { created: !existing, configChanged: true };
        },
      });
      const changed = Boolean(result.configChanged);
      return {
        status: result.created ? 201 : 200,
        state: "applied",
        peer: peerView,
        created: Boolean(result.created),
        tokenGenerated,
        changed,
        // Applied by OpenClaw's channels.a2a hot reload; no restart needed.
        restartRequired: false,
      };
    });
  };

  const removePeer = async (peerId, rawBody) => {
    validatePeerId(peerId);
    const body = rawBody ?? {};
    if (!isPlainObject(body)) {
      throw new A2aChannelError(400, "invalid_body", "Body must be a JSON object");
    }
    rejectUnknownKeys(body, kRemoveBodyKeys);
    if (hasOwn(body, "removeEnv") && typeof body.removeEnv !== "boolean") {
      throw new A2aChannelError(400, "invalid_body", "removeEnv must be a boolean");
    }
    const removeEnv = body.removeEnv === true;

    return withEnvSyncLock(() => {
      let removedToken;
      let stillReferenced = false;
      updateOpenclawConfig({
        fsModule,
        openclawDir,
        mutate: (cfg) => {
          const a2a = requireA2a(cfg);
          const peers = isPlainObject(a2a.peers) ? a2a.peers : null;
          if (!peers || !hasOwn(peers, peerId)) {
            throw new A2aChannelError(
              404,
              "peer_not_found",
              `A2A peer "${peerId}" is not configured`,
            );
          }
          removedToken = isPlainObject(peers[peerId]) ? peers[peerId].token : undefined;
          delete peers[peerId];
          const envName = parseEnvRef(removedToken);
          // Any remaining reference anywhere in the config (another peer's
          // token or outboundToken, or another subsystem) keeps the variable.
          stillReferenced = Boolean(envName) &&
            collectEnvRefs(cfg).some((ref) => ref.name === envName);
          return {};
        },
      });
      markRestart("a2a_peers_changed");

      const envName = parseEnvRef(removedToken);
      let env = null;
      if (removeEnv) {
        if (!envName) {
          env = {
            name: null,
            removed: false,
            reason: typeof removedToken === "string" && removedToken ? "literal_token" : "no_env_ref",
          };
        } else if (!isValidA2aTokenEnv(envName)) {
          env = { name: envName, removed: false, reason: "not_a2a_token_env" };
        } else if (stillReferenced) {
          env = { name: envName, removed: false, reason: "referenced_by_other_peer" };
        } else {
          let removedFromFile = false;
          updateEnvFile((current) => {
            const next = current.filter((v) => v.key !== envName);
            removedFromFile = next.length !== current.length;
            return next;
          });
          if (removedFromFile) {
            // reloadEnv only drops known keys that left the file; this one is
            // not a known key, so clear it from the live env explicitly or the
            // next gateway restart would still receive it.
            delete processEnv[envName];
            reloadEnv();
            env = { name: envName, removed: true };
          } else {
            env = {
              name: envName,
              removed: false,
              reason: String(processEnv[envName] || "").trim()
                ? "deployment_env"
                : "not_set",
            };
          }
        }
      }
      return {
        removed: peerId,
        tokenEnv: envName,
        ...(env ? { env } : {}),
        restartRequired: true,
      };
    });
  };

  const update = async (rawBody) => {
    const body = rawBody ?? {};
    if (!isPlainObject(body)) {
      throw new A2aChannelError(400, "invalid_body", "Body must be a JSON object");
    }
    rejectUnknownKeys(body, kUpdateBodyKeys);
    if (!hasOwn(body, "advertisedUrl")) {
      throw new A2aChannelError(
        400,
        "invalid_body",
        "advertisedUrl is required (an https origin, or null to unset)",
      );
    }
    const advertisedUrl = normalizeAdvertisedUrl(body.advertisedUrl);
    return withEnvSyncLock(() => {
      const result = updateOpenclawConfig({
        fsModule,
        openclawDir,
        mutate: (cfg) => {
          const a2a = requireA2a(cfg);
          const current = hasOwn(a2a, "advertisedUrl") ? a2a.advertisedUrl : undefined;
          if (advertisedUrl === null) {
            if (current === undefined) return { skipWrite: true, configChanged: false };
            delete a2a.advertisedUrl;
            return { configChanged: true };
          }
          if (current === advertisedUrl) return { skipWrite: true, configChanged: false };
          a2a.advertisedUrl = advertisedUrl;
          return { configChanged: true };
        },
      });
      const changed = Boolean(result.configChanged);
      if (changed) markRestart("a2a_channel_updated");
      return { advertisedUrl, changed, restartRequired: changed };
    });
  };

  return { read, upsertPeer, removePeer, update };
};

module.exports = {
  A2aChannelError,
  createA2aChannelService,
  defaultTokenEnvForPeer,
  isValidA2aPeerId,
  isValidA2aTokenEnv,
  kA2aPeerIdPattern,
  normalizeAdvertisedUrl,
};
