const fs = require("fs");
const { OPENCLAW_DIR } = require("./constants");
const {
  readOpenclawConfigForWrite,
  updateOpenclawConfig,
} = require("./openclaw-config");

// OpenClaw MCP server definitions (`mcp.servers.<name>` in openclaw.json) for
// the agent-admin ops mcp.server-list / server-set / server-remove.
//
// Entry schema: OpenClaw docs/gateway/config-extensions.md ("MCP") and
// docs/cli/mcp/registry.md; the validator is McpServerSchema in OpenClaw's
// src/config/zod-schema.mcp-server.ts (2026.9.5): url is an http(s) URL,
// transport is stdio|sse|streamable-http, headers is a string map,
// requestTimeoutMs is a positive finite number, toolFilter is a strict
// {include?, exclude?} of non-empty string lists. Config strings reference
// env vars as `${VAR}`, uppercase names only (docs/gateway/config-secrets-env.md,
// "Env var substitution"); `$${VAR}` is the escape for a literal `${VAR}`.
//
// Secret policy: a header value is accepted only when it is built from
// `${VAR}` references plus fixed scheme text ("Bearer ${GBRAIN_X_TOKEN}");
// anything else is treated as a literal secret, refused with 400, and never
// echoed. Every read projects entries through redactMcpServerEntry, which
// shows reference names and the fixed text that passes the same rule, and
// replaces anything else with a marker — for human and agent callers alike.

const kServerNamePattern = /^[A-Za-z0-9_-]{1,64}$/;
const kReservedNames = new Set(["__proto__", "constructor", "prototype"]);
// AlphaClaw's own REMOTE_MCP_URL entry (gateway.js ensureGatewayProxyConfig)
// carries this marker and is rewritten from env on every gateway start.
const kManagedMarker = "_alphaclawManaged";
const kHeaderNamePattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const kEnvRefPattern = /\$\{([A-Z_][A-Z0-9_]*)\}/g;
// Fixed text around references: at most two words of letters/hyphens
// (auth-scheme words such as Bearer, Basic, Token, Bot). No digits, no
// punctuation that a token alphabet uses, so a literal credential cannot hide
// in it.
const kFixedWordPattern = /^[A-Za-z][A-Za-z-]{0,23}$/;
const kMaxFixedWords = 2;
const kLiteralMarker = "<literal>";
const kRedactedMarker = "<redacted>";
const kPatchKeys = new Set(["url", "transport", "headers", "toolFilter", "requestTimeoutMs"]);
const kToolFilterKeys = new Set(["include", "exclude"]);
const kTransports = new Set(["streamable-http", "sse"]);
const kSensitiveQueryKey = /(token|key|secret|password|passwd|auth|sig|signature|credential)/i;

class McpServerError extends Error {
  constructor(message, { status = 400, code = "invalid_request", hint } = {}) {
    super(message);
    this.name = "McpServerError";
    this.status = status;
    this.code = code;
    if (hint) this.hint = hint;
  }
}

const isPlainObject = (value) =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// A key named in an error is echoed only when it has a key-like shape.
const describeKey = (key) =>
  /^[A-Za-z0-9_.-]{1,64}$/.test(String(key)) ? `"${key}"` : "an unrecognized key";

const normalizeServerName = (raw) => {
  const name = String(raw ?? "").trim();
  if (!kServerNamePattern.test(name) || kReservedNames.has(name)) {
    throw new McpServerError(
      "MCP server name must be 1-64 letters, digits, '-' or '_'",
      { code: "invalid_name" },
    );
  }
  return name;
};

const isFixedTextSafe = (segments) => {
  const words = segments
    .join(" ")
    .split(/[ \t]+/)
    .filter(Boolean);
  if (words.length > kMaxFixedWords) return false;
  // Only letters, hyphens and spaces/tabs may appear outside references.
  if (segments.some((segment) => /[^A-Za-z \t-]/.test(segment))) return false;
  return words.every((word) => kFixedWordPattern.test(word));
};

// Splits a config string into `${VAR}` references and the fixed text around
// them. ok=true only when the string is references + safe fixed text.
const analyzeEnvTemplate = (value) => {
  if (typeof value !== "string") return { ok: false, refs: [], segments: [] };
  const refs = [];
  const segments = [];
  let last = 0;
  for (const match of value.matchAll(kEnvRefPattern)) {
    segments.push(value.slice(last, match.index));
    refs.push(match[1]);
    last = match.index + match[0].length;
  }
  segments.push(value.slice(last));
  // `$${VAR}` (escape → literal `${VAR}`) or any stray `$` outside a valid
  // reference means the value is not purely env-backed.
  const escaped = /\$\$\{/.test(value);
  const strayDollar = segments.some((segment) => segment.includes("$"));
  const ok = refs.length > 0 && !escaped && !strayDollar && isFixedTextSafe(segments);
  return { ok, refs, segments };
};

// Shape of a header/env value for display: references kept by name, fixed
// text kept only when it passes the same rule the write path enforces.
const shapeEnvTemplate = (value) => {
  if (typeof value !== "string") return { shape: kLiteralMarker, literal: true };
  const analysis = analyzeEnvTemplate(value);
  if (analysis.ok) return { shape: value, literal: false };
  if (analysis.refs.length === 0) return { shape: kLiteralMarker, literal: true };
  const parts = [];
  analysis.segments.forEach((segment, index) => {
    if (segment) {
      const safe = !segment.includes("$") && isFixedTextSafe([segment]);
      parts.push(safe ? segment : kLiteralMarker);
    }
    if (index < analysis.refs.length) parts.push(`\${${analysis.refs[index]}}`);
  });
  return { shape: parts.join(""), literal: true };
};

const redactUrl = (raw) => {
  if (typeof raw !== "string") return raw === undefined ? undefined : kRedactedMarker;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return kRedactedMarker;
  }
  const hadUserinfo = Boolean(parsed.username || parsed.password);
  const params = [...parsed.searchParams.keys()];
  // Nothing credential-bearing besides the path: show the configured string.
  if (!hadUserinfo && params.length === 0 && !parsed.hash && !raw.includes("@")) return raw;
  const base = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  if (params.length === 0) return base;
  const query = params
    .map((key) => {
      const value = parsed.searchParams.get(key) || "";
      const pureRef = /^\$\{[A-Z_][A-Z0-9_]*\}$/.test(value);
      return `${encodeURIComponent(key)}=${pureRef ? value : kRedactedMarker}`;
    })
    .join("&");
  return `${base}?${query}`;
};

const kPassThroughKeys = [
  "enabled",
  "command",
  "cwd",
  "transport",
  "connectionTimeoutMs",
  "requestTimeoutMs",
  "supportsParallelToolCalls",
  "auth",
  "sslVerify",
  "clientCert",
  "clientKey",
];
const kOauthDisplayKeys = ["identity", "authProfileId", "scope", "redirectUrl", "clientMetadataUrl"];

// Explicit projection: known non-secret keys pass through, headers/env are
// shaped, args become a count, the url loses userinfo and query values, and
// every other key is reported by name only.
const redactMcpServerEntry = (entry) => {
  if (!isPlainObject(entry)) return { invalid: true };
  const out = {};
  const literalHeaders = [];
  const literalEnv = [];
  const otherKeys = [];
  for (const [key, value] of Object.entries(entry)) {
    if (key === kManagedMarker) continue;
    if (kPassThroughKeys.includes(key)) {
      out[key] = value;
    } else if (key === "url") {
      out.url = redactUrl(value);
    } else if (key === "headers" || key === "env") {
      if (!isPlainObject(value)) {
        out[key] = kRedactedMarker;
        continue;
      }
      const shaped = {};
      for (const [name, raw] of Object.entries(value)) {
        const { shape, literal } = shapeEnvTemplate(raw);
        shaped[name] = shape;
        if (literal) (key === "headers" ? literalHeaders : literalEnv).push(name);
      }
      out[key] = shaped;
    } else if (key === "args") {
      out.argsCount = Array.isArray(value) ? value.length : 0;
    } else if (key === "toolFilter") {
      out.toolFilter = isPlainObject(value)
        ? Object.fromEntries(
            ["include", "exclude"]
              .filter((k) => Array.isArray(value[k]))
              .map((k) => [k, value[k].filter((p) => typeof p === "string")]),
          )
        : kRedactedMarker;
    } else if (key === "oauth") {
      out.oauth = isPlainObject(value)
        ? Object.fromEntries(
            kOauthDisplayKeys.filter((k) => hasOwn(value, k)).map((k) => [k, value[k]]),
          )
        : kRedactedMarker;
    } else if (key === "codex") {
      out.codex = isPlainObject(value)
        ? {
            ...(Array.isArray(value.agents) ? { agents: value.agents } : {}),
            ...(typeof value.defaultToolsApprovalMode === "string"
              ? { defaultToolsApprovalMode: value.defaultToolsApprovalMode }
              : {}),
          }
        : kRedactedMarker;
    } else {
      otherKeys.push(key);
    }
  }
  if (entry[kManagedMarker] === true) out.managed = true;
  if (literalHeaders.length) out.literalHeaders = literalHeaders;
  if (literalEnv.length) out.literalEnv = literalEnv;
  if (otherKeys.length) out.otherKeys = otherKeys;
  return out;
};

const validateUrl = (value) => {
  if (typeof value !== "string" || !value.trim()) {
    throw new McpServerError("url must be a non-empty http(s) URL string", { code: "invalid_url" });
  }
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new McpServerError("url must be a valid http(s) URL", { code: "invalid_url" });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new McpServerError("url must use http:// or https://", { code: "invalid_url" });
  }
  if (parsed.username || parsed.password) {
    throw new McpServerError(
      "url must not carry credentials; put them in a header as a ${VAR} reference",
      { code: "literal_secret", hint: "Use headers: {\"Authorization\": \"Bearer ${YOUR_ENV_VAR}\"}." },
    );
  }
  for (const [key, paramValue] of parsed.searchParams.entries()) {
    if (!kSensitiveQueryKey.test(key)) continue;
    if (/^\$\{[A-Z_][A-Z0-9_]*\}$/.test(paramValue)) continue;
    throw new McpServerError(
      "url carries a credential-like query parameter with a literal value; use a ${VAR} reference or a header",
      { code: "literal_secret" },
    );
  }
  return value.trim();
};

const validateToolList = (list, field) => {
  if (!Array.isArray(list) || list.length === 0) {
    throw new McpServerError(`toolFilter.${field} must be a non-empty array of tool names, or null`, {
      code: "invalid_tool_filter",
    });
  }
  const out = [];
  for (const entry of list) {
    if (typeof entry !== "string" || !entry.trim()) {
      throw new McpServerError(`toolFilter.${field} entries must be non-empty strings`, {
        code: "invalid_tool_filter",
      });
    }
    const trimmed = entry.trim();
    if (!out.includes(trimmed)) out.push(trimmed);
  }
  return out;
};

// Validates a PUT body into a normalized patch. Field semantics (omitted =
// keep, null = remove) mirror agents.update's tools.fs patching. Throws
// McpServerError (400) and never includes a submitted value in the message.
const parseServerPatch = (body) => {
  if (!isPlainObject(body)) {
    throw new McpServerError("Body must be a JSON object", { code: "invalid_body" });
  }
  for (const key of Object.keys(body)) {
    if (!kPatchKeys.has(key)) {
      throw new McpServerError(
        `Unknown key ${describeKey(key)}; allowed: url, transport, headers, toolFilter, requestTimeoutMs`,
        { code: "unknown_key" },
      );
    }
  }
  const patch = {};
  if (hasOwn(body, "url")) {
    if (body.url === null) {
      throw new McpServerError("url cannot be removed; remove the server instead", { code: "invalid_url" });
    }
    patch.url = validateUrl(body.url);
  }
  if (hasOwn(body, "transport")) {
    if (body.transport !== null && !kTransports.has(body.transport)) {
      throw new McpServerError("transport must be \"streamable-http\" or \"sse\", or null", {
        code: "invalid_transport",
      });
    }
    patch.transport = body.transport;
  }
  if (hasOwn(body, "requestTimeoutMs")) {
    const value = body.requestTimeoutMs;
    if (value !== null && !(typeof value === "number" && Number.isFinite(value) && value > 0)) {
      throw new McpServerError("requestTimeoutMs must be a positive number of milliseconds, or null", {
        code: "invalid_timeout",
      });
    }
    patch.requestTimeoutMs = value;
  }
  if (hasOwn(body, "headers")) {
    if (body.headers === null) {
      patch.headers = null;
    } else {
      if (!isPlainObject(body.headers)) {
        throw new McpServerError("headers must be an object of header name to value, or null", {
          code: "invalid_headers",
        });
      }
      const headers = {};
      for (const [name, value] of Object.entries(body.headers)) {
        if (!kHeaderNamePattern.test(name)) {
          throw new McpServerError("headers contains an invalid header name", { code: "invalid_headers" });
        }
        if (value === null) {
          headers[name] = null;
          continue;
        }
        if (!analyzeEnvTemplate(value).ok) {
          throw new McpServerError(
            `Header "${name}" must be built from \${VAR} env references around fixed scheme text (e.g. "Bearer \${MY_TOKEN}"); literal values are refused`,
            {
              code: "literal_secret",
              hint: "Store the secret in an env var (env.update) and reference it as ${VAR_NAME}; uppercase names only.",
            },
          );
        }
        headers[name] = value;
      }
      patch.headers = headers;
    }
  }
  if (hasOwn(body, "toolFilter")) {
    if (body.toolFilter === null) {
      patch.toolFilter = null;
    } else {
      if (!isPlainObject(body.toolFilter)) {
        throw new McpServerError("toolFilter must be an object {include, exclude}, or null", {
          code: "invalid_tool_filter",
        });
      }
      const filter = {};
      for (const key of Object.keys(body.toolFilter)) {
        if (!kToolFilterKeys.has(key)) {
          throw new McpServerError(`Unknown toolFilter key ${describeKey(key)}; allowed: include, exclude`, {
            code: "unknown_key",
          });
        }
        const value = body.toolFilter[key];
        filter[key] = value === null ? null : validateToolList(value, key);
      }
      patch.toolFilter = filter;
    }
  }
  return patch;
};

const findHeaderKey = (headers, name) => {
  const lower = name.toLowerCase();
  return Object.keys(headers).find((key) => key.toLowerCase() === lower);
};

// Applies a normalized patch to an entry and returns the next entry. Keys the
// op does not manage (codex, enabled, auth, oauth, connectionTimeoutMs, ...)
// are carried over untouched.
const applyServerPatch = (current, patch) => {
  const next = isPlainObject(current) ? { ...current } : {};
  if (hasOwn(patch, "url")) next.url = patch.url;
  if (hasOwn(patch, "transport")) {
    if (patch.transport === null) delete next.transport;
    else next.transport = patch.transport;
  }
  if (hasOwn(patch, "requestTimeoutMs")) {
    if (patch.requestTimeoutMs === null) delete next.requestTimeoutMs;
    else next.requestTimeoutMs = patch.requestTimeoutMs;
  }
  if (hasOwn(patch, "headers")) {
    if (patch.headers === null) {
      delete next.headers;
    } else {
      const headers = isPlainObject(next.headers) ? { ...next.headers } : {};
      for (const [name, value] of Object.entries(patch.headers)) {
        // HTTP header names are case-insensitive: replace the existing
        // spelling instead of adding a second header.
        const existingKey = findHeaderKey(headers, name);
        if (existingKey !== undefined) delete headers[existingKey];
        if (value !== null) headers[name] = value;
      }
      if (Object.keys(headers).length > 0) next.headers = headers;
      else delete next.headers;
    }
  }
  if (hasOwn(patch, "toolFilter")) {
    if (patch.toolFilter === null) {
      delete next.toolFilter;
    } else {
      const filter = isPlainObject(next.toolFilter) ? { ...next.toolFilter } : {};
      for (const [key, value] of Object.entries(patch.toolFilter)) {
        if (value === null) delete filter[key];
        else filter[key] = value;
      }
      if (Object.keys(filter).length > 0) next.toolFilter = filter;
      else delete next.toolFilter;
    }
  }
  return next;
};

// OpenClaw's documented filter glob: exact text plus `*`
// (src/agents/mcp-tool-filter.ts, matchesMcpToolFilterPattern).
const matchesToolPattern = (pattern, value) => {
  const trimmed = String(pattern).trim();
  if (!trimmed) return false;
  if (!trimmed.includes("*")) return trimmed === value;
  const escaped = trimmed
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(value);
};

const toList = (value) => (Array.isArray(value) ? value.map((v) => String(v).trim()) : undefined);

// Narrowing = the next filter admits no tool the current one hides:
// include may only shrink (an absent include admits everything), exclude may
// only grow.
const isToolFilterNarrowing = (currentFilter, nextFilter) => {
  const cur = isPlainObject(currentFilter) ? currentFilter : {};
  const nxt = isPlainObject(nextFilter) ? nextFilter : {};
  const curInclude = toList(cur.include);
  const nextInclude = toList(nxt.include);
  if (nextInclude === undefined) {
    if (curInclude !== undefined) return false;
  } else if (curInclude !== undefined) {
    const within = nextInclude.every(
      (pattern) =>
        curInclude.includes(pattern) ||
        (!pattern.includes("*") && curInclude.some((c) => matchesToolPattern(c, pattern))),
    );
    if (!within) return false;
  }
  const curExclude = toList(cur.exclude) || [];
  const nextExclude = toList(nxt.exclude) || [];
  return curExclude.every((pattern) => nextExclude.includes(pattern));
};

const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
};

// Tier for one set: "write" when an existing server only narrows (smaller
// include, larger exclude, timeout), "dangerous" for a new server, a url /
// header / transport change, or a widened or cleared filter.
const classifyServerSet = ({ current, patch }) => {
  if (!isPlainObject(current)) return "dangerous";
  const next = applyServerPatch(current, patch);
  if (stableJson(current.url) !== stableJson(next.url)) return "dangerous";
  if (stableJson(current.transport) !== stableJson(next.transport)) return "dangerous";
  if (stableJson(current.headers) !== stableJson(next.headers)) return "dangerous";
  if (!isToolFilterNarrowing(current.toolFilter, next.toolFilter)) return "dangerous";
  return "write";
};

const readServers = (cfg) => {
  const servers = cfg?.mcp?.servers;
  if (servers === undefined) return {};
  if (!isPlainObject(servers)) throw new Error("mcp.servers is not an object");
  return servers;
};

const createMcpServersService = ({ fsModule = fs, openclawDir = OPENCLAW_DIR, log = console } = {}) => {
  const listServers = () => {
    const cfg = readOpenclawConfigForWrite({ fsModule, openclawDir });
    const servers = readServers(cfg);
    const names = Object.keys(servers).sort();
    return {
      names,
      servers: Object.fromEntries(names.map((name) => [name, redactMcpServerEntry(servers[name])])),
    };
  };

  const setServer = (rawName, body) => {
    const name = normalizeServerName(rawName);
    const patch = parseServerPatch(body);
    let created = false;
    let nextEntry;
    updateOpenclawConfig({
      fsModule,
      openclawDir,
      mutate: (cfg) => {
        const servers = readServers(cfg);
        const current = hasOwn(servers, name) ? servers[name] : undefined;
        if (current !== undefined && !isPlainObject(current)) {
          throw new McpServerError(`MCP server "${name}" is not an object in openclaw.json`, {
            status: 409,
            code: "invalid_existing_entry",
          });
        }
        if (current === undefined && !hasOwn(patch, "url")) {
          throw new McpServerError(`MCP server "${name}" not found`, {
            status: 404,
            code: "mcp_server_not_found",
            hint: "Creating a server requires url.",
          });
        }
        if (current?.[kManagedMarker] === true) {
          throw new McpServerError(`MCP server "${name}" is managed by REMOTE_MCP_* env and rewritten at every gateway start`, {
            status: 409,
            code: "managed_by_env",
            hint: "Change REMOTE_MCP_URL / REMOTE_MCP_API_TOKEN / REMOTE_MCP_NAME instead.",
          });
        }
        created = current === undefined;
        nextEntry = applyServerPatch(current, patch);
        if (!cfg.mcp || !isPlainObject(cfg.mcp)) cfg.mcp = {};
        cfg.mcp.servers = { ...servers, [name]: nextEntry };
        return {};
      },
    });
    log?.log?.(`[alphaclaw] MCP server "${name}" ${created ? "created" : "updated"}`);
    return { name, created, server: redactMcpServerEntry(nextEntry) };
  };

  const removeServer = (rawName) => {
    const name = normalizeServerName(rawName);
    updateOpenclawConfig({
      fsModule,
      openclawDir,
      mutate: (cfg) => {
        const servers = readServers(cfg);
        if (!hasOwn(servers, name)) {
          throw new McpServerError(`MCP server "${name}" not found`, {
            status: 404,
            code: "mcp_server_not_found",
          });
        }
        if (servers[name]?.[kManagedMarker] === true) {
          throw new McpServerError(`MCP server "${name}" is managed by REMOTE_MCP_* env and rewritten at every gateway start`, {
            status: 409,
            code: "managed_by_env",
            hint: "Unset REMOTE_MCP_URL / REMOTE_MCP_API_TOKEN instead.",
          });
        }
        const nextServers = { ...servers };
        delete nextServers[name];
        if (Object.keys(nextServers).length > 0) {
          cfg.mcp.servers = nextServers;
        } else {
          delete cfg.mcp.servers;
          if (Object.keys(cfg.mcp).length === 0) delete cfg.mcp;
        }
        return {};
      },
    });
    log?.log?.(`[alphaclaw] MCP server "${name}" removed`);
    return { name };
  };

  return { listServers, setServer, removeServer };
};

module.exports = {
  McpServerError,
  kManagedMarker,
  kLiteralMarker,
  normalizeServerName,
  analyzeEnvTemplate,
  shapeEnvTemplate,
  redactMcpServerEntry,
  parseServerPatch,
  applyServerPatch,
  isToolFilterNarrowing,
  classifyServerSet,
  readServers,
  createMcpServersService,
};
