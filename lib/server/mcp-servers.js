const fs = require("fs");
const path = require("path");
const { OPENCLAW_DIR } = require("./constants");
const {
  readOpenclawConfigForWrite,
  updateOpenclawConfig,
} = require("./openclaw-config");
const { classifyGatewayEnvKey } = require("./gateway-env-policy");
const { resolveRemoteMcpName } = require("./remote-mcp-name");
const { getGatewayLaunchEnvKeys } = require("./gateway-launch-env-snapshot");

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
// Secret policy:
// - A header value is exactly one `${VAR}`, optionally preceded by one
//   allowlisted scheme word and a space ("Bearer ${GBRAIN_X_TOKEN}"). Anything
//   else is a literal: refused with 400 and never echoed.
// - Every referenced VAR must reach the gateway child (gateway-env-policy.js
//   classifyGatewayEnvKey, the same decision filterGatewayChildEnv makes), or
//   OpenClaw would send the literal "${VAR}" text. AlphaClaw's and OpenClaw's
//   own credentials (OPENCLAW_*, ALPHACLAW_*, the gateway/webhook tokens, the
//   managed remote-MCP token) may never be referenced.
// - A url may not carry userinfo, a fragment, a credential-like path segment,
//   or a credential-like query/matrix parameter with a literal value.
// - Every read projects entries through redactMcpServerEntry, for human and
//   agent callers alike.

const kServerNamePattern = /^[A-Za-z0-9_-]{1,64}$/;
const kReservedNames = new Set(["__proto__", "constructor", "prototype"]);
// AlphaClaw's own REMOTE_MCP_URL entry (gateway.js ensureGatewayProxyConfig)
// carries this marker and is rewritten from env on every gateway start.
const kManagedMarker = "_alphaclawManaged";
const kHeaderNamePattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const kEnvRefPattern = /\$\{([A-Z_][A-Z0-9_]*)\}/g;
const kPureRefPattern = /^\$\{([A-Z_][A-Z0-9_]*)\}$/;
const kSchemeWords = ["Bearer", "Basic", "Token", "Bot", "ApiKey"];
const kHeaderTemplatePattern = new RegExp(
  `^(?:(${kSchemeWords.join("|")}) )?\\$\\{([A-Z_][A-Z0-9_]*)\\}$`,
);
const kSchemePrefixPattern = new RegExp(`^(?:${kSchemeWords.join("|")}) $`);
const kLiteralMarker = "<literal>";
const kRedactedMarker = "<redacted>";
const kPatchKeys = new Set(["url", "transport", "headers", "toolFilter", "requestTimeoutMs"]);
const kToolFilterKeys = new Set(["include", "exclude"]);
const kTransports = new Set(["streamable-http", "sse"]);
// Sensitive url parameter keys, matched against the whole key or its
// `_`/`-`/`.`/camelCase-delimited parts (never substrings): access_token,
// apiKey and X-Amz-Signature match; code_version, session and authorized do
// not.
const kSensitiveKeyParts = new Set([
  "token",
  "key",
  "apikey",
  "secret",
  "password",
  "passwd",
  "pwd",
  "auth",
  "authorization",
  "sig",
  "signature",
  "credential",
  "credentials",
  "jwt",
  "bearer",
  "sessionid",
  "jsessionid",
  "sid",
  "cookie",
]);
const kSensitiveWholeKeys = new Set(["code", "pass"]);
const isSensitiveParamKey = (rawKey) => {
  const key = safeDecode(String(rawKey ?? ""));
  const lower = key.toLowerCase();
  if (kSensitiveWholeKeys.has(lower) || kSensitiveKeyParts.has(lower)) return true;
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[-_.]+/)
    .some((part) => kSensitiveKeyParts.has(part));
};
// Env vars an MCP header must never carry: AlphaClaw's and OpenClaw's own
// credentials. Exact names on top of the prefixes.
const kReservedEnvPrefixes = ["OPENCLAW_", "ALPHACLAW_"];
const kReservedEnvNames = new Set([
  "OPENCLAW_GATEWAY_TOKEN",
  "OPENCLAW_GATEWAY_PASSWORD",
  "WEBHOOK_TOKEN",
  "SETUP_PASSWORD",
  "REMOTE_MCP_API_TOKEN",
]);

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

const safeDecode = (value) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

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

// The REMOTE_MCP_NAME key (default "remote") belongs to the gateway's managed
// entry even while REMOTE_MCP_* is unset: a server created there would be
// overwritten or deleted at the next gateway start.
const isReservedServerName = (name, env = process.env) => name === resolveRemoteMcpName(env).name;

// ---------------------------------------------------------------------------
// Credential detection (shared by url validation and url redaction)

const kCredentialPrefixPattern =
  /^(?:(?:sk|rk|pk)[-_]|gh[pousr]_|github_pat_|xox[a-z]-|eyJ|AKIA|ASIA|AIza|glpat-|ya29\.|hf_|npm_)/;
const kUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const shannonEntropy = (text) => {
  const counts = new Map();
  for (const ch of text) counts.set(ch, (counts.get(ch) || 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    bits -= p * Math.log2(p);
  }
  return bits;
};

// True for a string that looks like a credential rather than a word or an
// identifier: a known token prefix, a UUID (capability URLs), or a long
// high-entropy run (letters mixed with digits, or long mixed-case runs).
// Separators split words, so "streamable-http-v2-endpoint" stays a path.
const looksLikeCredential = (raw) => {
  const text = String(raw ?? "");
  if (!text || kPureRefPattern.test(text)) return false;
  if (kCredentialPrefixPattern.test(text) || kUuidPattern.test(text)) return true;
  if (text.length >= 32 && shannonEntropy(text) >= 3.5) return true;
  return text.split(/[-_.~+]/).some((piece) => {
    if (piece.length >= 16 && /[0-9]/.test(piece) && /[A-Za-z]/.test(piece)) {
      return shannonEntropy(piece) >= 3.0;
    }
    if (piece.length >= 20 && /[a-z]/.test(piece) && /[A-Z]/.test(piece)) {
      return (piece.match(/[A-Z]/g) || []).length >= 4 && shannonEntropy(piece) >= 3.5;
    }
    return false;
  });
};

// ---------------------------------------------------------------------------
// Header templates

// ok=true only for "[Scheme ]${VAR}" with Scheme in the allowlist.
const analyzeEnvTemplate = (value) => {
  if (typeof value !== "string") return { ok: false, refs: [] };
  const refs = [...value.matchAll(kEnvRefPattern)].map((m) => m[1]);
  const match = value.match(kHeaderTemplatePattern);
  if (!match) return { ok: false, refs };
  return { ok: true, refs: [match[2]], scheme: match[1] || null };
};

// Display shape: a valid template shows as is; otherwise references keep
// their names, a leading allowlisted scheme word stays, everything else is
// <literal>.
const shapeEnvTemplate = (value) => {
  if (typeof value !== "string") return { shape: kLiteralMarker, literal: true };
  if (analyzeEnvTemplate(value).ok) return { shape: value, literal: false };
  const matches = [...value.matchAll(kEnvRefPattern)];
  if (matches.length === 0) return { shape: kLiteralMarker, literal: true };
  const parts = [];
  let last = 0;
  matches.forEach((match, index) => {
    const segment = value.slice(last, match.index);
    if (segment) {
      parts.push(index === 0 && kSchemePrefixPattern.test(segment) ? segment : kLiteralMarker);
    }
    parts.push(`\${${match[1]}}`);
    last = match.index + match[0].length;
  });
  if (value.slice(last)) parts.push(kLiteralMarker);
  return { shape: parts.join(""), literal: true };
};

// Throws unless the gateway child will receive VAR and VAR is not one of
// AlphaClaw's/OpenClaw's own credentials. `where` names the field for the
// message (a header name or "url"); VAR names are not secrets.
const assertEnvRefUsable = (
  name,
  where,
  { classifyEnv = classifyGatewayEnvKey, env = process.env } = {},
) => {
  if (kReservedEnvNames.has(name) || kReservedEnvPrefixes.some((p) => name.startsWith(p))) {
    throw new McpServerError(
      `${where} references \${${name}}, an AlphaClaw/OpenClaw credential; an MCP server must never receive it`,
      { code: "env_reserved", hint: "Store the MCP server's own credential under a separate *_AUTH_TOKEN name." },
    );
  }
  const decision = classifyEnv(name);
  if (!decision?.forwarded) {
    throw new McpServerError(
      `${where} references \${${name}}, which the gateway does not receive (rule: ${decision?.rule || "unknown"}); OpenClaw would send the unresolved text`,
      {
        code: "env_not_forwarded",
        hint: "Name the variable *_AUTH_TOKEN (forwarded by suffix), or have the operator add it to ALPHACLAW_GATEWAY_ENV_PASSTHROUGH in the deployment env.",
      },
    );
  }
  // Forwarded by name is not enough: the gateway child env is process.env
  // through the policy, so an unset or empty VAR stays the literal text.
  if (!String(env?.[name] ?? "").trim()) {
    throw new McpServerError(
      `${where} references \${${name}}, which is not set (or empty) in AlphaClaw's environment; OpenClaw would send the unresolved text`,
      { code: "env_not_set", hint: "Set the variable first (env.update), then retry." },
    );
  }
};

// ---------------------------------------------------------------------------
// URLs

const splitMatrix = (segment) => {
  const [head, ...params] = segment.split(";");
  return {
    head,
    params: params.map((param) => {
      const eq = param.indexOf("=");
      return eq < 0 ? { key: param, value: "" } : { key: param.slice(0, eq), value: param.slice(eq + 1) };
    }),
  };
};

const redactUrl = (raw) => {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") return kRedactedMarker;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return kRedactedMarker;
  }
  let changed = Boolean(parsed.username || parsed.password || parsed.hash || raw.includes("@"));
  const hostLabels = parsed.hostname.split(".").map((label) => {
    if (!looksLikeCredential(label)) return label;
    changed = true;
    return kRedactedMarker;
  });
  const shownHost = `${hostLabels.join(".")}${parsed.port ? `:${parsed.port}` : ""}`;
  const segments = parsed.pathname.split("/").map((segment) => {
    const { head, params } = splitMatrix(segment);
    const decodedHead = safeDecode(head);
    let shownHead = head;
    if (kPureRefPattern.test(decodedHead)) shownHead = decodedHead;
    else if (looksLikeCredential(decodedHead)) {
      shownHead = kRedactedMarker;
      changed = true;
    }
    if (params.length === 0) return shownHead;
    changed = true;
    const shownParams = params.map(({ key, value }) => {
      const decodedValue = safeDecode(value);
      return `${key}=${kPureRefPattern.test(decodedValue) ? decodedValue : kRedactedMarker}`;
    });
    return [shownHead, ...shownParams].join(";");
  });
  const keys = [...parsed.searchParams.keys()];
  if (keys.length > 0) changed = true;
  if (!changed) return raw;
  const base = `${parsed.protocol}//${shownHost}${segments.join("/")}`;
  if (keys.length === 0) return base;
  const query = keys
    .map((key) => {
      const value = parsed.searchParams.get(key) || "";
      return `${encodeURIComponent(key)}=${kPureRefPattern.test(value) ? value : kRedactedMarker}`;
    })
    .join("&");
  return `${base}?${query}`;
};

const literalUrlSecret = (what) =>
  new McpServerError(`url ${what}; use a \${VAR} reference or a header instead`, {
    code: "literal_secret",
    hint: 'Use headers: {"Authorization": "Bearer ${YOUR_SERVICE_AUTH_TOKEN}"}.',
  });

// Returns { url, refs } or throws. Never echoes any part of the url.
const validateUrl = (value) => {
  if (typeof value !== "string" || !value.trim()) {
    throw new McpServerError("url must be a non-empty http(s) URL string", { code: "invalid_url" });
  }
  const trimmed = value.trim();
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new McpServerError("url must be a valid http(s) URL", { code: "invalid_url" });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new McpServerError("url must use http:// or https://", { code: "invalid_url" });
  }
  if (parsed.username || parsed.password) throw literalUrlSecret("must not carry credentials (userinfo)");
  if (parsed.hash) {
    throw new McpServerError("url must not carry a #fragment", { code: "invalid_url" });
  }
  if (parsed.hostname.split(".").some((label) => looksLikeCredential(label))) {
    throw literalUrlSecret("has a credential-like host label");
  }
  for (const segment of parsed.pathname.split("/")) {
    const { head, params } = splitMatrix(segment);
    if (looksLikeCredential(safeDecode(head))) throw literalUrlSecret("has a credential-like path segment");
    for (const { key, value: paramValue } of params) {
      const decodedValue = safeDecode(paramValue);
      if (kPureRefPattern.test(decodedValue)) continue;
      if (isSensitiveParamKey(key) || looksLikeCredential(decodedValue)) {
        throw literalUrlSecret("carries a credential-like ;matrix parameter with a literal value");
      }
    }
  }
  for (const [key, paramValue] of parsed.searchParams.entries()) {
    if (kPureRefPattern.test(paramValue)) continue;
    if (isSensitiveParamKey(key) || looksLikeCredential(paramValue)) {
      throw literalUrlSecret("carries a credential-like query parameter with a literal value");
    }
  }
  const refs = [...trimmed.matchAll(kEnvRefPattern)].map((m) => m[1]);
  return { url: trimmed, refs };
};

// ---------------------------------------------------------------------------
// Read projection

const kPassThroughKeys = [
  "enabled",
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
const kOauthPlainKeys = ["identity", "authProfileId", "scope"];
const kOauthUrlKeys = ["redirectUrl", "clientMetadataUrl"];

// Explicit projection: known non-secret keys pass through, headers/env are
// shaped, command becomes {program, argCount}, urls lose userinfo, query and
// matrix values and credential-like path segments, and every other key is
// reported by name only.
const redactMcpServerEntry = (entry) => {
  if (!isPlainObject(entry)) return { invalid: true };
  const out = {};
  const literalHeaders = [];
  const literalEnv = [];
  const otherKeys = [];
  const argsLength = Array.isArray(entry.args) ? entry.args.length : 0;
  for (const [key, value] of Object.entries(entry)) {
    if (key === kManagedMarker) continue;
    if (kPassThroughKeys.includes(key)) {
      out[key] = value;
    } else if (key === "url") {
      out.url = redactUrl(value);
    } else if (key === "command") {
      const tokens = typeof value === "string" ? value.trim().split(/\s+/).filter(Boolean) : [];
      out.command = {
        program:
          tokens.length && !looksLikeCredential(path.basename(tokens[0]))
            ? path.basename(tokens[0])
            : kRedactedMarker,
        argCount: Math.max(0, tokens.length - 1) + argsLength,
      };
    } else if (key === "args") {
      if (!hasOwn(entry, "command")) out.argsCount = argsLength;
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
        ? {
            ...Object.fromEntries(kOauthPlainKeys.filter((k) => hasOwn(value, k)).map((k) => [k, value[k]])),
            ...Object.fromEntries(
              kOauthUrlKeys.filter((k) => hasOwn(value, k)).map((k) => [k, redactUrl(value[k])]),
            ),
          }
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

// ---------------------------------------------------------------------------
// Patch parsing and application

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
const parseServerPatch = (body, { classifyEnv = classifyGatewayEnvKey, env = process.env } = {}) => {
  if (!isPlainObject(body)) {
    throw new McpServerError("Body must be a JSON object", { code: "invalid_body" });
  }
  const keys = Object.keys(body);
  if (keys.length === 0) {
    throw new McpServerError(
      "Body must set at least one of url, transport, headers, toolFilter, requestTimeoutMs",
      { code: "invalid_body" },
    );
  }
  for (const key of keys) {
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
    const { url, refs } = validateUrl(body.url);
    for (const ref of refs) assertEnvRefUsable(ref, "url", { classifyEnv, env });
    patch.url = url;
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
        const analysis = analyzeEnvTemplate(value);
        if (!analysis.ok) {
          throw new McpServerError(
            `Header "${name}" must be exactly one \${VAR} reference, optionally after one scheme word (${kSchemeWords.join(", ")}) and a space, e.g. "Bearer \${MY_SERVICE_AUTH_TOKEN}"; literal values are refused`,
            {
              code: "literal_secret",
              hint: "Store the secret in an env var named *_AUTH_TOKEN (env.update) and reference it as ${VAR_NAME}; uppercase names only.",
            },
          );
        }
        assertEnvRefUsable(analysis.refs[0], `Header "${name}"`, { classifyEnv, env });
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

// ---------------------------------------------------------------------------
// Tiering

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

// A `*` anywhere in a submitted filter list. Codex's MCP projection asserts
// exact tool names and throws on a glob, so a glob is never a plain write.
const patchHasToolGlob = (patch) =>
  isPlainObject(patch?.toolFilter) &&
  Object.values(patch.toolFilter).some((list) => Array.isArray(list) && list.some((p) => p.includes("*")));

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
// include, larger exclude, timeout); "dangerous" for a new server, a url /
// header / transport change, a widened or cleared filter, or any glob in a
// submitted filter list.
const classifyServerSet = ({ current, patch }) => {
  if (!isPlainObject(current)) return "dangerous";
  if (patchHasToolGlob(patch)) return "dangerous";
  const next = applyServerPatch(current, patch);
  if (stableJson(current.url) !== stableJson(next.url)) return "dangerous";
  if (stableJson(current.transport) !== stableJson(next.transport)) return "dangerous";
  if (stableJson(current.headers) !== stableJson(next.headers)) return "dangerous";
  if (!isToolFilterNarrowing(current.toolFilter, next.toolFilter)) return "dangerous";
  return "write";
};

// ---------------------------------------------------------------------------
// Confirm summaries (what the approving admin sees for a dangerous call)
//
// The line is rendered into the house notification format (bold, `code`,
// [label](url); utils/telegram-html.js), so every agent-supplied fragment
// (tool names) is reduced to [A-Za-z0-9_.:/-] and quoted, credential-shaped
// fragments are <redacted>, and only validated values (server name, header
// names, scheme words, VAR names, transport enum) appear as is. The
// high-consequence facts come first and are never dropped; variable-length
// lists are summarised by count plus at most kSummaryNames names, and the
// detail tail is cut to kSummaryDetailBudget characters.

const kSummaryNames = 3;
const kSummaryFragmentMax = 32;
const kSummaryHostMax = 64;
const kSummaryDetailBudget = 320;

const quoteFragment = (raw) => {
  const text = String(raw ?? "");
  if (looksLikeCredential(text)) return kRedactedMarker;
  const kept = text.replace(/[^A-Za-z0-9_.:/-]/g, "").slice(0, kSummaryFragmentMax);
  return `"${kept}${kept.length < text.length ? "~" : ""}"`;
};

const summarizeNames = (names) => {
  const shown = names.slice(0, kSummaryNames).map(quoteFragment);
  const more = names.length - shown.length;
  return `${names.length} [${shown.join(", ")}${more > 0 ? `, +${more} more` : ""}]`;
};

const listDelta = (before, after) => {
  const b = toList(before) || [];
  const a = toList(after) || [];
  return { added: a.filter((x) => !b.includes(x)), removed: b.filter((x) => !a.includes(x)) };
};

const summaryHost = (url) => {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname
      .split(".")
      .map((label) => (looksLikeCredential(label) ? kRedactedMarker : label.replace(/[^A-Za-z0-9-]/g, "")))
      .join(".");
    const clipped = host.length > kSummaryHostMax ? `${host.slice(0, kSummaryHostMax)}~` : host;
    return parsed.port ? `${clipped}:${parsed.port}` : clipped;
  } catch {
    return "invalid";
  }
};

// One line. Critical part (always shown, bounded): name, NEW/UPDATE, url
// host, transport, filter verdict (CLEARED / WIDENED / narrowed), GLOB,
// header change counts. Detail tail: header names with their VAR names and
// the include/exclude delta, cut at the budget.
const describeServerSet = ({ name, current, patch }) => {
  const isNew = !isPlainObject(current);
  const critical = [`server "${String(name).replace(/[^A-Za-z0-9_-]/g, "")}" ${isNew ? "NEW" : "UPDATE"}`];
  const detail = [];
  if (hasOwn(patch, "url")) critical.push(`url host ${summaryHost(patch.url)}`);
  if (hasOwn(patch, "transport")) critical.push(`transport ${patch.transport ?? "removed"}`);
  if (hasOwn(patch, "toolFilter")) {
    const next = applyServerPatch(current, { toolFilter: patch.toolFilter });
    if (patch.toolFilter === null || !next.toolFilter) {
      if (isPlainObject(current?.toolFilter)) critical.push("FILTER CLEARED");
    } else if (!isToolFilterNarrowing(current?.toolFilter, next.toolFilter)) {
      critical.push("FILTER WIDENED");
    } else {
      critical.push("filter narrowed");
    }
    if (patchHasToolGlob(patch)) critical.push("GLOB IN FILTER");
    if (isPlainObject(patch.toolFilter)) {
      const before = isPlainObject(current?.toolFilter) ? current.toolFilter : {};
      const after = next.toolFilter || {};
      for (const key of ["include", "exclude"]) {
        if (!hasOwn(patch.toolFilter, key)) continue;
        if (patch.toolFilter[key] === null) {
          detail.push(`${key} removed`);
          continue;
        }
        const { added, removed } = listDelta(before[key], after[key]);
        const parts = [];
        if (added.length) parts.push(`+${summarizeNames(added)}`);
        if (removed.length) parts.push(`-${summarizeNames(removed)}`);
        detail.push(`${key} ${parts.join(" ") || "unchanged"}`);
      }
    }
  }
  if (hasOwn(patch, "headers")) {
    if (patch.headers === null) critical.push("ALL HEADERS REMOVED");
    else {
      const entries = Object.entries(patch.headers);
      const set = entries.filter(([, value]) => value !== null);
      const removed = entries.filter(([, value]) => value === null);
      critical.push(`headers set ${set.length}, removed ${removed.length}`);
      const shown = set.slice(0, kSummaryNames).map(([header, value]) => {
        const analysis = analyzeEnvTemplate(value);
        const shownHeader = header.length > kSummaryFragmentMax ? `${header.slice(0, kSummaryFragmentMax)}~` : header;
        return `${shownHeader}=${analysis.scheme ? `${analysis.scheme} ` : ""}\${${analysis.refs[0]}}`;
      });
      if (set.length > kSummaryNames) shown.push(`+${set.length - kSummaryNames} more`);
      if (shown.length) detail.push(`set ${shown.join(", ")}`);
      if (removed.length) {
        const names = removed
          .slice(0, kSummaryNames)
          .map(([header]) => (header.length > kSummaryFragmentMax ? `${header.slice(0, kSummaryFragmentMax)}~` : header));
        if (removed.length > kSummaryNames) names.push(`+${removed.length - kSummaryNames} more`);
        detail.push(`removed ${names.join(", ")}`);
      }
    }
  }
  if (hasOwn(patch, "requestTimeoutMs")) detail.push(`requestTimeoutMs ${patch.requestTimeoutMs ?? "removed"}`);
  let line = critical.join("; ");
  for (const part of detail) {
    if (line.length + part.length + 2 > kSummaryDetailBudget) {
      line += "; ...";
      break;
    }
    line += `; ${part}`;
  }
  return line;
};

// ---------------------------------------------------------------------------
// Service

const patchEnvRefs = (patch) => {
  const refs = [];
  if (typeof patch.url === "string") refs.push(...[...patch.url.matchAll(kEnvRefPattern)].map((m) => m[1]));
  if (isPlainObject(patch.headers)) {
    for (const value of Object.values(patch.headers)) {
      if (typeof value === "string") refs.push(...analyzeEnvTemplate(value).refs);
    }
  }
  return [...new Set(refs)];
};

const readServers = (cfg) => {
  const servers = cfg?.mcp?.servers;
  if (servers === undefined) return {};
  if (!isPlainObject(servers)) throw new Error("mcp.servers is not an object");
  return servers;
};

const reservedNameError = (name) =>
  new McpServerError(
    `MCP server "${name}" is the REMOTE_MCP_NAME key: when REMOTE_MCP_URL and REMOTE_MCP_API_TOKEN are both set, AlphaClaw rewrites it at every gateway start, and it removes the entry only while it carries AlphaClaw's managed marker`,
    {
      status: 409,
      code: "managed_by_env",
      hint: "Use another name, or configure this server through REMOTE_MCP_URL / REMOTE_MCP_API_TOKEN / REMOTE_MCP_NAME.",
    },
  );

const createMcpServersService = ({
  fsModule = fs,
  openclawDir = OPENCLAW_DIR,
  log = console,
  env = process.env,
  classifyEnv = classifyGatewayEnvKey,
  getLaunchedEnvKeys = getGatewayLaunchEnvKeys,
} = {}) => {
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
    if (isReservedServerName(name, env)) throw reservedNameError(name);
    const patch = parseServerPatch(body, { classifyEnv, env });
    let created = false;
    let changed = false;
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
        if (current?.[kManagedMarker] === true) throw reservedNameError(name);
        created = current === undefined;
        nextEntry = applyServerPatch(current, patch);
        changed = created || stableJson(current) !== stableJson(nextEntry);
        // A no-op patch never round-trips the operator's file.
        if (!changed) return { skipWrite: true };
        if (!cfg.mcp || !isPlainObject(cfg.mcp)) cfg.mcp = {};
        cfg.mcp.servers = { ...servers, [name]: nextEntry };
        return {};
      },
    });
    if (changed) log?.log?.(`[alphaclaw] MCP server "${name}" ${created ? "created" : "updated"}`);
    // OpenClaw hot-applies the entry, but resolves ${VAR} from the RUNNING
    // gateway's env: a VAR set (env.update) after that daemon spawned is not
    // there until a restart. Names only.
    const refs = patchEnvRefs(patch);
    const launched = getLaunchedEnvKeys();
    const missing = changed ? refs.filter((ref) => !launched || !launched.has(ref)) : [];
    const result = { name, created, changed, restartRequired: missing.length > 0, server: redactMcpServerEntry(nextEntry) };
    if (missing.length > 0) {
      result.warning = launched
        ? `The running gateway was started before ${missing.map((ref) => `\${${ref}}`).join(", ")} was set; restart the gateway so OpenClaw can resolve it.`
        : `The running gateway's environment is unknown to this AlphaClaw process; restart the gateway to be sure ${missing.map((ref) => `\${${ref}}`).join(", ")} resolves.`;
    }
    return result;
  };

  const removeServer = (rawName) => {
    const name = normalizeServerName(rawName);
    if (isReservedServerName(name, env)) throw reservedNameError(name);
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
        if (servers[name]?.[kManagedMarker] === true) throw reservedNameError(name);
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
  kSchemeWords,
  normalizeServerName,
  isReservedServerName,
  looksLikeCredential,
  isSensitiveParamKey,
  analyzeEnvTemplate,
  shapeEnvTemplate,
  assertEnvRefUsable,
  redactUrl,
  redactMcpServerEntry,
  parseServerPatch,
  applyServerPatch,
  isToolFilterNarrowing,
  patchHasToolGlob,
  classifyServerSet,
  describeServerSet,
  readServers,
  createMcpServersService,
};
