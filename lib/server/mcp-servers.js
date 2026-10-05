const crypto = require("crypto");
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
const kPatchKeys = new Set(["url", "transport", "headers", "toolFilter", "requestTimeoutMs", "revision"]);
// Entry revision: 16 hex chars of sha256 over the entry's canonical JSON
// (sorted keys). "absent" stands for "no entry under this name".
const kAbsentRevision = "absent";
const kRevisionPattern = /^(?:[0-9a-f]{16}|absent)$/;
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
// `wholeString: false` skips the whole-string entropy rule (tool names: a
// long snake_case identifier has high whole-string entropy but no
// credential-shaped piece).
const looksLikeCredential = (raw, { wholeString = true } = {}) => {
  const text = String(raw ?? "");
  if (!text || kPureRefPattern.test(text)) return false;
  if (kCredentialPrefixPattern.test(text) || kUuidPattern.test(text)) return true;
  if (wholeString && text.length >= 32 && shannonEntropy(text) >= 3.5) return true;
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

// URL parameter KEYS. A key is a word key, never a credential, when it is
// letters split by -_. and camelCase into words that are each a lowercase
// word of 3-20 letters, a capitalised word of 3-21, a 1-5 letter acronym, or
// a 1-2 letter lowercase word, with at least one lowercase run of 4+ letters:
// "includeDeprecatedEndpointsForCompatibility", "api-version". Any other key
// gets the full looksLikeCredential check (prefix, UUID, whole-string
// entropy, pieces). A word key is also at most 48 characters long and has
// at most 2 words of 15+ letters; longer ones get the full check too. A pure
// ${VAR} key is a reference, not a literal.
const kKeyWordMaxLength = 48;
const kKeyLongWordMax = 2;
const kKeyWordPattern = /^(?:[a-z]{3,20}|[A-Z][a-z]{2,20}|[A-Z]{1,5}|[a-z]{1,2})$/;
const looksLikeCredentialKey = (raw) => {
  const key = String(raw ?? "");
  if (!key || kPureRefPattern.test(key)) return false;
  if (kCredentialPrefixPattern.test(key) || kUuidPattern.test(key)) return true;
  if (/^[A-Za-z]+(?:[-_.][A-Za-z]+)*$/.test(key)) {
    const words = key.replace(/([a-z])([A-Z])/g, "$1 $2").split(/[-_. ]+/);
    if (
      key.length <= kKeyWordMaxLength &&
      words.filter((word) => word.length >= 15).length <= kKeyLongWordMax &&
      words.every((word) => kKeyWordPattern.test(word)) &&
      /[a-z]{4}/.test(key)
    ) {
      return false;
    }
  }
  return looksLikeCredential(key);
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
      const decodedKey = safeDecode(key);
      const shownKey = kPureRefPattern.test(decodedKey)
        ? decodedKey
        : looksLikeCredentialKey(decodedKey)
          ? kRedactedMarker
          : key;
      return `${shownKey}=${kPureRefPattern.test(decodedValue) ? decodedValue : kRedactedMarker}`;
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
      const shownKey = kPureRefPattern.test(key)
        ? key
        : looksLikeCredentialKey(key)
          ? kRedactedMarker
          : encodeURIComponent(key);
      return `${shownKey}=${kPureRefPattern.test(value) ? value : kRedactedMarker}`;
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
      // The key itself can be the credential (";<token>", ";<token>=1").
      const decodedKey = safeDecode(key);
      if (looksLikeCredentialKey(decodedKey)) throw literalUrlSecret("has a credential-like ;matrix parameter key");
      const decodedValue = safeDecode(paramValue);
      if (kPureRefPattern.test(decodedValue)) continue;
      // ";${VAR}" / ";${VAR}=x": the key is a reference (counted in SENDS);
      // only a credential-like literal value is refused.
      if (kPureRefPattern.test(decodedKey)) {
        if (looksLikeCredential(decodedValue)) {
          throw literalUrlSecret("carries a credential-like ;matrix parameter with a literal value");
        }
        continue;
      }
      if (isSensitiveParamKey(key) || looksLikeCredential(decodedValue)) {
        throw literalUrlSecret("carries a credential-like ;matrix parameter with a literal value");
      }
    }
  }
  for (const [key, paramValue] of parsed.searchParams.entries()) {
    // searchParams keys are already decoded; "?<token>" and "?<uuid>" are keys.
    if (looksLikeCredentialKey(key)) throw literalUrlSecret("has a credential-like query parameter key");
    if (kPureRefPattern.test(paramValue)) continue;
    // "?${VAR}" / "?${VAR}=x": the key is a reference (counted in SENDS).
    if (kPureRefPattern.test(key)) {
      if (looksLikeCredential(paramValue)) {
        throw literalUrlSecret("carries a credential-like query parameter with a literal value");
      }
      continue;
    }
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
  "sslVerify",
];

// OpenClaw 2026.9.5: `auth` is z.literal("oauth") (dist/types.openclaw-*.d.ts,
// McpServerSchema; docs/cli/mcp/transports.md "auth: oauth"), and
// clientCert/clientKey are file paths read with fs.readFileSync
// (dist/mcp-http-fetch-*.mjs buildMcpHttpFetch; transports.md "mTLS client
// certificate and key paths"). A hand-edited file can still hold anything
// there: `auth` is shown only when it is exactly "oauth" (no other value and
// no key of an object is echoed), and a TLS value only when it is a plain
// absolute path. The character set excludes whitespace, "\", "=" and
// newlines, so inline PEM (one line or many) can never pass and needs no
// separate "-----BEGIN" check.
const projectAuthValue = (value) => (value === "oauth" ? value : kRedactedMarker);
const kTlsPathMax = 1024;
const projectTlsPath = (value) =>
  typeof value === "string" &&
  value.startsWith("/") &&
  value.length <= kTlsPathMax &&
  /^[A-Za-z0-9._/@+-]+$/.test(value) &&
  !value.includes("..") &&
  !looksLikeCredential(value) &&
  !value.split("/").some((segment) => looksLikeCredential(segment))
    ? value
    : kRedactedMarker;
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
    } else if (key === "auth") {
      out.auth = projectAuthValue(value);
    } else if (key === "clientCert" || key === "clientKey") {
      out[key] = projectTlsPath(value);
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

// At most kMaxHeaders headers per patch and per resulting entry.
const kMaxHeaders = 32;
const tooManyHeadersError = () =>
  new McpServerError(`An MCP server takes at most ${kMaxHeaders} headers, per call and in the resulting entry`, {
    code: "too_many_headers",
  });

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
  const keys = Object.keys(body).filter((key) => key !== "revision");
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
  if (hasOwn(body, "revision")) {
    if (typeof body.revision !== "string" || !kRevisionPattern.test(body.revision)) {
      throw new McpServerError('revision must be the 16-hex-character revision from mcp.server-list, or "absent" for a new server', {
        code: "invalid_revision",
      });
    }
    patch.revision = body.revision;
  }
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
      // Checked before any per-header work: the merge and the summaries are
      // linear in this count, and the cap keeps one call cheap.
      if (Object.keys(body.headers).length > kMaxHeaders) throw tooManyHeadersError();
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
      // HTTP header names are case-insensitive: a patched name replaces
      // (or, with null, removes) EVERY existing spelling of it, including
      // case duplicates a hand edit left on disk. One lower-cased index of
      // all spellings, so the merge is linear.
      const byLower = new Map();
      for (const key of Object.keys(headers)) {
        const lower = key.toLowerCase();
        if (!byLower.has(lower)) byLower.set(lower, []);
        byLower.get(lower).push(key);
      }
      for (const [name, value] of Object.entries(patch.headers)) {
        const lower = name.toLowerCase();
        for (const existingKey of byLower.get(lower) || []) delete headers[existingKey];
        byLower.delete(lower);
        if (value !== null) {
          headers[name] = value;
          byLower.set(lower, [name]);
        }
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

const entryRevision = (entry) =>
  entry === undefined
    ? kAbsentRevision
    : crypto.createHash("sha256").update(stableJson(entry)).digest("hex").slice(0, 16);

// Every set carries the revision of the entry it was read from ("absent" to
// create), so a confirm code minted for one summary can only be redeemed
// against the entry that summary described, whatever the patch touches.
const revisionRequired = () => true;

const revisionRequiredError = (what) =>
  new McpServerError(`${what} must carry revision: the entry's revision from mcp.server-list${what === "Every set" ? ', or "absent" for a new server' : ""}`, {
    code: "revision_required",
    hint: "Read mcp.server-list and send its revision for this server.",
  });

const assertRevisionPresent = (patch) => {
  if (revisionRequired(patch) && patch.revision === undefined) throw revisionRequiredError("Every set");
};

const entryChangedError = (currentRevision) => {
  const error = new McpServerError(
    `The MCP server entry changed since it was read (current revision ${currentRevision}); re-read mcp.server-list and resubmit`,
    { status: 409, code: "entry_changed", hint: `Current revision: ${currentRevision}.` },
  );
  error.currentRevision = currentRevision;
  return error;
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
//
// The critical part is bounded so it always fits confirm-service.js's
// 400-character clamp after the op title: server name (validated, <= 64),
// url as scheme + host clipped from the LEFT to kSummaryHostMax (the
// registrable domain stays) + redacted path clipped to kSummaryPathMax,
// transport, filter verdicts, header counts, and SENDS: every distinct
// ${VAR} the resulting entry (url and all headers) sends. That list is
// bounded by refusing an entry with more than kMaxEntryEnvRefs distinct
// references or a rendered list longer than kMaxEntryEnvRefsChars
// (assertEntryEnvRefsBounded), so it is never clipped. Header counts are
// bounded by kMaxHeaders per call and per entry (too_many_headers).
// Measured worst case (64-char name, "rev " + 8 hex, a 41-char IPv6 host
// with port 65535, clipped path, "(was http)", 4 refs rendering to exactly
// the 80-character bound, 16 literal headers, transport streamable-http,
// FILTER WIDENED, GLOB IN FILTER, "headers +16 -16"): 398 of the 400
// characters including the op title (tests: "F2: the worst-case critical
// part ..."). "url unchanged <url>" is one character shorter than
// "url <url> (was http)", so naming the url on every summary does not raise
// it. Header counts are "headers +N -M" to make room for the revision.

const kSummaryNames = 3;
const kSummaryFragmentMax = 32;
const kSummaryHostMax = 40;
const kSummaryPathMax = 16;
const kSummaryDetailBudget = 320;
const kMaxEntryEnvRefs = 4;
const kMaxEntryEnvRefsChars = 80;

const quoteFragment = (raw) => {
  const text = String(raw ?? "");
  if (looksLikeCredential(text, { wholeString: false })) return kRedactedMarker;
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

// Slices that never split a %XX escape (summaryHost escapes every odd
// character, so each '%' in a shown label starts one).
const tailSafe = (text, n) => {
  let start = Math.max(0, text.length - n);
  while (start > 0 && start < text.length && (text[start - 1] === "%" || text[start - 2] === "%")) start += 1;
  return text.slice(start);
};
const headSafe = (text, n) => {
  let end = Math.min(text.length, n);
  if (end < text.length) {
    if (text[end - 1] === "%") end -= 1;
    else if (text[end - 2] === "%") end -= 2;
  }
  return text.slice(0, end);
};

// Keeps the RIGHTMOST labels (the registrable domain and the labels next to
// it): "~.regional-mirror.attacker-owned.example". A trusted-looking prefix
// is what gets cut, never the domain that receives the request. The
// registrable (second-level) label is always shown: cut inside from its
// left when long ("~xxxx.com", never "~.com"), and when the TLD itself is
// long, at least its last 8 characters stay next to the TLD's start
// ("~ownedxyz.verylongtld~").
const clipHostLeft = (host) => {
  const max = kSummaryHostMax;
  if (host.length <= max) return host;
  const labels = host.split(".");
  const tld = labels.pop();
  if (!labels.length) return `~${tailSafe(tld, max - 1)}`;
  const sld = labels.pop();
  const sldMin = Math.min(sld.length, 8);
  if (sldMin + tld.length + 2 > max) {
    return `~${tailSafe(sld, sldMin)}.${headSafe(tld, max - sldMin - 3)}~`;
  }
  if (sld.length + tld.length + 1 > max - (labels.length ? 2 : 0)) {
    return `~${tailSafe(sld, max - tld.length - 2)}.${tld}`;
  }
  let kept = `${sld}.${tld}`;
  while (labels.length && kept.length + labels[labels.length - 1].length + 3 <= max) {
    kept = `${labels.pop()}.${kept}`;
  }
  return labels.length ? `~.${kept}` : kept;
};

const summaryHost = (url) => {
  try {
    const parsed = new URL(url);
    // IPv6 literals keep their brackets (the URL parser has already
    // validated and compressed them to hex digits, ':' and '.').
    if (parsed.hostname.startsWith("[")) {
      const ipv6 = /^\[[0-9a-f:.]+\]$/i.test(parsed.hostname) ? parsed.hostname : "invalid";
      return parsed.port ? `${ipv6}:${parsed.port}` : ipv6;
    }
    // A character outside [A-Za-z0-9_-] is shown %-escaped, never dropped:
    // "trusted!.example" must not read as "trusted.example".
    const host = parsed.hostname
      .split(".")
      .map((label) =>
        looksLikeCredential(label)
          ? kRedactedMarker
          : label.replace(/[^A-Za-z0-9_-]/g, (ch) =>
              [...Buffer.from(ch)].map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`).join(""),
            ),
      )
      .join(".");
    const clipped = clipHostLeft(host);
    return parsed.port ? `${clipped}:${parsed.port}` : clipped;
  } catch {
    return "invalid";
  }
};

// scheme://host[:port]/redacted-path: the path and query come from
// redactUrl over the normalised href (credential-like segments and literal
// parameter values are <redacted>; ${VAR} names stay), reduced to a safe
// character set and clipped to kSummaryPathMax.
const summaryUrl = (url) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return "invalid";
  }
  const redacted = String(redactUrl(parsed.href));
  const slash = redacted.indexOf("/", redacted.indexOf("//") + 2);
  const rest = (slash < 0 ? "" : redacted.slice(slash))
    .replace(/%24/gi, "$")
    .replace(/%7B/gi, "{")
    .replace(/%7D/gi, "}")
    .replace(/[^A-Za-z0-9_.~:/?&=;%<>${}+-]/g, "");
  const shownRest = rest.length > kSummaryPathMax ? `${headSafe(rest, kSummaryPathMax)}~` : rest;
  return `${parsed.protocol}//${summaryHost(url)}${shownRest}`;
};

// Every distinct ${VAR} the entry makes OpenClaw send: the url (query or
// path) and every header value, in that order.
const entryEnvRefs = (entry) => {
  const refs = [];
  if (typeof entry?.url === "string") refs.push(...[...entry.url.matchAll(kEnvRefPattern)].map((m) => m[1]));
  if (isPlainObject(entry?.headers)) {
    for (const value of Object.values(entry.headers)) {
      if (typeof value === "string") refs.push(...[...value.matchAll(kEnvRefPattern)].map((m) => m[1]));
    }
  }
  return [...new Set(refs)];
};

const entryLiteralHeaderCount = (entry) =>
  isPlainObject(entry?.headers)
    ? Object.values(entry.headers).filter((value) => shapeEnvTemplate(value).literal).length
    : 0;

const renderRefList = (refs) => refs.map((ref) => `\${${ref}}`).join(", ");

const entryEnvRefsWithinBounds = (refs) =>
  refs.length <= kMaxEntryEnvRefs && renderRefList(refs).length <= kMaxEntryEnvRefsChars;

// The confirm summary names every reference the resulting entry sends, so an
// entry whose list would not fit the summary is refused.
const assertEntryEnvRefsBounded = (entry) => {
  const refs = entryEnvRefs(entry);
  if (entryEnvRefsWithinBounds(refs)) return;
  throw new McpServerError(
    `The resulting MCP server entry would reference ${refs.length} distinct \${VAR} names (url and headers); at most ${kMaxEntryEnvRefs}, ${kMaxEntryEnvRefsChars} characters as \${A}, \${B}, so the confirm prompt can name every one`,
    { code: "too_many_env_refs", hint: "Reuse one variable across headers, or remove headers you no longer need." },
  );
};

// Everything setServer refuses after the merge (resulting-entry bounds),
// shared with the tier resolver so such a call resolves to write tier and
// no confirm code is spent on a call the route answers with 400.
const assertServerSetBounded = (nextEntry, patch) => {
  if (!hasOwn(patch, "url") && !hasOwn(patch, "headers")) return;
  if (isPlainObject(nextEntry?.headers) && Object.keys(nextEntry.headers).length > kMaxHeaders) {
    throw tooManyHeadersError();
  }
  assertEntryEnvRefsBounded(nextEntry);
};

// One line. Critical part (always shown, bounded): name, NEW/UPDATE, rev,
// the resulting entry's url (scheme, host, redacted path; "unchanged" when
// the patch does not change it), SENDS (every ${VAR} the resulting entry
// sends, plus literal headers by count; on every summary), transport, filter verdict (CLEARED /
// WIDENED / narrowed), GLOB, header change counts (+set -removed). Detail tail: header
// names with their VAR names and the include/exclude delta, cut at the
// budget.
const describeServerSet = ({ name, current, patch }) => {
  const isNew = !isPlainObject(current);
  // The revision the code binds to: its first 8 characters when it matches
  // the entry this summary was built from; STALE / MISSING when the route
  // will refuse the call (409 entry_changed / 400 revision_required).
  let rev = "";
  if (patch.revision !== undefined) {
    rev = patch.revision === entryRevision(isNew ? undefined : current) ? ` rev ${patch.revision.slice(0, 8)}` : " rev STALE";
  } else if (revisionRequired(patch)) {
    rev = " rev MISSING";
  }
  const critical = [`server "${String(name).replace(/[^A-Za-z0-9_-]/g, "")}" ${isNew ? "NEW" : "UPDATE"}${rev}`];
  const detail = [];
  const nextEntry = applyServerPatch(current, patch);
  // Every summary names where the resulting entry connects and what it
  // sends, whatever the patch touches.
  if (typeof nextEntry.url !== "string") {
    critical.push("url none");
  } else if (!hasOwn(patch, "url") || (!isNew && stableJson(current.url) === stableJson(patch.url))) {
    critical.push(`url unchanged ${summaryUrl(nextEntry.url)}`);
  } else {
    let was = "";
    try {
      const before = new URL(current?.url).protocol;
      if (before !== new URL(patch.url).protocol) was = ` (was ${before.replace(":", "")})`;
    } catch {
      // no previous url, or not parseable: nothing to compare
    }
    critical.push(`url ${summaryUrl(patch.url)}${was}`);
  }
  const refs = entryEnvRefs(nextEntry);
  const literal = entryLiteralHeaderCount(nextEntry);
  let sends;
  if (!entryEnvRefsWithinBounds(refs)) {
    sends = `${refs.length} \${VAR} refs, OVER LIMIT (refused)`;
  } else {
    const parts = refs.length ? [renderRefList(refs)] : [];
    if (literal) parts.push(`${literal} literal header${literal > 1 ? "s" : ""}`);
    sends = parts.length ? parts.join(", ") : "no credential";
  }
  critical.push(`SENDS ${sends}`);
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
      critical.push(`headers +${set.length} -${removed.length}`);
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

// References a patch itself sets (url and header values).
const patchEnvRefs = (patch) => entryEnvRefs({ url: patch.url, headers: isPlainObject(patch.headers) ? patch.headers : undefined });

// A parseable config whose `mcp` or `mcp.servers` is not an object is
// refused rather than read as empty: a write would otherwise replace it.
const unexpectedShapeError = (what) =>
  new McpServerError(`openclaw.json ${what} is not an object; fix the file before editing MCP servers`, {
    status: 409,
    code: "OPENCLAW_CONFIG_UNEXPECTED_SHAPE",
  });

const readServers = (cfg) => {
  if (cfg?.mcp === undefined) return {};
  if (!isPlainObject(cfg.mcp)) throw unexpectedShapeError("mcp");
  const servers = cfg.mcp.servers;
  if (servers === undefined) return {};
  if (!isPlainObject(servers)) throw unexpectedShapeError("mcp.servers");
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
      servers: Object.fromEntries(
        names.map((name) => [name, { ...redactMcpServerEntry(servers[name]), revision: entryRevision(servers[name]) }]),
      ),
    };
  };

  const setServer = (rawName, body) => {
    const name = normalizeServerName(rawName);
    if (isReservedServerName(name, env)) throw reservedNameError(name);
    const patch = parseServerPatch(body, { classifyEnv, env });
    assertRevisionPresent(patch);
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
        // Checked under the lock, against the entry as read here. A stale
        // revision whose patch changes nothing (a retry of a call that
        // already landed) is a no-op, not a conflict.
        if (patch.revision !== undefined && patch.revision !== entryRevision(current) && changed) {
          throw entryChangedError(entryRevision(current));
        }
        assertServerSetBounded(nextEntry, patch);
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
    // there until a restart. Every reference the stored entry carries counts,
    // whether or not this call changed anything: an idempotent retry of a
    // call whose variable the gateway still lacks must say so again.
    // Names only.
    // With no launch snapshot (AlphaClaw restarted under a running gateway)
    // nothing is known about the daemon env: only a call that changed
    // something carrying references asks for a restart, and the response
    // says the env is unknown.
    const launched = getLaunchedEnvKeys();
    const missing = launched
      ? entryEnvRefs(nextEntry).filter((ref) => !launched.has(ref))
      : changed
        ? patchEnvRefs(patch)
        : [];
    const result = {
      name,
      created,
      changed,
      restartRequired: missing.length > 0,
      revision: entryRevision(nextEntry),
      server: redactMcpServerEntry(nextEntry),
    };
    if (!launched) result.launchEnvUnknown = true;
    if (missing.length > 0) {
      result.warning = launched
        ? `The running gateway was started before ${missing.map((ref) => `\${${ref}}`).join(", ")} was set; restart the gateway so OpenClaw can resolve it.`
        : `The running gateway's environment is unknown to this AlphaClaw process; restart the gateway to be sure ${missing.map((ref) => `\${${ref}}`).join(", ")} resolves.`;
    }
    return result;
  };

  const removeServer = (rawName, { revision } = {}) => {
    const name = normalizeServerName(rawName);
    if (isReservedServerName(name, env)) throw reservedNameError(name);
    if (revision === undefined) throw revisionRequiredError("Every remove");
    if (typeof revision !== "string" || !/^[0-9a-f]{16}$/.test(revision)) {
      throw new McpServerError("revision must be the 16-hex-character revision from mcp.server-list", {
        code: "invalid_revision",
      });
    }
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
        if (revision !== entryRevision(servers[name])) {
          throw entryChangedError(entryRevision(servers[name]));
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
  entryEnvRefs,
  entryRevision,
  kAbsentRevision,
  revisionRequired,
  assertRevisionPresent,
  looksLikeCredentialKey,
  assertServerSetBounded,
  kMaxHeaders,
  kMaxEntryEnvRefs,
  kMaxEntryEnvRefsChars,
  readServers,
  createMcpServersService,
};
