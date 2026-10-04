const { OPENCLAW_DIR } = require("../../constants");
const openclawConfig = require("../../openclaw-config");
const {
  normalizeServerName,
  isReservedServerName,
  parseServerPatch,
  classifyServerSet,
  describeServerSet,
  readServers,
  kManagedMarker,
} = require("../../mcp-servers");

const kDefaultReadConfig = () =>
  openclawConfig.readOpenclawConfig({ openclawDir: OPENCLAW_DIR, fallback: null });

// The enforcement middleware is mounted at /api: rebuild the full path from
// baseUrl + path (the manifest's A19 convention, as in domains/agents.js).
const readServerNameFromRequest = (req) => {
  const joined = `${req?.baseUrl || ""}${req?.path || ""}`;
  const fullPath = joined || String(req?.originalUrl || req?.url || "").split("?")[0];
  const match = fullPath.match(/^\/api\/mcp\/servers\/([^/]+)\/?$/);
  if (!match) throw new Error("server name not in path");
  return decodeURIComponent(match[1]);
};

// mcp.server-set tier. Computed from the config on disk with the same patch
// function the route writes with. A body or name the route rejects (400) is
// "write": nothing is written. Unreadable config or a non-object entry
// throws, which resolveTier maps to dangerous (fail closed).
const createServerSetTier =
  ({ readConfig = kDefaultReadConfig } = {}) =>
  (req) => {
    let name;
    let patch;
    try {
      name = normalizeServerName(readServerNameFromRequest(req));
      patch = parseServerPatch(req?.body);
    } catch {
      return "write"; // the route rejects it (400), nothing is written
    }
    if (isReservedServerName(name)) return "write"; // the route refuses it (409)
    const cfg = readConfig();
    if (!cfg) throw new Error("config unreadable");
    const servers = readServers(cfg);
    const current = Object.prototype.hasOwnProperty.call(servers, name) ? servers[name] : undefined;
    if (current === undefined) {
      // No url: the route answers 404. With url: a new server.
      return Object.prototype.hasOwnProperty.call(patch, "url") ? "dangerous" : "write";
    }
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      throw new Error("mcp server entry is not an object");
    }
    if (current[kManagedMarker] === true) return "write"; // the route refuses it (409)
    return classifyServerSet({ current, patch });
  };
const serverSetTier = createServerSetTier();

// Confirm-summary detail (confirm-service.js buildConfirmSummary): what the
// approving admin is asked to allow. Falls back to the op title on any
// failure, including a body the route would reject.
const createServerSetConfirmSummary =
  ({ readConfig = kDefaultReadConfig } = {}) =>
  ({ pathParams, body }) => {
    const name = normalizeServerName(pathParams?.name);
    const patch = parseServerPatch(body);
    const servers = readServers(readConfig() || {});
    const current = Object.prototype.hasOwnProperty.call(servers, name) ? servers[name] : undefined;
    return describeServerSet({ name, current, patch });
  };
const serverSetConfirmSummary = createServerSetConfirmSummary();

const kNameField = {
  name: "name",
  location: "path",
  type: "string",
  required: true,
  description:
    "Server key under mcp.servers: 1-64 letters, digits, '-' or '_'. Unknown names return 404 (except a set that carries url, which creates the server). The REMOTE_MCP_NAME key (default remote) is reserved (409).",
};

module.exports = {
  createServerSetTier,
  createServerSetConfirmSummary,
  domain: "mcp",
  title: "MCP Servers",
  ops: [
    {
      id: "mcp.server-list",
      title: "List MCP servers (header values redacted)",
      method: "GET",
      path: "/api/mcp/servers",
      tier: "safe",
      notes:
        "Header and env values show only ${VAR} reference names and an allowlisted scheme word; anything else is `<literal>` and the header is listed in `literalHeaders`. url userinfo, query and ;matrix values and credential-like path segments are `<redacted>`; command is {program, argCount}; keys the projection does not know are listed by name in `otherKeys`. `managed: true` marks the REMOTE_MCP_* entry AlphaClaw rewrites at every gateway start.",
    },
    {
      id: "mcp.server-set",
      title: "Create or update an MCP server",
      method: "PUT",
      path: "/api/mcp/servers/:name",
      tier: "write",
      // Narrowing an existing server (smaller include, larger exclude, timeout
      // only) is write; a new server, a url/header/transport change, or a
      // widened or cleared filter is dangerous (confirm code).
      tierResolver: (req) => serverSetTier(req),
      confirmSummary: (params) => serverSetConfirmSummary(params),
      idempotent: true,
      readOp: "mcp.server-list",
      params: {
        fields: [
          kNameField,
          {
            name: "url",
            location: "body",
            type: "string",
            required: false,
            description:
              "http(s) URL of the MCP endpoint. Required to create a server; cannot be null. Userinfo, a #fragment, a credential-like host label or path segment, or a query or ;matrix parameter with a literal value and a sensitive key (whole key or delimited part) or a credential-like value is refused (400). A change is dangerous-tier.",
          },
          {
            name: "transport",
            location: "body",
            type: "string|null",
            required: false,
            description: "\"streamable-http\" or \"sse\"; null removes it. A change is dangerous-tier.",
          },
          {
            name: "headers",
            location: "body",
            type: "object|null",
            required: false,
            description:
              "Patched header by header (names case-insensitive): a value sets it, null removes it, omitted headers are kept; headers: null removes them all. Every value is exactly one ${VAR}, optionally after one scheme word (Bearer, Basic, Token, Bot, ApiKey) and a space, e.g. \"Bearer ${GBRAIN_X_AUTH_TOKEN}\"; anything else is 400 literal_secret and is never echoed. VAR must reach the gateway (name it *_AUTH_TOKEN or list it in ALPHACLAW_GATEWAY_ENV_PASSTHROUGH; else 400 env_not_forwarded) and must not be an OPENCLAW_*/ALPHACLAW_* or gateway/webhook/remote-MCP token (400 env_reserved), and must be set and non-empty (else 400 env_not_set). Any change is dangerous-tier.",
          },
          {
            name: "toolFilter",
            location: "body",
            type: "object|null",
            required: false,
            description:
              "{include, exclude}: non-empty arrays of MCP tool names or simple * globs, patched field by field (omitted keeps, null removes); toolFilter: null clears the filter; unknown keys 400. A smaller include or a larger exclude of exact names is write-tier; a widened or cleared filter, or any * glob, is dangerous-tier.",
          },
          {
            name: "requestTimeoutMs",
            location: "body",
            type: "number|null",
            required: false,
            description: "Per-server MCP request timeout in milliseconds (positive); null removes it.",
          },
        ],
        example: '{"toolFilter":{"include":["search","get_page"]}}',
      },
      hint: "Headers: \"Bearer ${X_AUTH_TOKEN}\" form only",
      notes:
        "Keys this op does not manage (codex, enabled, auth, oauth, connectionTimeoutMs, ...) are preserved; unknown body keys return 400. Put a secret in an env var named *_AUTH_TOKEN first (env.update), then reference it as ${VAR}. A body that changes nothing is not written (changed: false). Returns the redacted entry; 201 when the server was created. OpenClaw hot-applies mcp changes; restartRequired: true (with a warning) means a referenced var is not in the running gateway's env yet. The REMOTE_MCP_NAME key (default remote) answers 409 managed_by_env, even while REMOTE_MCP_* is unset.",
    },
    {
      id: "mcp.server-remove",
      title: "Remove an MCP server",
      method: "DELETE",
      path: "/api/mcp/servers/:name",
      tier: "dangerous",
      confirmSummary: ({ pathParams }) => `server "${normalizeServerName(pathParams?.name)}"`,
      idempotent: false,
      readOp: "mcp.server-list",
      params: {
        fields: [{ ...kNameField, description: "Server to remove; unknown names return 404." }],
        example: "DELETE /api/mcp/servers/legacy-docs",
      },
      notes: "The REMOTE_MCP_NAME key (default remote) answers 409 managed_by_env.",
    },
  ],
};
