const { OPENCLAW_DIR } = require("../../constants");
const openclawConfig = require("../../openclaw-config");
const {
  normalizeServerName,
  parseServerPatch,
  classifyServerSet,
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

const kNameField = {
  name: "name",
  location: "path",
  type: "string",
  required: true,
  description:
    "Server key under mcp.servers: 1-64 letters, digits, '-' or '_'. Unknown names return 404 (except a set that carries url, which creates the server).",
};

module.exports = {
  createServerSetTier,
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
        "Header and env values show only ${VAR} reference names and fixed scheme text; anything else is `<literal>` and the header is listed in `literalHeaders`. url query values and userinfo are `<redacted>`; args are a count; keys the projection does not know are listed by name in `otherKeys`. `managed: true` marks the REMOTE_MCP_* entry AlphaClaw rewrites at every gateway start.",
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
              "http(s) URL of the MCP endpoint. Required to create a server; cannot be null. Userinfo, or a credential-like query parameter with a literal value, is refused (400). A change is dangerous-tier.",
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
              "Patched header by header (names case-insensitive): a value sets it, null removes it, omitted headers are kept; headers: null removes them all. Every value must be ${VAR} env references around at most two words of fixed scheme text (e.g. \"Bearer ${GBRAIN_X_TOKEN}\"); a literal value is refused with 400 code literal_secret and is never echoed. Any change is dangerous-tier.",
          },
          {
            name: "toolFilter",
            location: "body",
            type: "object|null",
            required: false,
            description:
              "{include, exclude}: non-empty arrays of MCP tool names or simple * globs, patched field by field (omitted keeps, null removes); toolFilter: null clears the filter; unknown keys 400. A smaller include or a larger exclude is write-tier; a widened or cleared filter is dangerous-tier.",
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
      hint: "Header values: ${VAR} refs only; literals 400",
      notes:
        "Keys this op does not manage (codex, enabled, auth, oauth, connectionTimeoutMs, ...) are preserved; unknown body keys return 400. Put a secret in an env var first (env.update), then reference it as ${VAR}. Returns the redacted entry; 201 when the server was created. OpenClaw hot-applies mcp changes; no restart. The REMOTE_MCP_* managed entry answers 409 managed_by_env.",
    },
    {
      id: "mcp.server-remove",
      title: "Remove an MCP server",
      method: "DELETE",
      path: "/api/mcp/servers/:name",
      tier: "dangerous",
      idempotent: false,
      readOp: "mcp.server-list",
      params: {
        fields: [{ ...kNameField, description: "Server to remove; unknown names return 404." }],
        example: "DELETE /api/mcp/servers/legacy-docs",
      },
      notes: "The REMOTE_MCP_* managed entry answers 409 managed_by_env.",
    },
  ],
};
