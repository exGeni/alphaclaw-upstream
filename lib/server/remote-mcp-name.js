// The mcp.servers key AlphaClaw manages for REMOTE_MCP_URL (README
// "REMOTE_MCP_URL"). One resolver shared by the gateway's managed-entry
// writer (gateway.js ensureGatewayProxyConfig) and the agent-admin MCP ops,
// which treat the resolved name as reserved even while REMOTE_MCP_* is unset.
//
// Constrain the managed key. OpenClaw sanitizes names later for tool
// prefixes, but the config key itself must be safe to use as an object key
// and to read back in `openclaw mcp` CLI commands. Names with
// prototype-pollution shapes, spaces, or path-like names fall back to
// "remote" so a typo doesn't silently misroute.
const kRemoteMcpNamePattern = /^[A-Za-z0-9_-]{1,64}$/;
const kReservedRemoteMcpNames = new Set(["__proto__", "constructor", "prototype"]);
const kDefaultRemoteMcpName = "remote";

// `env` defaults to the live process environment (tests pass a fixture).
const resolveRemoteMcpName = (env) => {
  const raw = String((env ? env.REMOTE_MCP_NAME : process.env.REMOTE_MCP_NAME) || "").trim();
  if (!raw) return { name: kDefaultRemoteMcpName, invalidRaw: null };
  if (kRemoteMcpNamePattern.test(raw) && !kReservedRemoteMcpNames.has(raw)) {
    return { name: raw, invalidRaw: null };
  }
  return { name: kDefaultRemoteMcpName, invalidRaw: raw };
};

module.exports = {
  kRemoteMcpNamePattern,
  kDefaultRemoteMcpName,
  resolveRemoteMcpName,
};
