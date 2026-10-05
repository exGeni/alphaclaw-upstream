const { sendIfConfigUnreadable } = require("../utils/config-unreadable");
const { McpServerError } = require("../mcp-servers");

// OpenClaw `mcp.servers.<name>` definitions (agent-admin domain "mcp").
// Every response carries redacted entries only (lib/server/mcp-servers.js);
// error messages name fields and header names, never a submitted value.
// OpenClaw hot-applies `mcp` changes (docs/gateway/configuration/hot-reload.md,
// "Tools & media" row), but resolves ${VAR} from the running gateway's env:
// set reports restartRequired (with a warning) when a referenced var is not
// in the env the current gateway daemon was spawned with.
const sendError = (res, error) => {
  if (sendIfConfigUnreadable(res, error)) return;
  if (error instanceof McpServerError) {
    return res.status(error.status).json({
      ok: false,
      error: error.message,
      code: error.code,
      ...(error.hint ? { hint: error.hint } : {}),
    });
  }
  console.error(`[alphaclaw] MCP server route error: ${error?.message || error}`);
  return res.status(500).json({ ok: false, error: "MCP server operation failed", code: "internal_error" });
};

const registerMcpServerRoutes = ({ app, mcpServersService }) => {
  app.get("/api/mcp/servers", (_req, res) => {
    try {
      return res.json({ ok: true, ...mcpServersService.listServers() });
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.put("/api/mcp/servers/:name", (req, res) => {
    try {
      // Only a JSON object body is a patch: a text/plain or form body leaves
      // req.body as the parser's empty default, which must not read as "{}".
      if (!req.is("application/json")) {
        throw new McpServerError("Body must be a JSON object (Content-Type: application/json)", {
          code: "invalid_body",
        });
      }
      const result = mcpServersService.setServer(req.params.name, req.body);
      return res.status(result.created ? 201 : 200).json({ ok: true, ...result });
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.delete("/api/mcp/servers/:name", (req, res) => {
    try {
      const result = mcpServersService.removeServer(req.params.name);
      return res.json({ ok: true, removed: result.name });
    } catch (error) {
      return sendError(res, error);
    }
  });
};

module.exports = { registerMcpServerRoutes };
