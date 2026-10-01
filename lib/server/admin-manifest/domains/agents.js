const { OPENCLAW_DIR } = require("../../constants");
const openclawConfig = require("../../openclaw-config");
const {
  applyAgentToolsPatch,
  isToolsNarrowing,
} = require("../../agents/agent-tools-policy");

const kDefaultReadConfig = () =>
  openclawConfig.readOpenclawConfig({ openclawDir: OPENCLAW_DIR, fallback: null });

// The enforcement middleware is mounted at /api, so Express trims the mount
// from req.path ("/agents/<id>"); rebuild the full path from baseUrl + path
// (the manifest's own A19 convention).
const readAgentIdFromRequest = (req) => {
  const joined = `${req?.baseUrl || ""}${req?.path || ""}`;
  const fullPath = joined || String(req?.originalUrl || req?.url || "").split("?")[0];
  const match = fullPath.match(/^\/api\/agents\/([^/]+)\/?$/);
  if (!match) throw new Error("agent id not in path");
  return decodeURIComponent(match[1]).trim();
};

// Effective skill set of an agent today: its own list, else
// agents.defaults.skills, else null (unrestricted). Read from disk because
// the resolver runs before routing and must compare against current state.
const readEffectiveSkills = (cfg, agentId) => {
  if (!cfg) throw new Error("config unreadable");
  const list = Array.isArray(cfg.agents?.list) ? cfg.agents.list : [];
  const agent = list.find((entry) => String(entry?.id || "").trim() === agentId);
  // OpenClaw applies an agent's own `skills` whenever the key is present
  // (Object.hasOwn); a non-array own value is invalid config: fail closed.
  if (agent && Object.prototype.hasOwnProperty.call(agent, "skills")) {
    if (!Array.isArray(agent.skills)) throw new Error("agent skills is not a list");
    return agent.skills.map((s) => String(s).trim());
  }
  if (Array.isArray(cfg.agents?.defaults?.skills)) {
    return cfg.agents.defaults.skills.map((s) => String(s).trim());
  }
  return null;
};

// Skills tier: narrowing an agent's visible skills is a plain write;
// widening it (a name outside the current effective set) or removing the
// agent's own list (falls back to defaults, possibly unrestricted) is
// dangerous. Unknown state fails closed (resolveTier maps a throw to
// dangerous).
const createSkillsTier =
  ({ readConfig = kDefaultReadConfig } = {}) =>
  (req) => {
    const body = req?.body || {};
    if (!Object.prototype.hasOwnProperty.call(body, "skills")) return "write";
    if (body.skills === null) return "dangerous";
    if (!Array.isArray(body.skills)) return "write"; // the route rejects it (400)
    const current = readEffectiveSkills(readConfig(), readAgentIdFromRequest(req));
    if (current === null) return "write"; // unrestricted today: any list narrows
    const allowed = new Set(current);
    return body.skills.every((name) => allowed.has(String(name).trim())) ? "write" : "dangerous";
  };
const skillsTier = createSkillsTier();

// Tools tier, mirroring the skills tier: a patch that only narrows what the
// agent can call (more deny entries, a smaller alsoAllow, a strict allow list
// inside the current one, a profile inside the current effective profile,
// turning fs.workspaceOnly on) is a plain write; anything else, including
// tools: null, is dangerous. The next state is computed with the same
// function the service writes with, against the config on disk; an
// unreadable config or unknown agent state fails closed (resolveTier maps a
// throw to dangerous).
const createToolsTier =
  ({ readConfig = kDefaultReadConfig } = {}) =>
  (req) => {
    const body = req?.body || {};
    if (!Object.prototype.hasOwnProperty.call(body, "tools")) return "write";
    if (body.tools === null) return "dangerous";
    let nextTools;
    try {
      nextTools = applyAgentToolsPatch(undefined, body.tools);
    } catch {
      return "write"; // invalid patch: the route rejects it (400), nothing is written
    }
    const cfg = readConfig();
    if (!cfg) throw new Error("config unreadable");
    const agentId = readAgentIdFromRequest(req);
    const hasRoster = Array.isArray(cfg.agents?.list);
    const list = hasRoster ? cfg.agents.list : [];
    const agent = list.find((entry) => String(entry?.id || "").trim() === agentId);
    const ownTools = agent ? agent.tools : undefined;
    const isObjectOrAbsent = (value) =>
      value === undefined || value === null || (typeof value === "object" && !Array.isArray(value));
    if (!isObjectOrAbsent(ownTools)) throw new Error("agent tools is not an object");
    // OpenClaw applies agents.defaults.tools to the implicit agent only when
    // the config has no roster at all; the write then creates a roster, so
    // the defaults stop applying: compare against what applied before.
    const effectiveCurrent = agent || hasRoster ? ownTools : cfg.agents?.defaults?.tools;
    if (!isObjectOrAbsent(effectiveCurrent)) throw new Error("agent tools is not an object");
    nextTools = applyAgentToolsPatch(ownTools, body.tools);
    return isToolsNarrowing({ currentTools: effectiveCurrent, nextTools, globalTools: cfg.tools })
      ? "write"
      : "dangerous";
  };
const toolsTier = createToolsTier();

module.exports = {
  createSkillsTier,
  createToolsTier,
  domain: "agents",
  title: "Agents",
  ops: [
    {
      id: "agents.list",
      title: "List agents and agent defaults",
      method: "GET",
      path: "/api/agents",
      tier: "safe",
    },
    {
      id: "agents.detail",
      title: "Read one agent",
      method: "GET",
      path: "/api/agents/:id",
      tier: "safe",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id; unknown ids return 404.",
          },
        ],
        example: "GET /api/agents/main",
      },
    },
    {
      id: "agents.workspace-size",
      title: "Read an agent's workspace path and size on disk",
      method: "GET",
      path: "/api/agents/:id/workspace-size",
      tier: "safe",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id; unknown ids return 404.",
          },
        ],
        example: "GET /api/agents/main/workspace-size",
      },
    },
    {
      id: "agents.bindings-list",
      title: "List channel bindings for an agent",
      method: "GET",
      path: "/api/agents/:id/bindings",
      tier: "safe",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id; unknown ids return 404.",
          },
        ],
        example: "GET /api/agents/main/bindings",
      },
    },
    {
      id: "agents.create",
      title: "Create an agent (scaffolds its workspace)",
      method: "POST",
      path: "/api/agents",
      tier: "write",
      idempotent: false,
      readOp: "agents.list",
      params: {
        fields: [
          {
            name: "id",
            location: "body",
            type: "string",
            required: true,
            description:
              "Lowercase letters, numbers, hyphens only; rejected otherwise. Existing ids return 409.",
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: false,
            description: "Display name; defaults to a name derived from the id.",
          },
          {
            name: "workspaceFolder",
            location: "body",
            type: "string",
            required: false,
            description: "Workspace folder to scaffold; defaults to a per-agent folder.",
          },
          {
            name: "model",
            location: "body",
            type: "string",
            required: false,
            description: "Per-agent model override; omit to inherit the global default.",
          },
          {
            name: "identity",
            location: "body",
            type: "object",
            required: false,
            description: "Identity fields (persona etc.); `name` here loses to top-level name.",
          },
        ],
        example: '{"id":"support-bot","name":"Support Bot"}',
      },
    },
    {
      id: "agents.update",
      title: "Update an agent (name, identity, model, per-model runtime, tools, skills, thinking default)",
      method: "PUT",
      path: "/api/agents/:id",
      tier: "write",
      // Moving an agent's model onto a runtime other than the embedded
      // `openclaw` loop (claude-cli, codex, copilot, auto) can hand it native
      // shell/file tools: dangerous, confirm code. Removing a per-agent entry
      // or its runtime (models: null, an entry null, agentRuntime null) falls
      // back to agents.defaults, which may be such a runtime, so it is also
      // dangerous (conservatively, without reading the defaults). Field
      // patches without agentRuntime keep the existing runtime and stay write.
      tierResolver: (req) => {
        const body = req?.body || {};
        if (skillsTier(req) === "dangerous") return "dangerous";
        if (toolsTier(req) === "dangerous") return "dangerous";
        if (!Object.prototype.hasOwnProperty.call(body, "models")) return "write";
        const models = body.models;
        if (models === null) return "dangerous";
        if (typeof models !== "object" || Array.isArray(models)) return "write";
        const widens = Object.values(models).some((entry) => {
          if (entry === null) return true;
          if (!entry || typeof entry !== "object") return false;
          if (!Object.prototype.hasOwnProperty.call(entry, "agentRuntime")) return false;
          return String(entry.agentRuntime?.id ?? "").trim() !== "openclaw";
        });
        return widens ? "dangerous" : "write";
      },
      idempotent: true,
      readOp: "agents.detail",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id; unknown ids return 404.",
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: false,
            description: "New display name.",
          },
          {
            name: "identity",
            location: "body",
            type: "object",
            required: false,
            description: "REPLACES the whole identity object when provided — send every field you want kept.",
          },
          {
            name: "model",
            location: "body",
            type: "string|null",
            required: false,
            description: "Per-agent model override; null clears it (inherit global default).",
          },
          {
            name: "tools",
            location: "body",
            type: "object|null",
            required: false,
            description:
              "Per-agent tool policy (OpenClaw agents.entries.<id>.tools): {profile (minimal|coding|messaging|full), allow[] (strict allowlist, non-empty; cannot be combined with alsoAllow), alsoAllow[], deny[], fs {workspaceOnly: true|false|null}}. profile/alsoAllow/deny are replaced together (an omitted one is removed); allow is kept when omitted unless the patch sets alsoAllow, and allow: null removes it; fs is patched field by field (omitted keeps it, null removes it); other per-agent tools keys (elevated, exec, byProvider, ...) are kept. null removes the whole tools config; unknown keys are rejected (400). Narrowing (more deny entries, a smaller alsoAllow, an allow list inside the current one, or a new allow list naming only core tools/groups, a profile inside the current effective profile, workspaceOnly on) is write-tier; anything else, including null, is dangerous-tier.",
          },
          {
            name: "models",
            location: "body",
            type: "object|null",
            required: false,
            description:
              "Per-model settings keyed by provider/model (e.g. {\"anthropic/claude-sonnet-5-5\":{\"agentRuntime\":{\"id\":\"openclaw\"}}}). Each entry patches that model's settings field by field: agentRuntime {id: openclaw|claude-cli|codex|copilot|auto}, params (object) and codeMode (boolean); a field set to null is removed, omitted fields are kept. An entry set to null removes the model's settings; models: null clears them all. A non-openclaw runtime, or any removal (which may fall back to a non-openclaw default), is dangerous-tier.",
          },
          {
            name: "skills",
            location: "body",
            type: "array<string>|null",
            required: false,
            description:
              "Per-agent skill allowlist (OpenClaw agents.entries.<id>.skills): the agent's configured skill allowlist, replacing agents.defaults.skills (per-session skill toggles and exec access are separate; this is not a shell authorization boundary); [] exposes no skills; null removes the list so the agent inherits the defaults. Narrowing is write-tier; adding a skill outside the agent's current effective set, or null, is dangerous-tier.",
          },
          {
            name: "thinkingDefault",
            location: "body",
            type: "string|null",
            required: false,
            description: "Default thinking level; invalid values are rejected (400), null clears it.",
          },
        ],
        example: '{"name":"Support Bot","model":null}',
      },
      notes: "Omitted fields are left untouched, but `identity` is replace-not-merge.",
    },
    {
      id: "agents.binding-add",
      title: "Bind a channel/peer to an agent",
      method: "POST",
      path: "/api/agents/:id/bindings",
      tier: "write",
      idempotent: false,
      readOp: "agents.bindings-list",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id; unknown ids return 404.",
          },
          {
            name: "channel",
            location: "body",
            type: "string",
            required: true,
            description: "Channel provider to match (e.g. telegram). Required; empty is rejected.",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description: 'Channel account to match; omitted means "default".',
          },
          {
            name: "guildId",
            location: "body",
            type: "string",
            required: false,
            description: "Discord guild to match.",
          },
          {
            name: "teamId",
            location: "body",
            type: "string",
            required: false,
            description: "Slack team to match.",
          },
          {
            name: "peer",
            location: "body",
            type: "object",
            required: false,
            description: "Peer match (chat/user scope); narrows the binding to one conversation.",
          },
          {
            name: "parentPeer",
            location: "body",
            type: "object",
            required: false,
            description: "Parent-peer match (e.g. forum parent) for thread-scoped bindings.",
          },
          {
            name: "roles",
            location: "body",
            type: "array<string>",
            required: false,
            description: "Role names to match.",
          },
        ],
        example: '{"channel":"telegram","accountId":"default"}',
      },
      notes: "A binding already assigned to another agent returns 409.",
    },
    {
      id: "agents.binding-remove",
      title: "Remove a channel binding from an agent",
      method: "DELETE",
      path: "/api/agents/:id/bindings",
      tier: "write",
      idempotent: false,
      readOp: "agents.bindings-list",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent id.",
          },
          {
            name: "channel",
            location: "body",
            type: "string",
            required: true,
            description: "Channel of the binding to remove; the body must match an existing binding exactly (else 404).",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description: "Account of the binding to remove; omitted matches \"default\".",
          },
          {
            name: "guildId",
            location: "body",
            type: "string",
            required: false,
            description: "Guild of the binding to remove, if the binding has one.",
          },
          {
            name: "teamId",
            location: "body",
            type: "string",
            required: false,
            description: "Team of the binding to remove, if the binding has one.",
          },
          {
            name: "peer",
            location: "body",
            type: "object",
            required: false,
            description: "Peer match of the binding to remove, if the binding has one.",
          },
          {
            name: "parentPeer",
            location: "body",
            type: "object",
            required: false,
            description: "Parent-peer match of the binding to remove, if the binding has one.",
          },
          {
            name: "roles",
            location: "body",
            type: "array<string>",
            required: false,
            description: "Roles of the binding to remove, if the binding has them.",
          },
        ],
        example: '{"channel":"telegram","accountId":"default"}',
      },
    },
    {
      id: "agents.delete",
      title: "Delete an agent",
      method: "DELETE",
      path: "/api/agents/:id",
      tier: "dangerous",
      idempotent: false,
      readOp: "agents.list",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent to delete. The default/main agent cannot be deleted (400).",
          },
          {
            name: "keepWorkspace",
            location: "query",
            type: "boolean",
            required: false,
            description:
              "Defaults to true. \"0|false|no|off\" also erases the agent's workspace directory from disk.",
          },
        ],
        example: "DELETE /api/agents/support-bot?keepWorkspace=true",
      },
      hint: "Destroys the agent and every channel binding assigned to it; keepWorkspace=false erases its workspace too.",
    },
    {
      id: "agents.set-default",
      title: "Set the default agent",
      method: "POST",
      path: "/api/agents/:id/default",
      tier: "write",
      idempotent: true,
      readOp: "agents.list",
      params: {
        fields: [
          {
            name: "id",
            location: "path",
            type: "string",
            required: true,
            description: "Agent to promote; unknown ids return 404. Clears the flag on every other agent.",
          },
        ],
        example: "POST /api/agents/support-bot/default",
      },
    },
  ],
};
