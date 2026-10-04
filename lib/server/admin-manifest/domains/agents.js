module.exports = {
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
      title: "Update an agent (name, identity, model, per-model runtime, tools, thinking default)",
      method: "PUT",
      path: "/api/agents/:id",
      tier: "write",
      // Moving an agent's model onto a runtime other than the embedded
      // `openclaw` loop (claude-cli, codex, copilot, auto) can hand it native
      // shell/file tools: dangerous, confirm code. Removing a per-agent entry
      // or its runtime (models: null, an entry null, agentRuntime null) falls
      // back to agents.defaults, which may be such a runtime, and the resolver
      // cannot see the current config: also dangerous. Field patches without
      // agentRuntime keep the existing runtime and stay write.
      tierResolver: (req) => {
        const body = req?.body || {};
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
            description: "{profile, alsoAllow[], deny[]}; null or non-object clears the tools config.",
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
