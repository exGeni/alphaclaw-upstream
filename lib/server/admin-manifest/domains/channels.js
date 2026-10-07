module.exports = {
  domain: "channels",
  title: "Channel Accounts",
  ops: [
    {
      id: "channels.accounts-list",
      title: "List configured channel accounts (tokens masked)",
      method: "GET",
      path: "/api/channels/accounts",
      tier: "safe",
      notes: "Token values are masked server-side; only env key names are exposed.",
    },
    // Plaintext bot-token read: never enters the agent transcript.
    {
      id: "channels.account-token",
      title: "Read a channel account token in plaintext (denied)",
      method: "GET",
      path: "/api/channels/accounts/token",
      tier: "denied",
      hint: "Tokens are set via env vars, read never.",
    },
    {
      id: "channels.account-add",
      title: "Add a channel account (binds to an agent, reboots gateway)",
      method: "POST",
      path: "/api/channels/accounts",
      tier: "restart",
      // F068: the handler restarts the gateway itself (restartGateway after the
      // config write) — it does not just mark restart-required.
      restart: "restarts",
      idempotent: false,
      readOp: "channels.accounts-list",
      params: {
        fields: [
          {
            name: "provider",
            location: "body",
            type: "string",
            required: true,
            description:
              "One of telegram|discord|slack|whatsapp. Discord and WhatsApp allow a single account; a second add is rejected.",
          },
          {
            name: "agentId",
            location: "body",
            type: "string",
            required: true,
            description: "Agent to bind the account to. Unknown agent ids are rejected (404).",
          },
          {
            name: "token",
            location: "body",
            type: "string",
            required: false,
            description:
              "Bot token, stored as an env var (never in config). Required for every provider except whatsapp (QR login instead).",
          },
          {
            name: "appToken",
            location: "body",
            type: "string",
            required: false,
            description: "Slack app-level token; required when provider is slack.",
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: false,
            description: "Display label; defaults to the provider label.",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description:
              "Lowercase letters, numbers, hyphens. Defaults to \"default\" only when no accounts exist yet; required (and must be unique, else 409) otherwise.",
          },
        ],
        example:
          '{"provider":"telegram","agentId":"main","token":"123456:ABC-token","name":"Support Bot"}',
      },
      hint: "Pipe token-bearing bodies via --data-stdin so secrets stay out of process args.",
      notes:
        "Synchronous variant: reboots the gateway as its final step, so the agent's own session may drop — prefer the jobs variant.",
    },
    {
      id: "channels.account-add-job",
      title: "Add a channel account as a background job (202 + SSE progress)",
      method: "POST",
      path: "/api/channels/accounts/jobs",
      tier: "restart",
      // F068: the handler restarts the gateway itself (restartGateway after the
      // config write) — it does not just mark restart-required.
      restart: "restarts",
      idempotent: false,
      readOp: "channels.accounts-list",
      async: {
        statusOp: "channels.operation-events",
        idField: "operationId",
        terminalStates: ["completed", "failed"],
      },
      params: {
        fields: [
          {
            name: "provider",
            location: "body",
            type: "string",
            required: true,
            description:
              "One of telegram|discord|slack|whatsapp. Discord and WhatsApp allow a single account; a second add is rejected.",
          },
          {
            name: "agentId",
            location: "body",
            type: "string",
            required: true,
            description: "Agent to bind the account to. Unknown agent ids are rejected (404).",
          },
          {
            name: "token",
            location: "body",
            type: "string",
            required: false,
            description:
              "Bot token, stored as an env var (never in config). Required for every provider except whatsapp (QR login instead).",
          },
          {
            name: "appToken",
            location: "body",
            type: "string",
            required: false,
            description: "Slack app-level token; required when provider is slack.",
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: false,
            description: "Display label; defaults to the provider label.",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description:
              "Lowercase letters, numbers, hyphens. Defaults to \"default\" only when no accounts exist yet; required (and must be unique, else 409) otherwise.",
          },
        ],
        example:
          '{"provider":"slack","agentId":"main","token":"xoxb-...","appToken":"xapp-...","name":"Ops Bot"}',
      },
      hint: "Pipe token-bearing bodies via --data-stdin so secrets stay out of process args.",
      notes:
        "Returns 202 with operationId + streamUrl; only one account creation may run at a time.",
    },
    {
      id: "channels.operation-events",
      title: "Stream progress events for a background operation (SSE)",
      method: "GET",
      path: "/api/operations/:operationId/events",
      tier: "safe",
      streaming: true,
      params: {
        fields: [
          {
            name: "operationId",
            location: "path",
            type: "string",
            required: true,
            description:
              "Operation id from a 202 response (e.g. channels.account-add-job). Unknown or expired ids return 404.",
          },
        ],
        example: "GET /api/operations/op-1234/events",
      },
      notes: "SSE stream: phase events, then a terminal completed/failed event.",
    },
    {
      id: "channels.account-update",
      title: "Update a channel account (name, agent binding, token rotation, DM access)",
      method: "PUT",
      path: "/api/channels/accounts",
      tier: "restart",
      // Making an account public (dmPolicy "open" or an allowFrom wildcard)
      // lets anyone who finds the bot command it: dangerous, confirm code.
      tierResolver: (req) => {
        const body = req?.body || {};
        const policy = String(body.dmPolicy ?? "").trim();
        const allowFrom = Array.isArray(body.allowFrom) ? body.allowFrom : [];
        const widens =
          policy === "open" || allowFrom.some((entry) => String(entry ?? "").trim() === "*");
        return widens ? "dangerous" : "restart";
      },
      restart: "marks",
      idempotent: true,
      readOp: "channels.accounts-list",
      params: {
        fields: [
          {
            name: "provider",
            location: "body",
            type: "string",
            required: true,
            description: "One of telegram|discord|slack|whatsapp. Unknown accounts are rejected (404).",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description: 'Account to update; defaults to "default".',
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: true,
            description: "Display label — required on every update, not just when renaming.",
          },
          {
            name: "agentId",
            location: "body",
            type: "string",
            required: true,
            description:
              "Agent the account is bound to — required on every update; unknown agent ids are rejected.",
          },
          {
            name: "token",
            location: "body",
            type: "string",
            required: false,
            description: "New bot token; omit to keep the current one. Rotation marks restart-required.",
          },
          {
            name: "appToken",
            location: "body",
            type: "string",
            required: false,
            description: "New Slack app-level token; omit to keep the current one.",
          },
          {
            name: "dmPolicy",
            location: "body",
            type: "string",
            required: false,
            description:
              "Telegram, Discord or Slack only: pairing|allowlist|open|disabled. \"open\" requires allowFrom to include \"*\" and is refused under a restrictive channel-level allowFrom; \"allowlist\" requires at least one sender id. Omit to keep the current policy.",
          },
          {
            name: "allowFrom",
            location: "body",
            type: "array<string>",
            required: false,
            description:
              "Sender ids allowed to DM this account (Telegram: numeric user ids, optional tg:/telegram: prefix), or \"*\" for everyone (only with dmPolicy \"open\"; the op is then dangerous-tier). Replaces the account's list; [] removes it. Omit to keep the current list. On Telegram, when the account admits groups and has no explicit groupAllowFrom, \"*\" pins groupAllowFrom to the previous sender ids (or is refused), so group access does not widen.",
          },
        ],
        example: '{"provider":"telegram","accountId":"default","name":"Support Bot","agentId":"main"}',
      },
      hint: "Pipe token-bearing bodies via --data-stdin so secrets stay out of process args.",
      notes:
        "Marks restart-required only when a token actually changed. DM access changes apply to new admissions without a restart (OpenClaw access-control docs).",
    },
    {
      id: "channels.account-login",
      title: "Run channel login (WhatsApp QR pairing)",
      method: "POST",
      path: "/api/channels/accounts/login",
      tier: "restart",
      restart: "marks",
      idempotent: false,
      readOp: "channels.login-status",
      params: {
        fields: [
          {
            name: "provider",
            location: "body",
            type: "string",
            required: true,
            description: 'Only "whatsapp" is supported; other providers are rejected (400).',
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description: 'Account to log in; defaults to "default".',
          },
        ],
        example: '{"provider":"whatsapp","accountId":"default"}',
      },
      notes:
        "Runs the CLI login with a ~12s window and returns its stdout/stderr; completed=false means pairing did not finish in time.",
    },
    {
      id: "channels.login-status",
      title: "Read channel login status",
      method: "GET",
      path: "/api/channels/accounts/login-status",
      tier: "safe",
      params: {
        fields: [
          {
            name: "provider",
            location: "query",
            type: "string",
            required: true,
            description: 'Only "whatsapp" is supported; other providers are rejected (400).',
          },
          {
            name: "accountId",
            location: "query",
            type: "string",
            required: false,
            description: 'Account to check; defaults to "default".',
          },
        ],
        example: "GET /api/channels/accounts/login-status?provider=whatsapp",
      },
    },
    {
      id: "channels.account-remove",
      title: "Remove a channel account",
      method: "DELETE",
      path: "/api/channels/accounts",
      tier: "restart",
      // F068: the handler restarts the gateway itself (restartGateway after the
      // config write) — it does not just mark restart-required.
      restart: "restarts",
      idempotent: false,
      readOp: "channels.accounts-list",
      params: {
        fields: [
          {
            name: "provider",
            location: "body",
            type: "string",
            required: true,
            description: "One of telegram|discord|slack|whatsapp. Unknown accounts are rejected (404).",
          },
          {
            name: "accountId",
            location: "body",
            type: "string",
            required: false,
            description: 'Account to remove; defaults to "default".',
          },
        ],
        example: '{"provider":"telegram","accountId":"default"}',
      },
      notes: "Also removes the account's env-stored token and bindings.",
    },
    {
      id: "channels.buzz.setup-status",
      title: "Buzz (Matrix relay) setup wizard state",
      method: "GET",
      path: "/api/channels/buzz/setup",
      tier: "safe",
    },
    {
      id: "channels.buzz.install",
      title: "Install the Buzz relay plugin",
      method: "POST",
      path: "/api/channels/buzz/setup/install",
      tier: "restart",
      restart: "marks",
      idempotent: false,
      readOp: "channels.buzz.setup-status",
      notes:
        "Installs an external OpenClaw plugin and mutates gateway config. 502 on install failure; re-read state to see progress.",
    },
    {
      id: "channels.buzz.configure",
      title: "Configure the Buzz relay endpoint",
      method: "POST",
      path: "/api/channels/buzz/setup/configure",
      tier: "restart",
      restart: "marks",
      idempotent: true,
      readOp: "channels.buzz.setup-status",
      params: {
        fields: [
          {
            name: "relayUrl",
            location: "body",
            type: "string",
            required: true,
            description: "The Buzz relay base URL. Invalid input is a 400.",
          },
          {
            name: "name",
            location: "body",
            type: "string",
            required: false,
            description: 'Display label for the channel. Defaults to "Buzz".',
          },
        ],
        example: '{"relayUrl":"https://relay.example.com","name":"Buzz"}',
      },
    },
    {
      id: "channels.buzz.probe",
      title: "Probe the Buzz relay (connection test, no mutation)",
      method: "POST",
      path: "/api/channels/buzz/setup/probe",
      tier: "safe",
      readOp: "channels.buzz.setup-status",
    },
    {
      id: "channels.buzz.rooms",
      title: "Select Buzz rooms + default outbound room",
      method: "POST",
      path: "/api/channels/buzz/setup/rooms",
      tier: "restart",
      restart: "marks",
      idempotent: true,
      readOp: "channels.buzz.setup-status",
      params: {
        fields: [
          {
            name: "groups",
            location: "body",
            type: "array<{id}>",
            required: true,
            description:
              "Rooms to relay, addressed by UUID (copy from the room's settings). Empty is a 400 no_rooms.",
          },
          {
            name: "defaultTo",
            location: "body",
            type: "string",
            required: false,
            description:
              "UUID of the default outbound room; must be one of the selected rooms.",
          },
        ],
        example: '{"groups":[{"id":"..."}],"defaultTo":"..."}',
      },
    },
    {
      id: "channels.buzz.cancel",
      title: "Cancel/reset the Buzz setup wizard",
      method: "POST",
      path: "/api/channels/buzz/setup/cancel",
      tier: "write",
      idempotent: true,
      readOp: "channels.buzz.setup-status",
    },
    // A2A channel (channels.a2a in openclaw.json). Token VALUES never cross
    // this surface: reads report a peer token by kind and env presence only,
    // and the upsert takes an env NAME (optionally generating the value
    // server-side into AlphaClaw's .env).
    {
      id: "channels.a2a.read",
      title: "Read the A2A channel (peers by token env name; never a token value)",
      method: "GET",
      path: "/api/channels/a2a",
      tier: "safe",
      envelope: "structured",
      notes:
        "configured:false when channels.a2a is absent. Each peer is {id, tokenRef, tokenEnv, tokenEnvSet}: tokenRef is env (a ${VAR} reference), literal (a plaintext token in openclaw.json, value withheld), missing or unsupported.",
    },
    {
      id: "channels.a2a.peer-upsert",
      title: "Add or re-point an A2A peer token to an env variable",
      method: "PUT",
      path: "/api/channels/a2a/peers/:peerId",
      tier: "restart",
      restart: "marks",
      envelope: "structured",
      idempotent: true,
      readOp: "channels.a2a.read",
      params: {
        fields: [
          {
            name: "peerId",
            location: "path",
            type: "string",
            required: true,
            description:
              "Peer name, OpenClaw a2a schema ^[a-z0-9][a-z0-9._-]{0,63}$. Other fields of an existing peer (url, outboundToken) are kept.",
          },
          {
            name: "tokenEnv",
            location: "body",
            type: "string",
            required: false,
            description:
              "Env variable holding the peer's bearer token, ^A2A_[A-Z0-9_]+_TOKEN$. Defaults to A2A_<PEERID>_TOKEN (uppercased, . and - become _). Another peer's variable is refused (409 token_env_in_use).",
          },
          {
            name: "generate",
            location: "body",
            type: "boolean",
            required: false,
            description:
              "When the variable is unset, generate a 256-bit token into AlphaClaw's .env. Without it an unset variable is refused (409 token_env_unset). The value is never returned; hand it to the peer from the Envars tab.",
          },
        ],
        example: '{"generate":true}',
      },
      notes:
        "Two-phase. The reference channels.a2a.peers.<peerId>.token = \"${TOKEN_ENV}\" is written only when the RUNNING gateway was spawned with TOKEN_ENV (OpenClaw hot-reloads channels.a2a and would keep an unresolved \"${VAR}\" literal as the bearer). Otherwise the call stages the variable (generate) and answers 202 state token_staged or restart_required with openclaw.json untouched: restart the gateway, then repeat the call (200/201 state applied). Refuses (409 a2a_channel_absent) when channels.a2a is absent and never creates it.",
    },
    {
      id: "channels.a2a.peer-remove",
      title: "Remove an A2A peer (optionally its token env variable)",
      method: "DELETE",
      path: "/api/channels/a2a/peers/:peerId",
      tier: "dangerous",
      restart: "marks",
      envelope: "structured",
      idempotent: false,
      readOp: "channels.a2a.read",
      params: {
        fields: [
          {
            name: "peerId",
            location: "path",
            type: "string",
            required: true,
            description: "Peer to remove; unknown peers return 404 peer_not_found.",
          },
          {
            name: "removeEnv",
            location: "body",
            type: "boolean",
            required: false,
            description:
              "Also delete the peer's A2A_*_TOKEN variable from AlphaClaw's .env, unless another peer still references it. A deployment-env value is reported, not removed.",
          },
        ],
        example: '{"removeEnv":true}',
      },
      notes:
        "OpenClaw hot-reloads channels.a2a, so the peer stops authenticating within about a second of the write, without a restart. Restart-required is still marked.",
    },
    {
      id: "channels.a2a.update",
      title: "Set or unset the A2A advertised origin",
      method: "PUT",
      path: "/api/channels/a2a",
      // Dangerous: the origin is published in the public Agent Card, and
      // discovering peers send their bearer to it — a changed origin can
      // redirect peer credentials.
      tier: "dangerous",
      restart: "marks",
      envelope: "structured",
      idempotent: true,
      readOp: "channels.a2a.read",
      params: {
        fields: [
          {
            name: "advertisedUrl",
            location: "body",
            type: "string|null",
            required: true,
            description:
              "Externally reachable https origin of AlphaClaw, with no path, query or fragment (not /openclaw, not /a2a/v1: the card appends /a2a/v1). null removes the key.",
          },
        ],
        example: '{"advertisedUrl":"https://claw.example.com"}',
      },
      notes:
        "Dangerous tier (one-time confirm code): peers that discover this instance send their bearer token to the advertised origin. Refuses (409 a2a_channel_absent) when channels.a2a is absent. Marks restart-required.",
    },
  ],
};
