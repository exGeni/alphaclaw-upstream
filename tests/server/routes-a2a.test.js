const fs = require("fs");
const os = require("os");
const path = require("path");
const express = require("express");
const request = require("supertest");

const { registerA2aRoutes } = require("../../lib/server/routes/a2a");
const {
  createA2aChannelService,
  defaultTokenEnvForPeer,
  normalizeAdvertisedUrl,
} = require("../../lib/server/a2a-channel");

// A fixed, recognisable fake "random" source: every assertion that a token
// value never leaves the server greps responses and logs for its encoding.
const kFakeBytes = Buffer.alloc(32, 0xab);
const kFakeToken = kFakeBytes.toString("base64url");

describe("server/routes/a2a (channels.a2a administration)", () => {
  let openclawDir;
  let envVars;
  let processEnv;
  let restartRequiredState;
  let lock;
  let logSpy;
  let warnSpy;
  // Names in the env the running gateway was spawned with (null = unknown).
  let launchKeys;

  const configPath = () => path.join(openclawDir, "openclaw.json");
  const writeConfig = (cfg) => fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2));
  const readConfig = () => JSON.parse(fs.readFileSync(configPath(), "utf8"));
  const baseConfig = (a2a) => ({
    agents: { list: [{ id: "main" }] },
    channels: { telegram: { enabled: true }, ...(a2a === undefined ? {} : { a2a }) },
  });

  beforeEach(() => {
    openclawDir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-routes-"));
    envVars = [];
    processEnv = {};
    launchKeys = new Set();
    restartRequiredState = { markRequired: vi.fn() };
    lock = {
      held: 0,
      kinds: [],
      acquire: vi.fn(async (kind) => {
        lock.held += 1;
        lock.kinds.push(kind);
        return () => {
          lock.held -= 1;
        };
      }),
    };
    logSpy = vi.spyOn(console, "log");
    warnSpy = vi.spyOn(console, "warn");
  });
  afterEach(() => {
    logSpy.mockRestore();
    warnSpy.mockRestore();
    fs.rmSync(openclawDir, { recursive: true, force: true });
  });

  const createApp = ({ requireAdmin = (_req, _res, next) => next() } = {}) => {
    const a2aChannel = createA2aChannelService({
      fsModule: fs,
      openclawDir,
      readEnvFile: () => envVars.map((v) => ({ ...v })),
      updateEnvFile: (mutator) => {
        envVars = mutator(envVars.map((v) => ({ ...v })));
        return envVars;
      },
      reloadEnv: () => {
        for (const { key, value } of envVars) processEnv[key] = value;
        return true;
      },
      processEnv,
      randomBytes: (n) => {
        expect(n).toBe(32);
        return kFakeBytes;
      },
      restartRequiredState,
      gatewayLifecycleLock: lock,
      getGatewayLaunchEnvKeys: () => launchKeys,
    });
    const app = express();
    app.use(express.json());
    registerA2aRoutes({ app, requireAdmin, a2aChannel });
    return app;
  };

  const expectNoTokenLeak = (...bodies) => {
    for (const body of bodies) {
      expect(JSON.stringify(body)).not.toContain(kFakeToken);
    }
    for (const call of [...logSpy.mock.calls, ...warnSpy.mock.calls]) {
      expect(call.map(String).join(" ")).not.toContain(kFakeToken);
    }
  };

  describe("GET /api/channels/a2a (channels.a2a.read)", () => {
    it("reports configured:false when channels.a2a is absent", async () => {
      writeConfig(baseConfig());
      const res = await request(createApp()).get("/api/channels/a2a");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true, configured: false });
    });

    it("projects peers by token kind and env presence, never a token value", async () => {
      writeConfig(
        baseConfig({
          enabled: true,
          advertisedUrl: "https://claw.example.com",
          exposeAgents: ["main"],
          replyTimeoutMs: 30000,
          peers: {
            "claude-host": { token: "${A2A_CLAUDE_HOST_TOKEN}", url: "https://peer.example/a2a/v1" },
            hermes: { token: "${A2A_HERMES_TOKEN}" },
            legacy: { token: "literal-plaintext-peer-secret" },
            broken: {},
          },
        }),
      );
      processEnv.A2A_CLAUDE_HOST_TOKEN = "deployment-env-value";
      const res = await request(createApp()).get("/api/channels/a2a");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        ok: true,
        configured: true,
        enabled: true,
        exposeAgents: ["main"],
        advertisedUrl: "https://claw.example.com",
        replyTimeoutMs: 30000,
        peers: [
          { id: "broken", tokenRef: "missing", tokenEnv: null, tokenEnvSet: null },
          { id: "claude-host", tokenRef: "env", tokenEnv: "A2A_CLAUDE_HOST_TOKEN", tokenEnvSet: true },
          { id: "hermes", tokenRef: "env", tokenEnv: "A2A_HERMES_TOKEN", tokenEnvSet: false },
          { id: "legacy", tokenRef: "literal", tokenEnv: null, tokenEnvSet: null },
        ],
      });
      const text = JSON.stringify(res.body);
      expect(text).not.toContain("literal-plaintext-peer-secret");
      expect(text).not.toContain("deployment-env-value");
    });

    it("counts a value in AlphaClaw's .env as set", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hermes: { token: "${A2A_HERMES_TOKEN}" } } }));
      envVars = [{ key: "A2A_HERMES_TOKEN", value: "from-env-file" }];
      const res = await request(createApp()).get("/api/channels/a2a");
      expect(res.body.peers).toEqual([
        { id: "hermes", tokenRef: "env", tokenEnv: "A2A_HERMES_TOKEN", tokenEnvSet: true },
      ]);
      expect(JSON.stringify(res.body)).not.toContain("from-env-file");
    });

    it("answers the shared config_unreadable envelope for an unparseable openclaw.json", async () => {
      fs.writeFileSync(configPath(), "{ json5: 'not json' }");
      const res = await request(createApp()).get("/api/channels/a2a");
      expect(res.status).toBe(503);
      expect(res.body.code).toBe("config_unreadable");
    });

    it("is behind requireAdmin", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const deny = (_req, res) => res.status(403).json({ code: "admin_required" });
      const app = createApp({ requireAdmin: deny });
      expect((await request(app).get("/api/channels/a2a")).status).toBe(403);
      expect((await request(app).put("/api/channels/a2a/peers/x").send({})).status).toBe(403);
      expect((await request(app).delete("/api/channels/a2a/peers/x")).status).toBe(403);
      expect((await request(app).put("/api/channels/a2a").send({ advertisedUrl: null })).status).toBe(403);
    });
  });

  describe("PUT /api/channels/a2a/peers/:peerId (channels.a2a.peer-upsert)", () => {
    it("two-phase: generate stages the token (202, config untouched); the repeat after a restart writes the ${VAR} reference", async () => {
      writeConfig(baseConfig({ enabled: true, peers: {} }));
      const before = fs.readFileSync(configPath(), "utf8");
      const app = createApp();
      const staged = await request(app)
        .put("/api/channels/a2a/peers/new-peer")
        .send({ generate: true });
      expect(staged.status).toBe(202);
      expect(staged.body).toEqual({
        ok: true,
        state: "token_staged",
        reason: "token_env_generated",
        next: "Restart the gateway, then call channels.a2a.peer-upsert again with the same body.",
        peer: { id: "new-peer", tokenRef: "env", tokenEnv: "A2A_NEW_PEER_TOKEN", tokenEnvSet: true },
        created: false,
        tokenGenerated: true,
        changed: true,
        restartRequired: true,
      });
      expect(envVars).toEqual([{ key: "A2A_NEW_PEER_TOKEN", value: kFakeToken }]);
      expect(processEnv.A2A_NEW_PEER_TOKEN).toBe(kFakeToken);
      // B1: no reference reaches openclaw.json while the running gateway
      // lacks the variable (a hot reload would keep the literal as bearer).
      expect(fs.readFileSync(configPath(), "utf8")).toBe(before);
      expect(restartRequiredState.markRequired).toHaveBeenCalledWith("a2a_token_env_staged");

      // The gateway restarts with the staged variable in its env.
      launchKeys = new Set(["PATH", "A2A_NEW_PEER_TOKEN"]);
      const applied = await request(app)
        .put("/api/channels/a2a/peers/new-peer")
        .send({ generate: true });
      expect(applied.status).toBe(201);
      expect(applied.body).toEqual({
        ok: true,
        state: "applied",
        peer: { id: "new-peer", tokenRef: "env", tokenEnv: "A2A_NEW_PEER_TOKEN", tokenEnvSet: true },
        created: true,
        tokenGenerated: false,
        changed: true,
        restartRequired: false,
      });
      expect(envVars).toEqual([{ key: "A2A_NEW_PEER_TOKEN", value: kFakeToken }]);
      expect(readConfig().channels.a2a.peers).toEqual({
        "new-peer": { token: "${A2A_NEW_PEER_TOKEN}" },
      });
      expect(readConfig().channels.telegram).toEqual({ enabled: true });
      expect(lock.kinds).toEqual(["env_sync", "env_sync"]);
      expect(lock.held).toBe(0);
      expectNoTokenLeak(staged.body, applied.body, readConfig());
    });

    it("B1: a variable set (env.update) but absent from the running gateway is not referenced yet", async () => {
      writeConfig(baseConfig({ enabled: true }));
      envVars = [{ key: "A2A_HERMES_TOKEN", value: "set-after-spawn" }];
      launchKeys = new Set(["PATH"]);
      const before = fs.readFileSync(configPath(), "utf8");
      const res = await request(createApp()).put("/api/channels/a2a/peers/hermes").send({});
      expect(res.status).toBe(202);
      expect(res.body).toMatchObject({
        state: "restart_required",
        reason: "token_env_not_in_running_gateway",
        tokenGenerated: false,
        changed: false,
        restartRequired: true,
      });
      expect(fs.readFileSync(configPath(), "utf8")).toBe(before);
      expect(restartRequiredState.markRequired).toHaveBeenCalledWith("a2a_token_env_staged");
    });

    it("B1: an unknown running-gateway env (adopted incumbent) fails closed", async () => {
      writeConfig(baseConfig({ enabled: true }));
      processEnv.A2A_HERMES_TOKEN = "x";
      launchKeys = null;
      const before = fs.readFileSync(configPath(), "utf8");
      const res = await request(createApp()).put("/api/channels/a2a/peers/hermes").send({});
      expect(res.status).toBe(202);
      expect(res.body).toMatchObject({ state: "restart_required", reason: "running_gateway_env_unknown" });
      expect(fs.readFileSync(configPath(), "utf8")).toBe(before);
    });

    it("keeps an existing env value and the peer's other fields", async () => {
      writeConfig(
        baseConfig({
          enabled: true,
          peers: { hermes: { token: "old-literal", url: "https://hermes.example/a2a/v1" } },
        }),
      );
      envVars = [{ key: "A2A_HERMES_TOKEN", value: "already-there" }];
      launchKeys = new Set(["A2A_HERMES_TOKEN"]);
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/hermes")
        .send({ generate: true });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ state: "applied", created: false, tokenGenerated: false, changed: true });
      expect(envVars).toEqual([{ key: "A2A_HERMES_TOKEN", value: "already-there" }]);
      expect(readConfig().channels.a2a.peers.hermes).toEqual({
        token: "${A2A_HERMES_TOKEN}",
        url: "https://hermes.example/a2a/v1",
      });
      expect(JSON.stringify(res.body)).not.toContain("old-literal");
    });

    it("honours an explicit tokenEnv set in the deployment env", async () => {
      writeConfig(baseConfig({ enabled: true }));
      processEnv.A2A_CLAUDE_HOST_TOKEN = "deployment-env-value";
      launchKeys = new Set(["A2A_CLAUDE_HOST_TOKEN"]);
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/claude.host")
        .send({ tokenEnv: "A2A_CLAUDE_HOST_TOKEN" });
      expect(res.status).toBe(201);
      expect(res.body.peer).toEqual({
        id: "claude.host",
        tokenRef: "env",
        tokenEnv: "A2A_CLAUDE_HOST_TOKEN",
        tokenEnvSet: true,
      });
      expect(envVars).toEqual([]);
      expect(readConfig().channels.a2a.peers["claude.host"]).toEqual({
        token: "${A2A_CLAUDE_HOST_TOKEN}",
      });
    });

    it("is a no-op (no write, no restart) when the reference is already in place", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hermes: { token: "${A2A_HERMES_TOKEN}" } } }));
      processEnv.A2A_HERMES_TOKEN = "x";
      launchKeys = new Set(["A2A_HERMES_TOKEN"]);
      const before = fs.statSync(configPath()).mtimeMs;
      const res = await request(createApp()).put("/api/channels/a2a/peers/hermes").send({});
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ changed: false, restartRequired: false, tokenGenerated: false });
      expect(fs.statSync(configPath()).mtimeMs).toBe(before);
      expect(restartRequiredState.markRequired).not.toHaveBeenCalled();
    });

    it("refuses an unset variable without generate, writing nothing", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const before = fs.readFileSync(configPath(), "utf8");
      const res = await request(createApp()).put("/api/channels/a2a/peers/hermes").send({});
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({ ok: false, code: "token_env_unset" });
      expect(res.body.hint).toMatch(/generate:true/);
      expect(fs.readFileSync(configPath(), "utf8")).toBe(before);
      expect(envVars).toEqual([]);
    });

    it("refuses when channels.a2a is absent and never creates it (no env write either)", async () => {
      writeConfig(baseConfig());
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/hermes")
        .send({ generate: true });
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({ ok: false, code: "a2a_channel_absent" });
      expect(readConfig().channels.a2a).toBeUndefined();
      expect(envVars).toEqual([]);
      expect(restartRequiredState.markRequired).not.toHaveBeenCalled();
    });

    it("refuses a tokenEnv another peer already uses", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hermes: { token: "${A2A_HERMES_TOKEN}" } } }));
      processEnv.A2A_HERMES_TOKEN = "x";
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/other")
        .send({ tokenEnv: "A2A_HERMES_TOKEN" });
      expect(res.status).toBe(409);
      expect(res.body.code).toBe("token_env_in_use");
    });

    it.each([
      [
        "another peer's outboundToken",
        { channels: { a2a: { enabled: true, peers: { b: { token: "${A2A_B_TOKEN}", outboundToken: "${A2A_X_TOKEN}" } } } } },
      ],
      [
        "the same peer's outboundToken",
        { channels: { a2a: { enabled: true, peers: { x: { token: "lit", outboundToken: "${A2A_X_TOKEN}" } } } } },
      ],
      [
        "an inline reference elsewhere in openclaw.json",
        { channels: { a2a: { enabled: true } }, mcp: { servers: { r: { headers: { Authorization: "Bearer ${A2A_X_TOKEN}" } } } } },
      ],
    ])("M1: refuses a tokenEnv referenced by %s", async (_label, cfg) => {
      writeConfig(cfg);
      processEnv.A2A_X_TOKEN = "x";
      launchKeys = new Set(["A2A_X_TOKEN"]);
      const res = await request(createApp()).put("/api/channels/a2a/peers/x").send({});
      expect(res.status).toBe(409);
      expect(res.body.code).toBe("token_env_in_use");
    });

    it("M1: an escaped $${VAR} literal is not a reference", async () => {
      writeConfig({ channels: { a2a: { enabled: true } }, notes: { text: "$${A2A_X_TOKEN}" } });
      processEnv.A2A_X_TOKEN = "x";
      launchKeys = new Set(["A2A_X_TOKEN"]);
      const res = await request(createApp()).put("/api/channels/a2a/peers/x").send({});
      expect(res.status).toBe(201);
    });

    it.each([
      ["Upper", "uppercase"],
      ["-lead", "leading hyphen"],
      ["a".repeat(65), "too long"],
      ["constructor", "reserved name"],
      ["a b", "space"],
    ])("rejects peer id %j (%s)", async (peerId) => {
      writeConfig(baseConfig({ enabled: true }));
      const res = await request(createApp())
        .put(`/api/channels/a2a/peers/${encodeURIComponent(peerId)}`)
        .send({ generate: true });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe("invalid_peer_id");
      expect(envVars).toEqual([]);
    });

    it.each(["WEBHOOK_TOKEN", "A2A_HERMES", "a2a_hermes_token", "A2A__TOKEN", "A2A_X-Y_TOKEN", 7])(
      "rejects tokenEnv %j",
      async (tokenEnv) => {
        writeConfig(baseConfig({ enabled: true }));
        const res = await request(createApp())
          .put("/api/channels/a2a/peers/hermes")
          .send({ tokenEnv, generate: true });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe("invalid_token_env");
        expect(envVars).toEqual([]);
      },
    );

    it("m1: a rejected tokenEnv is logged by shape, never by value", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/hermes")
        .send({ tokenEnv: "sk-pasted-Secret9" });
      expect(res.status).toBe(400);
      const lines = warnSpy.mock.calls.map((call) => call.map(String).join(" "));
      const inputLine = lines.find((line) => line.includes("field=tokenEnv"));
      expect(inputLine).toContain("<string:upper+lower+digit+other>");
      for (const line of lines) expect(line).not.toContain("pasted");
    });

    it("rejects a token value in the body", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/hermes")
        .send({ token: "plaintext-in-body" });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe("invalid_body");
      expect(res.body.hint).toMatch(/never accepted/);
      expect(JSON.stringify(res.body)).not.toContain("plaintext-in-body");
    });

    it("rejects a non-boolean generate", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const res = await request(createApp())
        .put("/api/channels/a2a/peers/hermes")
        .send({ generate: "yes" });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe("invalid_body");
    });
  });

  describe("DELETE /api/channels/a2a/peers/:peerId (channels.a2a.peer-remove)", () => {
    it("removes the peer and keeps its env variable by default", async () => {
      writeConfig(
        baseConfig({
          enabled: true,
          peers: { hermes: { token: "${A2A_HERMES_TOKEN}" }, other: { token: "${A2A_OTHER_TOKEN}" } },
        }),
      );
      envVars = [{ key: "A2A_HERMES_TOKEN", value: "v" }];
      const res = await request(createApp()).delete("/api/channels/a2a/peers/hermes");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        ok: true,
        removed: "hermes",
        tokenEnv: "A2A_HERMES_TOKEN",
        restartRequired: true,
      });
      expect(readConfig().channels.a2a.peers).toEqual({ other: { token: "${A2A_OTHER_TOKEN}" } });
      expect(envVars).toEqual([{ key: "A2A_HERMES_TOKEN", value: "v" }]);
      expect(restartRequiredState.markRequired).toHaveBeenCalledWith("a2a_peers_changed");
    });

    it("removeEnv deletes the variable from the env store and the live env", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hermes: { token: "${A2A_HERMES_TOKEN}" } } }));
      envVars = [
        { key: "A2A_HERMES_TOKEN", value: "v" },
        { key: "OTHER", value: "keep" },
      ];
      processEnv.A2A_HERMES_TOKEN = "v";
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/hermes")
        .send({ removeEnv: true });
      expect(res.status).toBe(200);
      expect(res.body.env).toEqual({ name: "A2A_HERMES_TOKEN", removed: true });
      expect(envVars).toEqual([{ key: "OTHER", value: "keep" }]);
      expect(processEnv).not.toHaveProperty("A2A_HERMES_TOKEN");
      expect(readConfig().channels.a2a.peers).toEqual({});
    });

    it("removeEnv reports a deployment-env value instead of removing it", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hermes: { token: "${A2A_HERMES_TOKEN}" } } }));
      processEnv.A2A_HERMES_TOKEN = "deployment";
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/hermes")
        .send({ removeEnv: true });
      expect(res.body.env).toEqual({ name: "A2A_HERMES_TOKEN", removed: false, reason: "deployment_env" });
      expect(processEnv.A2A_HERMES_TOKEN).toBe("deployment");
    });

    it("removeEnv never deletes a variable outside the A2A token shape", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { hooks: { token: "${WEBHOOK_TOKEN}" } } }));
      envVars = [{ key: "WEBHOOK_TOKEN", value: "w" }];
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/hooks")
        .send({ removeEnv: true });
      expect(res.body.env).toEqual({ name: "WEBHOOK_TOKEN", removed: false, reason: "not_a2a_token_env" });
      expect(envVars).toEqual([{ key: "WEBHOOK_TOKEN", value: "w" }]);
    });

    it("removeEnv keeps a variable another peer still references", async () => {
      writeConfig(
        baseConfig({
          enabled: true,
          peers: { a: { token: "${A2A_SHARED_TOKEN}" }, b: { token: "${A2A_SHARED_TOKEN}" } },
        }),
      );
      envVars = [{ key: "A2A_SHARED_TOKEN", value: "s" }];
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/a")
        .send({ removeEnv: true });
      expect(res.body.env).toEqual({
        name: "A2A_SHARED_TOKEN",
        removed: false,
        reason: "referenced_by_other_peer",
      });
      expect(envVars).toHaveLength(1);
    });

    it("M1/Codex P2: removeEnv keeps a variable another peer's outboundToken references", async () => {
      writeConfig(
        baseConfig({
          enabled: true,
          peers: {
            a: { token: "${A2A_SHARED_TOKEN}" },
            b: { token: "${A2A_B_TOKEN}", outboundToken: "${A2A_SHARED_TOKEN}" },
          },
        }),
      );
      envVars = [{ key: "A2A_SHARED_TOKEN", value: "s" }];
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/a")
        .send({ removeEnv: true });
      expect(res.body.env).toEqual({
        name: "A2A_SHARED_TOKEN",
        removed: false,
        reason: "referenced_by_other_peer",
      });
      expect(envVars).toEqual([{ key: "A2A_SHARED_TOKEN", value: "s" }]);
    });

    it("removeEnv on a literal token reports it without echoing the value", async () => {
      writeConfig(baseConfig({ enabled: true, peers: { legacy: { token: "literal-secret" } } }));
      const res = await request(createApp())
        .delete("/api/channels/a2a/peers/legacy")
        .send({ removeEnv: true });
      expect(res.status).toBe(200);
      expect(res.body.env).toEqual({ name: null, removed: false, reason: "literal_token" });
      expect(JSON.stringify(res.body)).not.toContain("literal-secret");
    });

    it("404s an unknown peer and 409s an absent channel, writing nothing", async () => {
      writeConfig(baseConfig({ enabled: true, peers: {} }));
      const missing = await request(createApp()).delete("/api/channels/a2a/peers/nope");
      expect(missing.status).toBe(404);
      expect(missing.body.code).toBe("peer_not_found");
      writeConfig(baseConfig());
      const absent = await request(createApp()).delete("/api/channels/a2a/peers/nope");
      expect(absent.status).toBe(409);
      expect(absent.body.code).toBe("a2a_channel_absent");
      expect(restartRequiredState.markRequired).not.toHaveBeenCalled();
    });
  });

  describe("PUT /api/channels/a2a (channels.a2a.update)", () => {
    it("sets an https origin and marks restart", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const res = await request(createApp())
        .put("/api/channels/a2a")
        .send({ advertisedUrl: "https://claw.example.com/" });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        ok: true,
        advertisedUrl: "https://claw.example.com",
        changed: true,
        restartRequired: true,
      });
      expect(readConfig().channels.a2a).toEqual({
        enabled: true,
        advertisedUrl: "https://claw.example.com",
      });
      expect(restartRequiredState.markRequired).toHaveBeenCalledWith("a2a_channel_updated");
    });

    it("null unsets the key; repeating is a no-op", async () => {
      writeConfig(baseConfig({ enabled: true, advertisedUrl: "https://claw.example.com" }));
      const app = createApp();
      const first = await request(app).put("/api/channels/a2a").send({ advertisedUrl: null });
      expect(first.body).toMatchObject({ advertisedUrl: null, changed: true });
      expect(readConfig().channels.a2a).toEqual({ enabled: true });
      const second = await request(app).put("/api/channels/a2a").send({ advertisedUrl: null });
      expect(second.body).toMatchObject({ changed: false, restartRequired: false });
      expect(restartRequiredState.markRequired).toHaveBeenCalledTimes(1);
    });

    it.each([
      "http://claw.example.com",
      "https://claw.example.com/openclaw",
      "https://claw.example.com/a2a/v1",
      "https://claw.example.com?x=1",
      "https://claw.example.com/#frag",
      "https://user@claw.example.com",
      "claw.example.com",
      "",
      42,
    ])("rejects advertisedUrl %j", async (advertisedUrl) => {
      writeConfig(baseConfig({ enabled: true }));
      const before = fs.readFileSync(configPath(), "utf8");
      const res = await request(createApp()).put("/api/channels/a2a").send({ advertisedUrl });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe("invalid_advertised_url");
      expect(fs.readFileSync(configPath(), "utf8")).toBe(before);
    });

    it("requires advertisedUrl and rejects other fields", async () => {
      writeConfig(baseConfig({ enabled: true }));
      const app = createApp();
      expect((await request(app).put("/api/channels/a2a").send({})).body.code).toBe("invalid_body");
      const extra = await request(app)
        .put("/api/channels/a2a")
        .send({ advertisedUrl: null, enabled: false });
      expect(extra.status).toBe(400);
      expect(extra.body.code).toBe("invalid_body");
    });

    it("refuses when channels.a2a is absent", async () => {
      writeConfig(baseConfig());
      const res = await request(createApp())
        .put("/api/channels/a2a")
        .send({ advertisedUrl: "https://claw.example.com" });
      expect(res.status).toBe(409);
      expect(res.body.code).toBe("a2a_channel_absent");
      expect(readConfig().channels.a2a).toBeUndefined();
    });
  });

  describe("helpers", () => {
    it("derives the default token env from the peer id", () => {
      expect(defaultTokenEnvForPeer("claude-host")).toBe("A2A_CLAUDE_HOST_TOKEN");
      expect(defaultTokenEnvForPeer("a.b_c-9")).toBe("A2A_A_B_C_9_TOKEN");
    });

    it("normalizes an origin", () => {
      expect(normalizeAdvertisedUrl("https://Claw.Example.com:8443")).toBe("https://claw.example.com:8443");
      expect(normalizeAdvertisedUrl(null)).toBeNull();
    });
  });
});
