const fs = require("fs");
const os = require("os");
const path = require("path");
const express = require("express");
const request = require("supertest");

const manifest = require("../../lib/server/admin-manifest");
const openclawConfig = require("../../lib/server/openclaw-config");
const {
  analyzeEnvTemplate,
  looksLikeCredential,
  redactMcpServerEntry,
  parseServerPatch,
  isToolFilterNarrowing,
  describeServerSet,
  createMcpServersService,
} = require("../../lib/server/mcp-servers");
const { classifyGatewayEnvKey } = require("../../lib/server/gateway-env-policy");
const { resolveRemoteMcpName } = require("../../lib/server/remote-mcp-name");
const { registerMcpServerRoutes } = require("../../lib/server/routes/mcp-servers");
const {
  createServerSetTier,
  createServerSetConfirmSummary,
} = require("../../lib/server/admin-manifest/domains/mcp");
const { createAgentAdminEnforcement } = require("../../lib/server/agent-admin/enforcement");
const { buildConfirmSummary, extractPathParams } = require("../../lib/server/agent-admin/confirm-service");

// Fixture values are fake. kLiteral stands in for a literal credential an
// agent might paste; the tests assert it never comes back out anywhere.
// Header references use *_AUTH_TOKEN names, which the gateway env policy
// forwards by suffix.
const kLiteral = "Bearer literalfixturevalue42";
const kLiteralCore = "literalfixturevalue42";
const kFakePathToken = "a8F3kQ9zL2mX7pR4tV6wY1bN5cJ0dH";

const baseEntry = () => ({
  url: "https://brain.example.test/mcp",
  transport: "streamable-http",
  headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" },
  toolFilter: { include: ["search", "get_page", "query"] },
  codex: { agents: ["tiflis"], defaultToolsApprovalMode: "approve" },
  requestTimeoutMs: 30000,
});

const makeDir = (config) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-servers-"));
  if (config !== undefined) {
    fs.writeFileSync(path.join(dir, "openclaw.json"), JSON.stringify(config, null, 2));
  }
  return dir;
};
const configPath = (dir) => path.join(dir, "openclaw.json");
const readConfig = (dir) => JSON.parse(fs.readFileSync(configPath(dir), "utf8"));

const makeApp = (dir, { env = {} } = {}) => {
  const app = express();
  app.use(express.json());
  const log = { log: vi.fn() };
  registerMcpServerRoutes({
    app,
    mcpServersService: createMcpServersService({ fsModule: fs, openclawDir: dir, log, env }),
  });
  return { app, log };
};

const codeOf = (fn) => {
  try {
    fn();
  } catch (error) {
    return error.code;
  }
  return "accepted";
};

describe("mcp header value policy (scheme allowlist + one ${VAR})", () => {
  it("accepts an optional allowlisted scheme word, one space, and exactly one reference", () => {
    for (const value of [
      "Bearer ${GBRAIN_X_AUTH_TOKEN}",
      "${API_KEY}",
      "Bot ${TG_AUTH_TOKEN}",
      "Basic ${B_AUTH_TOKEN}",
      "Token ${T_AUTH_TOKEN}",
      "ApiKey ${K_API_KEY}",
    ]) {
      expect(analyzeEnvTemplate(value).ok, value).toBe(true);
    }
  });

  it("refuses literals, other words, two references, glued text and odd whitespace", () => {
    for (const value of [
      kLiteral,
      "plainvalue",
      "",
      "Bearer ${lower_case}",
      "$${ESCAPED}",
      "Bearer $VAR",
      "Bearer${X}",
      "Bearer  ${X}",
      "bearer ${X}",
      "Custom ${X}",
      "Token ${A}${B}",
      "Bearer ${X}.extra",
      "Bearer\n${X}",
      "Bearer ${X}\r\nX-Injected: 1",
      42,
      null,
    ]) {
      expect(analyzeEnvTemplate(value).ok, String(value)).toBe(false);
    }
  });
});

describe("mcp header env references reach the gateway (M1)", () => {
  it("uses the gateway env policy's own per-key decision", () => {
    expect(classifyGatewayEnvKey("GBRAIN_X_AUTH_TOKEN")).toMatchObject({ forwarded: true });
    expect(classifyGatewayEnvKey("GBRAIN_X_TOKEN")).toEqual({ forwarded: false, rule: "not allowlisted" });
    expect(classifyGatewayEnvKey("SETUP_PASSWORD").forwarded).toBe(false);
    expect(
      classifyGatewayEnvKey("GBRAIN_X_TOKEN", { hatch: { passthrough: "GBRAIN_*", unrestricted: false } }),
    ).toEqual({ forwarded: true, rule: "ALPHACLAW_GATEWAY_ENV_PASSTHROUGH" });
  });

  it("refuses a reference the gateway would not receive, naming the var and the rule", () => {
    let error;
    try {
      parseServerPatch({ headers: { Authorization: "Bearer ${GBRAIN_X_TOKEN}" } });
    } catch (e) {
      error = e;
    }
    expect(error.code).toBe("env_not_forwarded");
    expect(error.message).toContain("GBRAIN_X_TOKEN");
    expect(error.message).toContain("not allowlisted");
    expect(error.hint).toContain("_AUTH_TOKEN");
    // The same var is fine when the policy forwards it (passthrough).
    const classifyEnv = (key) =>
      classifyGatewayEnvKey(key, { hatch: { passthrough: "GBRAIN_X_TOKEN", unrestricted: false } });
    expect(
      parseServerPatch({ headers: { Authorization: "Bearer ${GBRAIN_X_TOKEN}" } }, { classifyEnv }).headers,
    ).toEqual({ Authorization: "Bearer ${GBRAIN_X_TOKEN}" });
  });

  it("refuses AlphaClaw/OpenClaw credentials even when the policy forwards them", () => {
    for (const name of [
      "OPENCLAW_GATEWAY_TOKEN",
      "OPENCLAW_ANY_AUTH_TOKEN",
      "ALPHACLAW_X_AUTH_TOKEN",
      "WEBHOOK_TOKEN",
      "REMOTE_MCP_API_TOKEN",
    ]) {
      expect(codeOf(() => parseServerPatch({ headers: { Authorization: `Bearer \${${name}}` } })), name).toBe(
        "env_reserved",
      );
    }
    expect(codeOf(() => parseServerPatch({ url: "https://x.test/mcp?api_key=${OPENCLAW_GATEWAY_TOKEN}" }))).toBe(
      "env_reserved",
    );
  });
});

describe("mcp url credential policy (M2)", () => {
  it("detects credential-like strings but not ordinary path words", () => {
    for (const value of [kFakePathToken, "sk_live_FAKEFAKEFAKE", "ghp_FAKEFAKEFAKEFAKE", "123e4567-e89b-12d3-a456-426614174000", "eyJhbGciOi"]) {
      expect(looksLikeCredential(value), value).toBe(true);
    }
    for (const value of ["mcp", "streamable-http-v2-endpoint", "api", "v1", "brain-tiflis", "${PATH_API_KEY}", "getPage"]) {
      expect(looksLikeCredential(value), value).toBe(false);
    }
  });

  it("refuses path, matrix, query and fragment credentials, and accepts ${VAR} in their place", () => {
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/s/${kFakePathToken}/mcp` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/mcp;token=${kLiteralCore}` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/mcp?jwt=${kLiteralCore}` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/mcp?access_token=${kLiteralCore}` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/mcp?%74oken=${kLiteralCore}` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://x.test/mcp?page=${kFakePathToken}` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: `https://u:${kLiteralCore}@x.test/mcp` }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: "https://x.test/mcp#token=x" }))).toBe("invalid_url");
    expect(parseServerPatch({ url: "https://x.test/mcp?api_key=${MCP_API_KEY}" }).url).toBe(
      "https://x.test/mcp?api_key=${MCP_API_KEY}",
    );
    expect(parseServerPatch({ url: "https://x.test/s/${PATH_API_KEY}/mcp" }).url).toBe("https://x.test/s/${PATH_API_KEY}/mcp");
    expect(parseServerPatch({ url: "https://x.test/streamable-http-v2/mcp?page=2" }).url).toBe(
      "https://x.test/streamable-http-v2/mcp?page=2",
    );
    expect(codeOf(() => parseServerPatch({ url: "ftp://x.test" }))).toBe("invalid_url");
    expect(codeOf(() => parseServerPatch({ url: null }))).toBe("invalid_url");
  });
});

describe("mcp server redaction", () => {
  it("shows reference names and allowlisted scheme words only; literals become <literal>", () => {
    const out = redactMcpServerEntry({
      ...baseEntry(),
      headers: {
        Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}",
        "X-Api-Key": kLiteralCore,
        "X-Mixed": `${kLiteralCore} \${PART}`,
        "X-Scheme": "Custom ${PART}",
      },
      env: { TOKEN: kLiteralCore, OTHER: "${OTHER_REF}" },
      somethingNew: kLiteralCore,
      _alphaclawManaged: true,
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(kLiteralCore);
    expect(out.headers).toEqual({
      Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}",
      "X-Api-Key": "<literal>",
      "X-Mixed": "<literal>${PART}",
      "X-Scheme": "<literal>${PART}",
    });
    expect(out.literalHeaders).toEqual(["X-Api-Key", "X-Mixed", "X-Scheme"]);
    expect(out.env).toEqual({ TOKEN: "<literal>", OTHER: "${OTHER_REF}" });
    expect(out.otherKeys).toEqual(["somethingNew"]);
    expect(out.managed).toBe(true);
    expect(out.codex).toEqual({ agents: ["tiflis"], defaultToolsApprovalMode: "approve" });
    expect(out.toolFilter).toEqual({ include: ["search", "get_page", "query"] });
  });

  it("strips url userinfo, query and matrix values, fragments and credential-like path segments", () => {
    expect(
      redactMcpServerEntry({
        url: `https://user:${kLiteralCore}@h.example.test/mcp?token=${kLiteralCore}&ref=\${QUERY_REF}`,
      }).url,
    ).toBe("https://h.example.test/mcp?token=<redacted>&ref=${QUERY_REF}");
    expect(redactMcpServerEntry({ url: "https://h.example.test/mcp/${PATH_REF}" }).url).toBe(
      "https://h.example.test/mcp/${PATH_REF}",
    );
    expect(redactMcpServerEntry({ url: `https://h.example.test/mcp#token=${kLiteralCore}` }).url).toBe(
      "https://h.example.test/mcp",
    );
    expect(redactMcpServerEntry({ url: `https://h.example.test/s/${kFakePathToken}/mcp` }).url).toBe(
      "https://h.example.test/s/<redacted>/mcp",
    );
    expect(redactMcpServerEntry({ url: `https://h.example.test/mcp;token=${kLiteralCore}` }).url).toBe(
      "https://h.example.test/mcp;token=<redacted>",
    );
  });

  it("reduces command to program basename plus arg count and redacts oauth urls (m2)", () => {
    const out = redactMcpServerEntry({
      command: `/usr/bin/env TOKEN=${kLiteralCore} node srv.js`,
      args: ["--token", kLiteralCore],
      oauth: {
        scope: "docs.read",
        redirectUrl: `https://cb.example.test/cb?token=${kLiteralCore}`,
        clientMetadataUrl: `https://m.example.test/${kFakePathToken}/meta.json`,
      },
    });
    expect(JSON.stringify(out)).not.toContain(kLiteralCore);
    expect(JSON.stringify(out)).not.toContain(kFakePathToken);
    expect(out.command).toEqual({ program: "env", argCount: 5 });
    expect(out).not.toHaveProperty("argsCount");
    expect(out.oauth).toEqual({
      scope: "docs.read",
      redirectUrl: "https://cb.example.test/cb?token=<redacted>",
      clientMetadataUrl: "https://m.example.test/<redacted>/meta.json",
    });
    expect(redactMcpServerEntry({ args: ["a", "b"] }).argsCount).toBe(2);
  });
});

describe("mcp server patch parsing", () => {
  it("rejects unknown keys (top level and inside toolFilter) and empty bodies", () => {
    expect(() => parseServerPatch({ url: "https://x.test/mcp", codex: {} })).toThrow(/Unknown key "codex"/);
    expect(() => parseServerPatch({ toolFilter: { include: ["a"], allow: ["b"] } })).toThrow(/Unknown toolFilter key/);
    expect(codeOf(() => parseServerPatch({}))).toBe("invalid_body");
    expect(codeOf(() => parseServerPatch([]))).toBe("invalid_body");
  });

  it("rejects literal header values without echoing them", () => {
    let error;
    try {
      parseServerPatch({ headers: { Authorization: kLiteral } });
    } catch (e) {
      error = e;
    }
    expect(error.status).toBe(400);
    expect(error.code).toBe("literal_secret");
    expect(error.message).toContain("Authorization");
    expect(error.message).not.toContain(kLiteralCore);
  });

  it("validates transport, timeout and filter lists", () => {
    expect(() => parseServerPatch({ transport: "stdio" })).toThrow(/transport/);
    expect(() => parseServerPatch({ requestTimeoutMs: 0 })).toThrow(/requestTimeoutMs/);
    expect(() => parseServerPatch({ toolFilter: { include: [] } })).toThrow(/non-empty/);
    expect(parseServerPatch({ toolFilter: { include: [" a ", "a", "b"] } }).toolFilter).toEqual({ include: ["a", "b"] });
  });
});

describe("mcp tool filter narrowing", () => {
  it("include may only shrink, exclude may only grow", () => {
    const cur = { include: ["search", "get_*"], exclude: ["get_secret"] };
    expect(isToolFilterNarrowing(cur, { include: ["search"], exclude: ["get_secret"] })).toBe(true);
    expect(isToolFilterNarrowing(cur, { include: ["get_page"], exclude: ["get_secret", "x"] })).toBe(true);
    expect(isToolFilterNarrowing(cur, { include: ["search", "put_page"], exclude: ["get_secret"] })).toBe(false);
    expect(isToolFilterNarrowing(cur, { include: ["search", "*"], exclude: ["get_secret"] })).toBe(false);
    expect(isToolFilterNarrowing(cur, { include: ["search"] })).toBe(false); // exclude dropped
    expect(isToolFilterNarrowing(cur, { exclude: ["get_secret"] })).toBe(false); // include cleared
    expect(isToolFilterNarrowing(undefined, { include: ["anything"] })).toBe(true);
    expect(isToolFilterNarrowing(undefined, undefined)).toBe(true);
  });
});

describe("mcp.server-set tier", () => {
  const cfg = { mcp: { servers: { brain: baseEntry() } } };
  const tierFor = (config) => createServerSetTier({ readConfig: () => config });
  const req = (body, name = "brain") => ({ baseUrl: "/api", path: `/mcp/servers/${name}`, body });

  it("is write when an existing server only narrows with exact names", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ toolFilter: { include: ["search"] } }))).toBe("write");
    expect(tier(req({ toolFilter: { exclude: ["query"] } }))).toBe("write");
    expect(tier(req({ requestTimeoutMs: 10000 }))).toBe("write");
    expect(tier(req({ url: "https://brain.example.test/mcp" }))).toBe("write"); // unchanged url
  });

  it("is dangerous for any * glob in a submitted filter list, even one that narrows (M4)", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ toolFilter: { exclude: ["delete_*"] } }))).toBe("dangerous");
    expect(tier(req({ toolFilter: { include: ["get_*"] } }))).toBe("dangerous");
    const unfiltered = tierFor({ mcp: { servers: { docs: { url: "https://d.example.test/mcp" } } } });
    expect(unfiltered(req({ toolFilter: { include: ["get_*"] } }, "docs"))).toBe("dangerous");
    expect(unfiltered(req({ toolFilter: { include: ["get_page"] } }, "docs"))).toBe("write");
  });

  it("is dangerous for a new server, a url/header/transport change, or a widened or cleared filter", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ url: "https://other.example.test/mcp" }, "new-server"))).toBe("dangerous");
    expect(tier(req({ url: "https://other.example.test/mcp" }))).toBe("dangerous");
    expect(tier(req({ transport: "sse" }))).toBe("dangerous");
    expect(tier(req({ transport: null }))).toBe("dangerous");
    expect(tier(req({ headers: { Authorization: "Bearer ${OTHER_AUTH_TOKEN}" } }))).toBe("dangerous");
    expect(tier(req({ headers: { authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" } }))).toBe("dangerous");
    expect(tier(req({ headers: { "X-Extra": "${EXTRA_AUTH_TOKEN}" } }))).toBe("dangerous");
    expect(tier(req({ headers: null }))).toBe("dangerous");
    expect(tier(req({ toolFilter: { include: ["search", "put_page"] } }))).toBe("dangerous");
    expect(tier(req({ toolFilter: { include: null } }))).toBe("dangerous");
    expect(tier(req({ toolFilter: null }))).toBe("dangerous");
  });

  it("leaves bodies and names the route rejects at write (nothing is written) and fails closed on unreadable config", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ headers: { Authorization: kLiteral } }))).toBe("write");
    expect(tier(req({ bogus: 1 }))).toBe("write");
    expect(tier(req({ requestTimeoutMs: 1 }, "missing"))).toBe("write"); // route answers 404
    expect(tier(req({ url: "https://x.test/mcp" }, resolveRemoteMcpName().name))).toBe("write"); // route answers 409
    expect(() => tierFor(null)(req({ requestTimeoutMs: 1 }))).toThrow("config unreadable");
    expect(() => tierFor({ mcp: { servers: { brain: "x" } } })(req({ requestTimeoutMs: 1 }))).toThrow();
    const op = manifest.findOp("PUT", "/api/mcp/servers/brain");
    // resolveTier maps a throwing resolver to dangerous.
    expect(manifest.resolveTier({ ...op, tierResolver: () => { throw new Error("x"); } }, req({}))).toBe("dangerous");
  });
});

describe("mcp confirm summaries (M3)", () => {
  const cfg = { mcp: { servers: { brain: baseEntry() } } };

  it("lets an op add a detail line to the confirm summary, scrubbed and with a title fallback", () => {
    expect(extractPathParams("/api/mcp/servers/:name", "/api/mcp/servers/my%2Dserver")).toEqual({ name: "my-server" });
    const op = { id: "x.y", title: "Do X", path: "/api/x/:id", confirmSummary: ({ pathParams }) => `item ${pathParams.id}` };
    const req = { method: "DELETE", baseUrl: "/api", path: "/x/42", query: {}, body: null };
    expect(buildConfirmSummary(op, req)).toBe("Do X: item 42");
    expect(buildConfirmSummary({ ...op, confirmSummary: () => { throw new Error("boom"); } }, req)).toBe("Do X");
    expect(buildConfirmSummary({ ...op, confirmSummary: () => 7 }, req)).toBe("Do X");
    expect(buildConfirmSummary({ id: "x.y", title: "Do X" }, req)).toBe("Do X");
    expect(buildConfirmSummary({ ...op, confirmSummary: () => "Bearer abcdefghijklmnop\nnext" }, req)).toBe("Do X: *** next");
  });

  it("describes a server set: name, url host, header names with their ${VAR}, transport, filter delta", () => {
    const summary = createServerSetConfirmSummary({ readConfig: () => cfg });
    expect(
      summary({
        pathParams: { name: "docs" },
        body: {
          url: "https://docs.example.test/mcp?page=2",
          transport: "sse",
          headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" },
          toolFilter: { include: ["search"] },
        },
      }),
    ).toBe(
      'server "docs" (new); url host docs.example.test; transport sse; headers Authorization: Bearer ${DOCS_AUTH_TOKEN}; include +search',
    );
    expect(
      summary({ pathParams: { name: "brain" }, body: { toolFilter: { include: ["search", "put_page", "get_*"], exclude: ["query"] } } }),
    ).toBe('server "brain" (update); include +put_page,get_* -get_page,query; exclude +query');
    expect(describeServerSet({ name: "brain", current: baseEntry(), patch: { headers: null, toolFilter: null } })).toBe(
      'server "brain" (update); all headers removed; tool filter cleared',
    );
  });

  it("wires the summaries into the manifest ops", () => {
    const set = manifest.findOp("PUT", "/api/mcp/servers/brain");
    const remove = manifest.findOp("DELETE", "/api/mcp/servers/brain");
    expect(typeof set.confirmSummary).toBe("function");
    const req = { method: "DELETE", baseUrl: "/api", path: "/mcp/servers/legacy", query: {}, body: null };
    expect(buildConfirmSummary(remove, req)).toBe('Remove an MCP server: server "legacy"');
    expect(manifest.getManifest().ops.find((o) => o.id === "mcp.server-set").detailedConfirm).toBe(true);
  });
});

describe("mcp manifest entries", () => {
  it("classifies the three ops with their tiers", () => {
    expect(manifest.findOp("GET", "/api/mcp/servers")).toMatchObject({ id: "mcp.server-list", tier: "safe" });
    const set = manifest.findOp("PUT", "/api/mcp/servers/brain");
    expect(set).toMatchObject({ id: "mcp.server-set", tier: "write", readOp: "mcp.server-list" });
    expect(typeof set.tierResolver).toBe("function");
    expect(manifest.findOp("DELETE", "/api/mcp/servers/brain")).toMatchObject({
      id: "mcp.server-remove",
      tier: "dangerous",
    });
    const serialized = manifest.getManifest().ops.filter((op) => op.domain === "mcp");
    expect(serialized.map((op) => op.id)).toEqual(["mcp.server-list", "mcp.server-set", "mcp.server-remove"]);
  });
});

describe("mcp server routes", () => {
  it("lists servers redacted", async () => {
    const dir = makeDir({
      mcp: { servers: { brain: baseEntry(), raw: { url: "https://r.example.test/mcp", headers: { "X-Key": kLiteralCore } } } },
    });
    const { app } = makeApp(dir);
    const res = await request(app).get("/api/mcp/servers");
    expect(res.status).toBe(200);
    expect(res.body.names).toEqual(["brain", "raw"]);
    expect(res.body.servers.brain.headers.Authorization).toBe("Bearer ${GBRAIN_TEST_AUTH_TOKEN}");
    expect(res.body.servers.raw.literalHeaders).toEqual(["X-Key"]);
    expect(res.text).not.toContain(kLiteralCore);
  });

  it("lists an empty set when the config has no mcp block, and 503s on an unparseable config", async () => {
    const empty = makeDir({ gateway: {} });
    expect((await request(makeApp(empty).app).get("/api/mcp/servers")).body).toMatchObject({ ok: true, names: [] });
    const broken = makeDir();
    fs.writeFileSync(configPath(broken), "{ json5: 'not strict', }");
    const res = await request(makeApp(broken).app).get("/api/mcp/servers");
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("config_unreadable");
  });

  it("creates a server (201) and narrows it field by field, preserving unmanaged keys", async () => {
    const dir = makeDir({ gateway: { port: 1 }, mcp: { servers: { brain: baseEntry() } } });
    const { app, log } = makeApp(dir);

    const created = await request(app)
      .put("/api/mcp/servers/docs")
      .send({ url: "https://docs.example.test/mcp", transport: "streamable-http", headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ ok: true, created: true, changed: true, name: "docs" });
    expect(readConfig(dir).mcp.servers.docs).toEqual({
      url: "https://docs.example.test/mcp",
      transport: "streamable-http",
      headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" },
    });

    const narrowed = await request(app)
      .put("/api/mcp/servers/brain")
      .send({ toolFilter: { include: ["search"], exclude: ["query"] }, requestTimeoutMs: 15000 });
    expect(narrowed.status).toBe(200);
    expect(narrowed.body.created).toBe(false);
    const brain = readConfig(dir).mcp.servers.brain;
    expect(brain.toolFilter).toEqual({ include: ["search"], exclude: ["query"] });
    expect(brain.requestTimeoutMs).toBe(15000);
    expect(brain.codex).toEqual({ agents: ["tiflis"], defaultToolsApprovalMode: "approve" });
    expect(brain.headers).toEqual({ Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" });
    expect(readConfig(dir).gateway).toEqual({ port: 1 });

    // Header patch: case-insensitive replace, null removes, others kept.
    await request(app)
      .put("/api/mcp/servers/brain")
      .send({ headers: { authorization: "Bearer ${ROTATED_AUTH_TOKEN}", "X-Tenant": "${TENANT_AUTH_TOKEN}" } })
      .expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({
      authorization: "Bearer ${ROTATED_AUTH_TOKEN}",
      "X-Tenant": "${TENANT_AUTH_TOKEN}",
    });
    await request(app).put("/api/mcp/servers/brain").send({ headers: { "X-Tenant": null } }).expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({ authorization: "Bearer ${ROTATED_AUTH_TOKEN}" });

    // Clearing the filter removes the key entirely.
    await request(app).put("/api/mcp/servers/brain").send({ toolFilter: null }).expect(200);
    expect(readConfig(dir).mcp.servers.brain).not.toHaveProperty("toolFilter");
    expect(log.log.mock.calls.flat().join(" ")).not.toContain("${");
  });

  it("skips the write for a no-op PUT (m3)", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(configPath(dir), past, past);
    const mtimeBefore = fs.statSync(configPath(dir)).mtimeMs;
    const { app, log } = makeApp(dir);
    const res = await request(app)
      .put("/api/mcp/servers/brain")
      .send({ url: "https://brain.example.test/mcp", requestTimeoutMs: 30000, toolFilter: { include: ["search", "get_page", "query"] } });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, created: false, changed: false });
    expect(fs.readFileSync(configPath(dir), "utf8")).toBe(before);
    expect(fs.statSync(configPath(dir)).mtimeMs).toBe(mtimeBefore);
    expect(log.log).not.toHaveBeenCalled();
  });

  it("400s a non-JSON or non-object body (m3)", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const { app } = makeApp(dir);
    const text = await request(app)
      .put("/api/mcp/servers/brain")
      .set("Content-Type", "text/plain")
      .send(JSON.stringify({ url: "https://evil.example.test/" }));
    expect(text.status).toBe(400);
    expect(text.body.code).toBe("invalid_body");
    const array = await request(app).put("/api/mcp/servers/brain").send([{ url: "https://evil.example.test/" }]);
    expect(array.body.code).toBe("invalid_body");
    const empty = await request(app).put("/api/mcp/servers/brain").send({});
    expect(empty.body.code).toBe("invalid_body");
    expect(fs.readFileSync(configPath(dir), "utf8")).toBe(before);
  });

  it("refuses a literal header with 400 and never echoes it in the response or logs", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const { app, log } = makeApp(dir);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await request(app).put("/api/mcp/servers/brain").send({ headers: { Authorization: kLiteral } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("literal_secret");
    expect(res.text).not.toContain(kLiteralCore);
    expect(JSON.stringify(log.log.mock.calls)).not.toContain(kLiteralCore);
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(kLiteralCore);
    expect(fs.readFileSync(configPath(dir), "utf8")).toBe(before);
  });

  it("400s a header reference the gateway would not receive", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app } = makeApp(dir);
    const res = await request(app).put("/api/mcp/servers/brain").send({ headers: { Authorization: "Bearer ${GBRAIN_X_TOKEN}" } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("env_not_forwarded");
    const reserved = await request(app)
      .put("/api/mcp/servers/brain")
      .send({ headers: { Authorization: "Bearer ${OPENCLAW_GATEWAY_TOKEN}" } });
    expect(reserved.body.code).toBe("env_reserved");
  });

  it("400s unknown keys, 404s update/remove of an unknown name, 409s the REMOTE_MCP managed entry", async () => {
    const dir = makeDir({
      mcp: { servers: { brain: baseEntry(), sure: { url: "https://m.example.test", _alphaclawManaged: true } } },
    });
    const { app } = makeApp(dir);
    expect((await request(app).put("/api/mcp/servers/brain").send({ codex: { agents: [] } })).body.code).toBe("unknown_key");
    const missingSet = await request(app).put("/api/mcp/servers/nope").send({ requestTimeoutMs: 5 });
    expect(missingSet.status).toBe(404);
    expect(missingSet.body.code).toBe("mcp_server_not_found");
    const missingDelete = await request(app).delete("/api/mcp/servers/nope");
    expect(missingDelete.status).toBe(404);
    expect((await request(app).put("/api/mcp/servers/bad%20name").send({ url: "https://x.test" })).body.code).toBe(
      "invalid_name",
    );
    expect((await request(app).put("/api/mcp/servers/sure").send({ requestTimeoutMs: 5 })).status).toBe(409);
    expect((await request(app).delete("/api/mcp/servers/sure")).body.code).toBe("managed_by_env");
  });

  it("reserves the REMOTE_MCP_NAME key (default remote) for create, set and remove even with REMOTE_MCP_* unset (m4)", async () => {
    const dir = makeDir({ mcp: { servers: { notion: { url: "https://n.example.test/mcp" } } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const { app } = makeApp(dir); // env {} → default "remote"
    const create = await request(app).put("/api/mcp/servers/remote").send({ url: "https://r.example.test/mcp" });
    expect(create.status).toBe(409);
    expect(create.body.code).toBe("managed_by_env");
    expect((await request(app).delete("/api/mcp/servers/remote")).status).toBe(409);
    const custom = makeApp(dir, { env: { REMOTE_MCP_NAME: "notion" } }).app;
    expect((await request(custom).put("/api/mcp/servers/notion").send({ requestTimeoutMs: 5 })).status).toBe(409);
    expect((await request(custom).delete("/api/mcp/servers/notion")).status).toBe(409);
    expect((await request(custom).put("/api/mcp/servers/remote").send({ url: "https://r.example.test/mcp" })).status).toBe(201);
    const invalidName = makeApp(dir, { env: { REMOTE_MCP_NAME: "bad name" } }).app; // falls back to "remote"
    expect((await request(invalidName).delete("/api/mcp/servers/remote")).status).toBe(409);
    expect(JSON.parse(before).mcp.servers.notion).toEqual(readConfig(dir).mcp.servers.notion);
  });

  it("removes a server and drops an emptied mcp block", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app } = makeApp(dir);
    const res = await request(app).delete("/api/mcp/servers/brain");
    expect(res.body).toEqual({ ok: true, removed: "brain" });
    expect(readConfig(dir)).not.toHaveProperty("mcp");
  });
});

describe("mcp ops through agent-admin enforcement", () => {
  // Agent actor, no confirm service: a dangerous tier answers 403
  // dangerous_op_requires_confirmation, a write tier reaches the route.
  const compose = (dir) => {
    const events = [];
    vi.spyOn(openclawConfig, "readOpenclawConfig").mockImplementation(() => readConfig(dir));
    const app = express();
    app.use(express.json());
    app.use(
      "/api",
      createAgentAdminEnforcement({
        resolveRequestActor: () => ({ type: "agent" }),
        insertWatchdogEvent: (event) => events.push(event),
        confirmService: null,
      }),
    );
    registerMcpServerRoutes({
      app,
      mcpServersService: createMcpServersService({ fsModule: fs, openclawDir: dir, log: null, env: {} }),
    });
    return { app, events };
  };

  it("narrowing applies at write tier; widening, globs, new servers and removal need a confirm; audit rows carry no values", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app, events } = compose(dir);

    await request(app).put("/api/mcp/servers/brain").send({ toolFilter: { include: ["search"] } }).expect(200);
    const widen = await request(app).put("/api/mcp/servers/brain").send({ toolFilter: { include: ["search", "put_page"] } });
    expect(widen.status).toBe(403);
    expect(widen.body.code).toBe("dangerous_op_requires_confirmation");
    const glob = await request(app).put("/api/mcp/servers/brain").send({ toolFilter: { exclude: ["delete_*"] } });
    expect(glob.status).toBe(403);
    const created = await request(app)
      .put("/api/mcp/servers/docs")
      .send({ url: "https://docs.example.test/mcp", headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(created.status).toBe(403);
    expect((await request(app).delete("/api/mcp/servers/brain")).status).toBe(403);
    const literal = await request(app).put("/api/mcp/servers/brain").send({ headers: { Authorization: kLiteral } });
    expect(literal.status).toBe(400);
    expect(literal.text).not.toContain(kLiteralCore);
    const listed = await request(app).get("/api/mcp/servers");
    expect(listed.status).toBe(200);

    expect(readConfig(dir).mcp.servers).toEqual({ brain: { ...baseEntry(), toolFilter: { include: ["search"] } } });
    const audit = JSON.stringify(events);
    expect(events.length).toBeGreaterThan(0);
    expect(audit).not.toContain(kLiteralCore);
    expect(audit).not.toContain("DOCS_AUTH_TOKEN");
    expect(events.map((e) => e.details.op)).toEqual(
      expect.arrayContaining(["mcp.server-set", "mcp.server-remove"]),
    );
  });
});
