const fs = require("fs");
const os = require("os");
const path = require("path");
const express = require("express");
const request = require("supertest");

const manifest = require("../../lib/server/admin-manifest");
const openclawConfig = require("../../lib/server/openclaw-config");
const {
  analyzeEnvTemplate,
  redactMcpServerEntry,
  parseServerPatch,
  isToolFilterNarrowing,
  createMcpServersService,
} = require("../../lib/server/mcp-servers");
const { registerMcpServerRoutes } = require("../../lib/server/routes/mcp-servers");
const { createServerSetTier } = require("../../lib/server/admin-manifest/domains/mcp");
const { createAgentAdminEnforcement } = require("../../lib/server/agent-admin/enforcement");

// Fixture values are fake. kLiteral stands in for a literal credential an
// agent might paste; the tests assert it never comes back out anywhere.
const kLiteral = "Bearer literalfixturevalue42";
const kLiteralCore = "literalfixturevalue42";

const baseEntry = () => ({
  url: "https://brain.example.test/mcp",
  transport: "streamable-http",
  headers: { Authorization: "Bearer ${GBRAIN_TEST_TOKEN}" },
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
const readConfig = (dir) => JSON.parse(fs.readFileSync(path.join(dir, "openclaw.json"), "utf8"));

const makeApp = (dir) => {
  const app = express();
  app.use(express.json());
  const log = { log: vi.fn() };
  registerMcpServerRoutes({
    app,
    mcpServersService: createMcpServersService({ fsModule: fs, openclawDir: dir, log }),
  });
  return { app, log };
};

describe("mcp header value policy", () => {
  it("accepts ${VAR} references around at most two words of fixed scheme text", () => {
    for (const value of ["Bearer ${GBRAIN_X_TOKEN}", "${API_KEY}", "Bot ${TG}", "Token ${A}${B}", "Bearer${X}"]) {
      expect(analyzeEnvTemplate(value).ok, value).toBe(true);
    }
  });

  it("refuses literals, lowercase or escaped references, and digits or token punctuation in fixed text", () => {
    for (const value of [
      kLiteral,
      "plainvalue",
      "",
      "Bearer ${lower_case}",
      "$${ESCAPED}",
      "Bearer $VAR",
      "Bearer abc123 ${X}",
      "Bearer one two ${X}",
      "Bearer ${X}.extra",
      "Bearer ${X}\r\nX-Injected: 1",
      42,
      null,
    ]) {
      expect(analyzeEnvTemplate(value).ok, String(value)).toBe(false);
    }
  });
});

describe("mcp server redaction", () => {
  it("shows reference names and safe fixed text only; literals become <literal>", () => {
    const out = redactMcpServerEntry({
      ...baseEntry(),
      headers: {
        Authorization: "Bearer ${GBRAIN_TEST_TOKEN}",
        "X-Api-Key": kLiteralCore,
        "X-Mixed": `${kLiteralCore} \${PART}`,
      },
      env: { TOKEN: kLiteralCore, OTHER: "${OTHER_REF}" },
      args: ["--token", kLiteralCore],
      somethingNew: kLiteralCore,
      _alphaclawManaged: true,
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(kLiteralCore);
    expect(out.headers).toEqual({
      Authorization: "Bearer ${GBRAIN_TEST_TOKEN}",
      "X-Api-Key": "<literal>",
      "X-Mixed": "<literal>${PART}",
    });
    expect(out.literalHeaders).toEqual(["X-Api-Key", "X-Mixed"]);
    expect(out.env).toEqual({ TOKEN: "<literal>", OTHER: "${OTHER_REF}" });
    expect(out.argsCount).toBe(2);
    expect(out.otherKeys).toEqual(["somethingNew"]);
    expect(out.managed).toBe(true);
    expect(out.codex).toEqual({ agents: ["tiflis"], defaultToolsApprovalMode: "approve" });
    expect(out.toolFilter).toEqual({ include: ["search", "get_page", "query"] });
  });

  it("strips url userinfo and query values", () => {
    const out = redactMcpServerEntry({
      url: `https://user:${kLiteralCore}@h.example.test/mcp?token=${kLiteralCore}&ref=\${QUERY_REF}`,
    });
    expect(out.url).toBe("https://h.example.test/mcp?token=<redacted>&ref=${QUERY_REF}");
    expect(redactMcpServerEntry({ url: "https://h.example.test/mcp/${PATH_REF}" }).url).toBe(
      "https://h.example.test/mcp/${PATH_REF}",
    );
    expect(redactMcpServerEntry({ url: `https://h.example.test/mcp#token=${kLiteralCore}` }).url).toBe(
      "https://h.example.test/mcp",
    );
  });
});

describe("mcp server patch parsing", () => {
  it("rejects unknown keys (top level and inside toolFilter)", () => {
    expect(() => parseServerPatch({ url: "https://x.test/mcp", codex: {} })).toThrow(/Unknown key "codex"/);
    expect(() => parseServerPatch({ toolFilter: { include: ["a"], allow: ["b"] } })).toThrow(/Unknown toolFilter key/);
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

  it("rejects url credentials and credential-like literal query params", () => {
    expect(() => parseServerPatch({ url: `https://u:${kLiteralCore}@x.test/mcp` })).toThrow(/credentials/);
    expect(() => parseServerPatch({ url: `https://x.test/mcp?api_key=${kLiteralCore}` })).toThrow(/query parameter/);
    expect(parseServerPatch({ url: "https://x.test/mcp?api_key=${MCP_KEY}" }).url).toBe(
      "https://x.test/mcp?api_key=${MCP_KEY}",
    );
    expect(() => parseServerPatch({ url: "ftp://x.test" })).toThrow(/http/);
    expect(() => parseServerPatch({ url: null })).toThrow(/cannot be removed/);
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

  it("is write when an existing server only narrows", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ toolFilter: { include: ["search"] } }))).toBe("write");
    expect(tier(req({ toolFilter: { exclude: ["query"] } }))).toBe("write");
    expect(tier(req({ requestTimeoutMs: 10000 }))).toBe("write");
    expect(tier(req({ url: "https://brain.example.test/mcp" }))).toBe("write"); // unchanged url
    expect(tier(req({ headers: { authorization: "Bearer ${GBRAIN_TEST_TOKEN}" } }))).toBe("dangerous"); // header spelling change rewrites the header
  });

  it("is dangerous for a new server, a url/header/transport change, or a widened or cleared filter", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ url: "https://other.example.test/mcp" }, "new-server"))).toBe("dangerous");
    expect(tier(req({ url: "https://other.example.test/mcp" }))).toBe("dangerous");
    expect(tier(req({ transport: "sse" }))).toBe("dangerous");
    expect(tier(req({ transport: null }))).toBe("dangerous");
    expect(tier(req({ headers: { Authorization: "Bearer ${OTHER_TOKEN}" } }))).toBe("dangerous");
    expect(tier(req({ headers: { "X-Extra": "${EXTRA}" } }))).toBe("dangerous");
    expect(tier(req({ headers: null }))).toBe("dangerous");
    expect(tier(req({ toolFilter: { include: ["search", "put_page"] } }))).toBe("dangerous");
    expect(tier(req({ toolFilter: { include: null } }))).toBe("dangerous");
    expect(tier(req({ toolFilter: null }))).toBe("dangerous");
  });

  it("leaves bodies the route rejects at write (nothing is written) and fails closed on unreadable config", () => {
    const tier = tierFor(cfg);
    expect(tier(req({ headers: { Authorization: kLiteral } }))).toBe("write");
    expect(tier(req({ bogus: 1 }))).toBe("write");
    expect(tier(req({ requestTimeoutMs: 1 }, "missing"))).toBe("write"); // route answers 404
    expect(() => tierFor(null)(req({ requestTimeoutMs: 1 }))).toThrow("config unreadable");
    expect(() => tierFor({ mcp: { servers: { brain: "x" } } })(req({ requestTimeoutMs: 1 }))).toThrow();
    const op = manifest.findOp("PUT", "/api/mcp/servers/brain");
    // resolveTier maps a throwing resolver to dangerous.
    expect(manifest.resolveTier({ ...op, tierResolver: () => { throw new Error("x"); } }, req({}))).toBe("dangerous");
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
    expect(res.body.servers.brain.headers.Authorization).toBe("Bearer ${GBRAIN_TEST_TOKEN}");
    expect(res.body.servers.raw.literalHeaders).toEqual(["X-Key"]);
    expect(res.text).not.toContain(kLiteralCore);
  });

  it("lists an empty set when the config has no mcp block, and 503s on an unparseable config", async () => {
    const empty = makeDir({ gateway: {} });
    expect((await request(makeApp(empty).app).get("/api/mcp/servers")).body).toMatchObject({ ok: true, names: [] });
    const broken = makeDir();
    fs.writeFileSync(path.join(broken, "openclaw.json"), "{ json5: 'not strict', }");
    const res = await request(makeApp(broken).app).get("/api/mcp/servers");
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("config_unreadable");
  });

  it("creates a server (201) and narrows it field by field, preserving unmanaged keys", async () => {
    const dir = makeDir({ gateway: { port: 1 }, mcp: { servers: { brain: baseEntry() } } });
    const { app, log } = makeApp(dir);

    const created = await request(app)
      .put("/api/mcp/servers/docs")
      .send({ url: "https://docs.example.test/mcp", transport: "streamable-http", headers: { Authorization: "Bearer ${DOCS_TOKEN}" } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ ok: true, created: true, name: "docs" });
    expect(readConfig(dir).mcp.servers.docs).toEqual({
      url: "https://docs.example.test/mcp",
      transport: "streamable-http",
      headers: { Authorization: "Bearer ${DOCS_TOKEN}" },
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
    expect(brain.headers).toEqual({ Authorization: "Bearer ${GBRAIN_TEST_TOKEN}" });
    expect(readConfig(dir).gateway).toEqual({ port: 1 });

    // Header patch: case-insensitive replace, null removes, others kept.
    await request(app)
      .put("/api/mcp/servers/brain")
      .send({ headers: { authorization: "Bearer ${ROTATED}", "X-Tenant": "${TENANT}" } })
      .expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({
      authorization: "Bearer ${ROTATED}",
      "X-Tenant": "${TENANT}",
    });
    await request(app).put("/api/mcp/servers/brain").send({ headers: { "X-Tenant": null } }).expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({ authorization: "Bearer ${ROTATED}" });

    // Clearing the filter removes the key entirely.
    await request(app).put("/api/mcp/servers/brain").send({ toolFilter: null }).expect(200);
    expect(readConfig(dir).mcp.servers.brain).not.toHaveProperty("toolFilter");
    expect(log.log.mock.calls.flat().join(" ")).not.toContain("${");
  });

  it("refuses a literal header with 400 and never echoes it in the response or logs", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const before = fs.readFileSync(path.join(dir, "openclaw.json"), "utf8");
    const { app, log } = makeApp(dir);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await request(app).put("/api/mcp/servers/brain").send({ headers: { Authorization: kLiteral } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("literal_secret");
    expect(res.text).not.toContain(kLiteralCore);
    expect(JSON.stringify(log.log.mock.calls)).not.toContain(kLiteralCore);
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(kLiteralCore);
    expect(fs.readFileSync(path.join(dir, "openclaw.json"), "utf8")).toBe(before);
  });

  it("400s unknown keys, 404s update/remove of an unknown name, 409s the REMOTE_MCP managed entry", async () => {
    const dir = makeDir({
      mcp: { servers: { brain: baseEntry(), remote: { url: "https://m.example.test", _alphaclawManaged: true } } },
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
    expect((await request(app).put("/api/mcp/servers/remote").send({ requestTimeoutMs: 5 })).status).toBe(409);
    expect((await request(app).delete("/api/mcp/servers/remote")).body.code).toBe("managed_by_env");
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
      mcpServersService: createMcpServersService({ fsModule: fs, openclawDir: dir, log: null }),
    });
    return { app, events };
  };

  it("narrowing applies at write tier; widening, new servers and removal need a confirm; audit rows carry no values", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app, events } = compose(dir);

    await request(app).put("/api/mcp/servers/brain").send({ toolFilter: { include: ["search"] } }).expect(200);
    const widen = await request(app).put("/api/mcp/servers/brain").send({ toolFilter: { include: ["search", "put_page"] } });
    expect(widen.status).toBe(403);
    expect(widen.body.code).toBe("dangerous_op_requires_confirmation");
    const created = await request(app)
      .put("/api/mcp/servers/docs")
      .send({ url: "https://docs.example.test/mcp", headers: { Authorization: "Bearer ${DOCS_TOKEN}" } });
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
    expect(audit).not.toContain("DOCS_TOKEN");
    expect(events.map((e) => e.details.op)).toEqual(
      expect.arrayContaining(["mcp.server-set", "mcp.server-remove"]),
    );
  });
});
