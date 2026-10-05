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
  applyServerPatch,
  entryRevision,
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
const { renderTelegramHtml } = require("../../lib/server/utils/telegram-html");
const { filterGatewayChildEnv } = require("../../lib/server/gateway-env-policy");
const {
  recordGatewayLaunchEnv,
  resetGatewayLaunchEnvForTests,
} = require("../../lib/server/gateway-launch-env-snapshot");
const { isSensitiveParamKey } = require("../../lib/server/mcp-servers");

// Fixture values are fake. kLiteral stands in for a literal credential an
// agent might paste; the tests assert it never comes back out anywhere.
// Header references use *_AUTH_TOKEN names, which the gateway env policy
// forwards by suffix.
const kLiteral = "Bearer literalfixturevalue42";
const kLiteralCore = "literalfixturevalue42";
const kFakePathToken = "a8F3kQ9zL2mX7pR4tV6wY1bN5cJ0dH";

// Every *_AUTH_TOKEN / *_API_KEY the fixtures reference, "set" in the env the
// gateway would be spawned with (presence check, env_not_set). Placeholder
// values, not credentials.
const kFixtureEnvNames = [
  "GBRAIN_TEST_AUTH_TOKEN",
  "GBRAIN_X_AUTH_TOKEN",
  "DOCS_AUTH_TOKEN",
  "OTHER_AUTH_TOKEN",
  "EXTRA_AUTH_TOKEN",
  "ROTATED_AUTH_TOKEN",
  "TENANT_AUTH_TOKEN",
  "MCP_API_KEY",
  "PATH_API_KEY",
  "GBRAIN_X_TOKEN",
];
const kFixtureEnv = Object.fromEntries(kFixtureEnvNames.map((name) => [name, "fixture-placeholder"]));
beforeEach(() => {
  for (const name of kFixtureEnvNames) vi.stubEnv(name, "fixture-placeholder");
  resetGatewayLaunchEnvForTests();
});
afterEach(() => {
  vi.unstubAllEnvs();
  resetGatewayLaunchEnvForTests();
});

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

const makeApp = (dir, { env = {}, getLaunchedEnvKeys } = {}) => {
  const app = express();
  app.use(express.json());
  const log = { log: vi.fn() };
  registerMcpServerRoutes({
    app,
    mcpServersService: createMcpServersService({
      fsModule: fs,
      openclawDir: dir,
      log,
      env: { ...kFixtureEnv, ...env },
      ...(getLaunchedEnvKeys ? { getLaunchedEnvKeys } : {}),
    }),
  });
  return { app, log };
};

// A url/headers patch carries the revision of the entry it was read from.
// Every set and remove carries the revision of the entry it was read from.
const withRev = (body, current) =>
  body && typeof body === "object" && !Array.isArray(body) && !("revision" in body)
    ? { ...body, revision: entryRevision(current) }
    : body;
const serversOf = (dir) => {
  const mcp = readConfig(dir).mcp;
  return mcp && typeof mcp === "object" && !Array.isArray(mcp) && mcp.servers && typeof mcp.servers === "object" ? mcp.servers : {};
};
const revOf = (dir, name) => entryRevision(Object.prototype.hasOwnProperty.call(serversOf(dir), name) ? serversOf(dir)[name] : undefined);
// A remove of an unknown name still needs a well-formed revision to reach the 404.
const delRev = (dir, name) => {
  const rev = revOf(dir, name);
  return rev === "absent" ? "0000000000000000" : rev;
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
    for (const value of [kFakePathToken, "sk_live_FAKEFAKEFAKE", "gh" + "p_FAKEFAKEFAKEFAKE", "123e4567-e89b-12d3-a456-426614174000", "eyJhbGciOi"]) {
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
    expect(out.otherKeys).toBe(1); // a count, never the key name
    expect(text).not.toContain("somethingNew");
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
  const req = (body, name = "brain", config = cfg) => ({
    baseUrl: "/api",
    path: `/mcp/servers/${name}`,
    body: withRev(body, config?.mcp?.servers?.[name]),
  });

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
    const unfilteredCfg = { mcp: { servers: { docs: { url: "https://d.example.test/mcp" } } } };
    const unfiltered = tierFor(unfilteredCfg);
    expect(unfiltered(req({ toolFilter: { include: ["get_*"] } }, "docs", unfilteredCfg))).toBe("dangerous");
    expect(unfiltered(req({ toolFilter: { include: ["get_page"] } }, "docs", unfilteredCfg))).toBe("write");
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
          revision: "absent",
          url: "https://docs.example.test/mcp?page=2",
          transport: "sse",
          headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" },
          toolFilter: { include: ["search"] },
        },
      }),
    ).toBe(
      'server "docs" NEW rev absent; url https://docs.example.test/mcp?page%3D<red~; SENDS ${DOCS_AUTH_TOKEN}; transport sse; filter narrowed; headers +1 -0; include +1 ["search"]; set Authorization=Bearer ${DOCS_AUTH_TOKEN}',
    );
    expect(
      summary({ pathParams: { name: "brain" }, body: { revision: entryRevision(baseEntry()), toolFilter: { include: ["search", "put_page", "get_*"], exclude: ["query"] } } }),
    ).toBe(
      `server "brain" UPDATE rev ${entryRevision(baseEntry()).slice(0, 8)}; url unchanged https://brain.example.test/mcp; SENDS \${GBRAIN_TEST_AUTH_TOKEN}; FILTER WIDENED; GLOB IN FILTER; include +2 ["put_page", "get_~"] -2 ["get_page", "query"]; exclude +1 ["query"]`,
    );
    expect(describeServerSet({ name: "brain", current: baseEntry(), patch: { revision: entryRevision(baseEntry()), headers: null, toolFilter: null } })).toBe(
      `server "brain" UPDATE rev ${entryRevision(baseEntry()).slice(0, 8)}; url unchanged https://brain.example.test/mcp; SENDS no credential; FILTER CLEARED; ALL HEADERS REMOVED`,
    );
  });

  it("wires the summaries into the manifest ops", () => {
    const set = manifest.findOp("PUT", "/api/mcp/servers/brain");
    const remove = manifest.findOp("DELETE", "/api/mcp/servers/brain");
    expect(typeof set.confirmSummary).toBe("function");
    const req = { method: "DELETE", baseUrl: "/api", path: "/mcp/servers/legacy", query: {}, body: null };
    expect(buildConfirmSummary(remove, req)).toMatch(/^Remove an MCP server: server "legacy"/);
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
      .send({ revision: "absent", url: "https://docs.example.test/mcp", transport: "streamable-http", headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ ok: true, created: true, changed: true, name: "docs" });
    expect(readConfig(dir).mcp.servers.docs).toEqual({
      url: "https://docs.example.test/mcp",
      transport: "streamable-http",
      headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" },
    });

    const narrowed = await request(app)
      .put("/api/mcp/servers/brain")
      .send(withRev({ toolFilter: { include: ["search"], exclude: ["query"] }, requestTimeoutMs: 15000 }, serversOf(dir)["brain"]));
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
      .send({ revision: revOf(dir, "brain"), headers: { authorization: "Bearer ${ROTATED_AUTH_TOKEN}", "X-Tenant": "${TENANT_AUTH_TOKEN}" } })
      .expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({
      authorization: "Bearer ${ROTATED_AUTH_TOKEN}",
      "X-Tenant": "${TENANT_AUTH_TOKEN}",
    });
    await request(app).put("/api/mcp/servers/brain").send({ revision: revOf(dir, "brain"), headers: { "X-Tenant": null } }).expect(200);
    expect(readConfig(dir).mcp.servers.brain.headers).toEqual({ authorization: "Bearer ${ROTATED_AUTH_TOKEN}" });

    // Clearing the filter removes the key entirely.
    await request(app).put("/api/mcp/servers/brain").send(withRev({ toolFilter: null }, serversOf(dir)["brain"])).expect(200);
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
      .send({ revision: revOf(dir, "brain"), url: "https://brain.example.test/mcp", requestTimeoutMs: 30000, toolFilter: { include: ["search", "get_page", "query"] } });
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
    const empty = await request(app).put("/api/mcp/servers/brain").send(withRev({}, serversOf(dir)["brain"]));
    expect(empty.body.code).toBe("invalid_body");
    expect(fs.readFileSync(configPath(dir), "utf8")).toBe(before);
  });

  it("refuses a literal header with 400 and never echoes it in the response or logs", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const { app, log } = makeApp(dir);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await request(app).put("/api/mcp/servers/brain").send(withRev({ headers: { Authorization: kLiteral } }, serversOf(dir)["brain"]));
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
    const res = await request(app).put("/api/mcp/servers/brain").send(withRev({ headers: { Authorization: "Bearer ${GBRAIN_X_TOKEN}" } }, serversOf(dir)["brain"]));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("env_not_forwarded");
    const reserved = await request(app)
      .put("/api/mcp/servers/brain")
      .send(withRev({ headers: { Authorization: "Bearer ${OPENCLAW_GATEWAY_TOKEN}" } }, serversOf(dir)["brain"]));
    expect(reserved.body.code).toBe("env_reserved");
  });

  it("400s unknown keys, 404s update/remove of an unknown name, 409s the REMOTE_MCP managed entry", async () => {
    const dir = makeDir({
      mcp: { servers: { brain: baseEntry(), sure: { url: "https://m.example.test", _alphaclawManaged: true } } },
    });
    const { app } = makeApp(dir);
    expect((await request(app).put("/api/mcp/servers/brain").send(withRev({ codex: { agents: [] } }, serversOf(dir)["brain"]))).body.code).toBe("unknown_key");
    const missingSet = await request(app).put("/api/mcp/servers/nope").send(withRev({ requestTimeoutMs: 5 }, serversOf(dir)["nope"]));
    expect(missingSet.status).toBe(404);
    expect(missingSet.body.code).toBe("mcp_server_not_found");
    const missingDelete = await request(app).delete("/api/mcp/servers/nope").query({ revision: delRev(dir, "nope") });
    expect(missingDelete.status).toBe(404);
    expect((await request(app).put("/api/mcp/servers/bad%20name").send(withRev({ url: "https://x.test" }, serversOf(dir)["bad%20name"]))).body.code).toBe(
      "invalid_name",
    );
    expect((await request(app).put("/api/mcp/servers/sure").send(withRev({ requestTimeoutMs: 5 }, serversOf(dir)["sure"]))).status).toBe(409);
    expect((await request(app).delete("/api/mcp/servers/sure").query({ revision: delRev(dir, "sure") })).body.code).toBe("managed_by_env");
  });

  it("reserves the REMOTE_MCP_NAME key (default remote) for create, set and remove even with REMOTE_MCP_* unset (m4)", async () => {
    const dir = makeDir({ mcp: { servers: { notion: { url: "https://n.example.test/mcp" } } } });
    const before = fs.readFileSync(configPath(dir), "utf8");
    const { app } = makeApp(dir); // env {} → default "remote"
    const create = await request(app).put("/api/mcp/servers/remote").send(withRev({ url: "https://r.example.test/mcp" }, serversOf(dir)["remote"]));
    expect(create.status).toBe(409);
    expect(create.body.code).toBe("managed_by_env");
    expect((await request(app).delete("/api/mcp/servers/remote").query({ revision: delRev(dir, "remote") })).status).toBe(409);
    const custom = makeApp(dir, { env: { REMOTE_MCP_NAME: "notion" } }).app;
    expect((await request(custom).put("/api/mcp/servers/notion").send(withRev({ requestTimeoutMs: 5 }, serversOf(dir)["notion"]))).status).toBe(409);
    expect((await request(custom).delete("/api/mcp/servers/notion").query({ revision: delRev(dir, "notion") })).status).toBe(409);
    expect((await request(custom).put("/api/mcp/servers/remote").send({ revision: "absent", url: "https://r.example.test/mcp" })).status).toBe(201);
    const invalidName = makeApp(dir, { env: { REMOTE_MCP_NAME: "bad name" } }).app; // falls back to "remote"
    expect((await request(invalidName).delete("/api/mcp/servers/remote").query({ revision: delRev(dir, "remote") })).status).toBe(409);
    expect(JSON.parse(before).mcp.servers.notion).toEqual(readConfig(dir).mcp.servers.notion);
  });

  it("removes a server and drops an emptied mcp block", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app } = makeApp(dir);
    const res = await request(app).delete("/api/mcp/servers/brain").query({ revision: delRev(dir, "brain") });
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
      mcpServersService: createMcpServersService({ fsModule: fs, openclawDir: dir, log: null, env: kFixtureEnv }),
    });
    return { app, events };
  };

  it("narrowing applies at write tier; widening, globs, new servers and removal need a confirm; audit rows carry no values", async () => {
    const dir = makeDir({ mcp: { servers: { brain: baseEntry() } } });
    const { app, events } = compose(dir);

    await request(app).put("/api/mcp/servers/brain").send(withRev({ toolFilter: { include: ["search"] } }, serversOf(dir)["brain"])).expect(200);
    const widen = await request(app).put("/api/mcp/servers/brain").send(withRev({ toolFilter: { include: ["search", "put_page"] } }, serversOf(dir)["brain"]));
    expect(widen.status).toBe(403);
    expect(widen.body.code).toBe("dangerous_op_requires_confirmation");
    const glob = await request(app).put("/api/mcp/servers/brain").send(withRev({ toolFilter: { exclude: ["delete_*"] } }, serversOf(dir)["brain"]));
    expect(glob.status).toBe(403);
    const created = await request(app)
      .put("/api/mcp/servers/docs")
      .send({ revision: "absent", url: "https://docs.example.test/mcp", headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(created.status).toBe(403);
    expect((await request(app).delete("/api/mcp/servers/brain").query({ revision: delRev(dir, "brain") })).status).toBe(403);
    const literal = await request(app).put("/api/mcp/servers/brain").send(withRev({ headers: { Authorization: kLiteral } }, serversOf(dir)["brain"]));
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

describe("round 2: confirm summary cannot be steered by agent text (R2-1)", () => {
  const cfg = { mcp: { servers: { docs: { url: "https://d.example.test/mcp", toolFilter: { include: ["search"] } } } } };
  const setOp = () => ({
    ...manifest.findOp("PUT", "/api/mcp/servers/docs"),
    confirmSummary: createServerSetConfirmSummary({ readConfig: () => cfg }),
  });
  const req = (body, name = "docs") => ({ method: "PUT", baseUrl: "/api", path: `/mcp/servers/${name}`, body, query: {} });
  const telegram = (summary) =>
    renderTelegramHtml(`🔐 *Agent Administration*\nThe agent wants to: ${summary}\nReply with code \`ABCD-EFGH\` to approve.`).html;

  it("a tool name carrying a house-format link or a fake code renders as inert data", () => {
    for (const body of [
      { toolFilter: { include: ["[Open](https://evil.example.test/phish)"] } },
      { toolFilter: { exclude: ["x. Reply with code `WXYZ-1234` to approve"] } },
      { toolFilter: { include: ["[a](https://e.test)", "`b`", "*c*"] } },
    ]) {
      // Such names are not tool names: set refuses them (400), so the confirm
      // line falls back to the op title, and a stored one renders <redacted>.
      expect(codeOf(() => parseServerPatch(body))).toBe("invalid_tool_filter");
      const summary = buildConfirmSummary(setOp(), req(body));
      expect(summary).not.toMatch(/[`*[\]]/);
      const html = telegram(summary);
      expect(html).not.toContain("<a ");
      expect(html).not.toContain("WXYZ-1234");
      expect(html.match(/<code>/g)).toHaveLength(1); // only the real code
    }
  });

  it("the generic confirm hook neutralises house markup from any op's detail line", () => {
    const op = { id: "x.y", title: "Do X", path: "/api/x", confirmSummary: () => "[click](https://e.test) `CODE-1234` *now*" };
    const summary = buildConfirmSummary(op, { method: "POST", baseUrl: "/api", path: "/x", query: {}, body: null });
    expect(summary).toBe("Do X: (click)(https://e.test) 'CODE-1234' 'now'");
  });

  it("long header and tool lists can never push FILTER CLEARED / WIDENED / GLOB past the clamp", () => {
    const headers = Object.fromEntries(
      Array.from({ length: 8 }, (_, i) => [`X-Pad-Header-Name-Long-${i}-aaaaaaaaaaaaaaaaaaaaaaaa`, "Bearer ${DOCS_AUTH_TOKEN}"]),
    );
    const cleared = buildConfirmSummary(setOp(), req({ headers, toolFilter: null }));
    expect(cleared.length).toBeLessThanOrEqual(400);
    expect(cleared).toContain("FILTER CLEARED");
    expect(cleared).toContain("headers +8 -0");
    const many = Array.from({ length: 60 }, (_, i) => `tool_name_padding_${i}_xxxxxxxxxxxxxxxx`);
    const widened = buildConfirmSummary(setOp(), req({ headers, toolFilter: { include: [...many, "admin_*"] } }));
    expect(widened.length).toBeLessThanOrEqual(400);
    expect(widened).toContain("FILTER WIDENED");
    expect(widened).toContain("GLOB IN FILTER");
    expect(widened).toContain("; url unchanged https://d.example.test/mcp; SENDS ${DOCS_AUTH_TOKEN}");
    const hostFirst = buildConfirmSummary(setOp(), req({ url: "https://new-host.example.test/mcp", headers, toolFilter: { include: many } }));
    expect(hostFirst).toContain("url https://new-host.example.test/mcp; SENDS ${DOCS_AUTH_TOKEN}");
    expect(hostFirst).toContain("include +60");
  });

  it("credential-shaped tool names and host labels are <redacted> in the summary", () => {
    const token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    expect(codeOf(() => parseServerPatch({ toolFilter: { exclude: [token] } }))).toBe("invalid_tool_filter");
    // A hand-edited stored name that the patch removes is shown <redacted>.
    const summary = describeServerSet({
      name: "docs",
      current: { url: "https://d.example.test/mcp", toolFilter: { exclude: [token, "search"] } },
      patch: { toolFilter: { exclude: null } },
    });
    expect(summary).toContain("exclude removed");
    expect(describeServerSet({ name: "docs", current: { url: "https://d.example.test/mcp", toolFilter: { include: [token, "a"] } }, patch: { toolFilter: { include: ["a"] } } })).toContain("-1 [<redacted>]");
    expect(summary).not.toContain("a1B2c3D4");
    expect(describeServerSet({ name: "docs", current: undefined, patch: { url: "https://a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.mcp.example.test/mcp" } })).toBe(
      'server "docs" NEW rev MISSING; url https://<redacted>.mcp.example.test/mcp; SENDS no credential',
    );
  });
});

describe("round 2: referenced vars must be set, and a late var needs a restart (R2-2)", () => {
  it("refuses a forwardable but unset or empty var with 400 env_not_set", async () => {
    expect(codeOf(() => parseServerPatch({ headers: { Authorization: "Bearer ${NEVER_SET_ANYWHERE_AUTH_TOKEN}" } }))).toBe("env_not_set");
    expect(codeOf(() => parseServerPatch({ headers: { Authorization: "Bearer ${EMPTY_AUTH_TOKEN}" } }, { env: { EMPTY_AUTH_TOKEN: "  " } }))).toBe("env_not_set");
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://d.example.test/mcp" } } } });
    const res = await request(makeApp(dir).app)
      .put("/api/mcp/servers/docs")
      .send(withRev({ headers: { Authorization: "Bearer ${NEVER_SET_ANYWHERE_AUTH_TOKEN}" } }, serversOf(dir)["docs"]));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("env_not_set");
    expect(readConfig(dir).mcp.servers.docs).toEqual({ url: "https://d.example.test/mcp" });
  });

  it("reports restartRequired when the running gateway was spawned before the var was set", async () => {
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://d.example.test/mcp" } } } });
    recordGatewayLaunchEnv({ PATH: "/bin", GBRAIN_TEST_AUTH_TOKEN: "x" });
    const { app } = makeApp(dir, { getLaunchedEnvKeys: undefined });
    const late = await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(late.status).toBe(200);
    expect(late.body.restartRequired).toBe(true);
    expect(late.body.warning).toContain("${DOCS_AUTH_TOKEN}");
    const known = await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" } });
    expect(known.body.restartRequired).toBe(false);
    expect(known.body).not.toHaveProperty("warning");
    const timeoutOnly = await request(app).put("/api/mcp/servers/docs").send(withRev({ requestTimeoutMs: 9 }, serversOf(dir)["docs"]));
    expect(timeoutOnly.body.restartRequired).toBe(false);
  });

  it("reports restartRequired with a warning when the running gateway's env is unknown", async () => {
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://d.example.test/mcp" } } } });
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } });
    expect(res.body.restartRequired).toBe(true);
    expect(res.body.warning).toMatch(/unknown/);
  });

  it("classifyGatewayEnvKey agrees with filterGatewayChildEnv on every key and hatch", () => {
    const keys = ["PATH", "HOME", "ALPHACLAW_ROOT_DIR", "ALPHACLAW_X", "SETUP_PASSWORD", "OPENCLAW_GATEWAY_TOKEN", "X_API_KEY", "X_AUTH_TOKEN", "RAILWAY_API_TOKEN", "npm_config__auth", "npm_config_cache", "CLAUDE_CODE_LOCAL_X", "AWS_SECRET", "FOO", "GBRAIN_MCP_TOKEN", "WEBHOOK_TOKEN", "LC_ALL", "constructor", "__proto__", ""];
    const hatches = [
      { passthrough: "", unrestricted: false },
      { passthrough: "GBRAIN_* FOO, SETUP_PASSWORD", unrestricted: false },
      { passthrough: "", unrestricted: true },
    ];
    for (const hatch of hatches) {
      const env = Object.fromEntries(keys.map((k) => [k, "v"]));
      const out = filterGatewayChildEnv(env, { logger: {}, hatch });
      for (const key of keys) {
        expect(classifyGatewayEnvKey(key, { hatch }).forwarded, `${JSON.stringify(hatch)} ${key}`).toBe(
          Object.prototype.hasOwnProperty.call(out, key),
        );
      }
    }
  });
});

describe("round 2: url keys, host labels, command program, reserved-name wording (R2-3..6)", () => {
  it("refuses a credential-shaped host label and redacts it in the list view", () => {
    for (const url of [
      "https://a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.mcp.example.test/mcp",
      "https://sk-live-a1B2c3D4e5F6g7H8i9J0.example.test/mcp",
    ]) {
      expect(codeOf(() => parseServerPatch({ url })), url).toBe("literal_secret");
    }
    expect(redactMcpServerEntry({ url: "https://a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.mcp.example.test/mcp" }).url).toBe(
      "https://<redacted>.mcp.example.test/mcp",
    );
    expect(parseServerPatch({ url: "http://openclaw:3131/mcp" }).url).toBe("http://openclaw:3131/mcp");
  });

  it("matches sensitive param keys by whole key or delimited part, not substring", () => {
    for (const key of ["code_version", "session", "authorized", "monkey", "page", "keyboard"]) {
      expect(isSensitiveParamKey(key), key).toBe(false);
    }
    for (const key of ["token", "access_token", "apiKey", "api-key", "X-Amz-Signature", "jwt", "code", "jsessionid", "auth"]) {
      expect(isSensitiveParamKey(key), key).toBe(true);
    }
    for (const url of ["https://h.example.test/mcp?code_version=2", "https://h.example.test/mcp?session=default", "https://h.example.test/mcp/sse?authorized=1"]) {
      expect(parseServerPatch({ url }).url).toBe(url);
    }
    expect(codeOf(() => parseServerPatch({ url: "https://h.example.test/mcp?accessToken=plain" }))).toBe("literal_secret");
  });

  it("redacts a credential-shaped command program", () => {
    expect(redactMcpServerEntry({ command: "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789" }).command).toEqual({
      program: "<redacted>",
      argCount: 0,
    });
    expect(redactMcpServerEntry({ command: "/usr/local/bin/uvx mcp-server-fetch" }).command).toEqual({ program: "uvx", argCount: 1 });
  });

  it("states what the gateway actually does with the reserved entry", async () => {
    const dir = makeDir({ mcp: { servers: {} } });
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/remote").send(withRev({ url: "https://r.example.test/mcp" }, serversOf(dir)["remote"]));
    expect(res.status).toBe(409);
    expect(res.body.error).toContain("when REMOTE_MCP_URL and REMOTE_MCP_API_TOKEN are both set");
    expect(res.body.error).toContain("managed marker");
    expect(res.body.error).not.toContain("rewrites or removes");
  });
});

describe("round 3: the confirm summary names every credential the entry sends, and where (R3)", () => {
  const docs = { url: "https://d.example.test/mcp", headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" } };
  const summaryFor = (body, current = docs, name = "docs") => {
    const op = {
      ...manifest.findOp("PUT", `/api/mcp/servers/${name}`),
      confirmSummary: createServerSetConfirmSummary({ readConfig: () => ({ mcp: { servers: current ? { [name]: current } : {} } }) }),
    };
    return buildConfirmSummary(op, { method: "PUT", baseUrl: "/api", path: `/mcp/servers/${name}`, body, query: {} });
  };

  it("F1: clips a long host from the left, so the receiving domain stays visible", () => {
    const host = "gbrain.tailnet-example.ts.net.mcp-gateway.regional-mirror.attacker-owned.example";
    const summary = summaryFor({ url: `https://${host}/mcp` });
    expect(summary).toContain("url https://~.");
    expect(summary).toContain(".regional-mirror.attacker-owned.example/mcp");
    expect(summary).not.toContain("gbrain.tailnet-example");
    expect(describeServerSet({ name: "x", current: undefined, patch: { url: `https://${"a".repeat(60)}.example.test:8443/mcp` } })).toBe(
      'server "x" NEW rev MISSING; url https://~.example.test:8443/mcp; SENDS no credential',
    );
    expect(describeServerSet({ name: "x", current: undefined, patch: { url: `https://${"a".repeat(60)}:8443/mcp` } })).toBe(
      `server "x" NEW rev MISSING; url https://~${"a".repeat(39)}:8443/mcp; SENDS no credential`,
    );
  });

  it("F2a: names ${VAR} references carried in the url query or path", () => {
    const query = summaryFor({ url: "https://d.example.test/mcp?q=${MCP_API_KEY}" });
    expect(query).toContain("SENDS ${MCP_API_KEY}, ${GBRAIN_TEST_AUTH_TOKEN}");
    const inPath = summaryFor({ url: "https://d.example.test/${PATH_API_KEY}/mcp" }, undefined);
    expect(inPath).toContain("url https://d.example.test/${PATH_API_KEY}~");
    expect(inPath).toContain("SENDS ${PATH_API_KEY}");
  });

  it("F2b: names every header reference, not the first three", () => {
    const summary = summaryFor({
      headers: { "X-A": "${DOCS_AUTH_TOKEN}", "X-B": "${OTHER_AUTH_TOKEN}", "X-C": "${EXTRA_AUTH_TOKEN}", "X-D": "Bearer ${MCP_API_KEY}" },
    }, { url: "https://d.example.test/mcp" });
    expect(summary).toContain(
      "url unchanged https://d.example.test/mcp; SENDS ${DOCS_AUTH_TOKEN}, ${OTHER_AUTH_TOKEN}, ${EXTRA_AUTH_TOKEN}, ${MCP_API_KEY};",
    );
  });

  it("F2c: a long filter delta cannot push a header reference out of the summary", () => {
    const many = Array.from({ length: 6 }, (_, i) => `search_pages_by_topic_number_${i}`);
    const summary = summaryFor({
      toolFilter: { include: many, exclude: many.map((t) => `x_${t}`) },
      headers: { "X-Tenant": "${TENANT_AUTH_TOKEN}" },
    });
    expect(summary).toContain("url unchanged https://d.example.test/mcp; SENDS ${GBRAIN_TEST_AUTH_TOKEN}, ${TENANT_AUTH_TOKEN};");
    expect(summary.indexOf("SENDS")).toBeLessThan(summary.indexOf("include"));
  });

  it("F2d: a url change names the existing headers that now go to the new host, literal ones by count", () => {
    const summary = summaryFor(
      { url: "https://elsewhere.example.test/mcp" },
      { url: "https://d.example.test/mcp", headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}", "X-Raw": kLiteralCore } },
    );
    expect(summary).toContain("url https://elsewhere.example.test/mcp; SENDS ${GBRAIN_TEST_AUTH_TOKEN}, 1 literal header");
    expect(summary).not.toContain(kLiteralCore);
  });

  it("F2: refuses an entry with more distinct references than the summary can name, and says so", async () => {
    const five = { "X-1": "${DOCS_AUTH_TOKEN}", "X-2": "${OTHER_AUTH_TOKEN}", "X-3": "${EXTRA_AUTH_TOKEN}", "X-4": "${ROTATED_AUTH_TOKEN}" };
    const dir = makeDir({ mcp: { servers: { docs } } });
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: five });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("too_many_env_refs");
    expect(readConfig(dir).mcp.servers.docs).toEqual(docs);
    expect(summaryFor({ revision: entryRevision(docs), headers: five })).toContain("SENDS 5 ${VAR} refs, OVER LIMIT (refused)");
    // Character bound: three long names exceed it even under the count limit.
    const long = ["A", "B", "C"].map((p) => `${p}_${"LONG_NAME_".repeat(2)}AUTH_TOKEN`);
    const env = Object.fromEntries(long.map((n) => [n, "fixture-placeholder"]));
    const longDir = makeDir({ mcp: { servers: {} } });
    const longRes = await request(makeApp(longDir, { env }).app)
      .put("/api/mcp/servers/wide")
      .send({ revision: "absent", url: "https://w.example.test/mcp", headers: Object.fromEntries(long.map((n, i) => [`X-${i}`, `\${${n}}`])) });
    expect(longRes.status).toBe(400);
    expect(longRes.body.code).toBe("too_many_env_refs");
  });

  it("F2: the worst-case critical part fits the 400-character clamp with every reference named", () => {
    // Worst case under every bound: 64-char name, revision, 41-char IPv6
    // host with port, clipped path, scheme change, 4 refs, 16 literal
    // headers, transport, FILTER WIDENED, GLOB, "headers +16 -16", and the
    // reference list at exactly the 80-character bound.
    const refs = ["R0_XY_AUTH_TOKEN", "R1_XY_AUTH_TOKEN", "R2_X_AUTH_TOKEN", "R3_X_AUTH_TOKEN"];
    expect(refs.map((r) => `\${${r}}`).join(", ")).toHaveLength(80);
    for (const ref of refs) vi.stubEnv(ref, "fixture-placeholder");
    const name = "n".repeat(64);
    const literal = Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`L-${i}`, "plain"]));
    const current = { url: "http://x.example.test/mcp", toolFilter: { include: ["a"] }, headers: literal };
    const headers = {};
    for (let i = 0; i < 16; i += 1) headers[`X-${i}`] = `Bearer \${${refs[i % 4]}}`;
    for (let i = 0; i < 16; i += 1) headers[`L-${i}`] = null;
    const summary = summaryFor(
      {
        revision: entryRevision(current),
        url: `https://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/${"a".repeat(45)}?q=1`,
        transport: "streamable-http",
        toolFilter: { include: ["b*"], exclude: ["c"] },
        headers,
      },
      current,
      name,
    );
    expect(summary.length).toBeLessThanOrEqual(400);
    for (const ref of refs) expect(summary).toContain(`\${${ref}}`);
    const mark = "headers +16 -16";
    const critical = summary.slice(0, summary.indexOf(mark) + mark.length);
    expect(critical).toContain(`UPDATE rev ${entryRevision(current).slice(0, 8)}; url https://`);
    expect(critical).toContain("16 literal headers; transport streamable-http; FILTER WIDENED; GLOB IN FILTER; headers +16 -16");
    expect(critical.length).toBe(398); // measured bound, stated in mcp-servers.js
    // One character more is refused, and the summary says so.
    vi.stubEnv("R0_XYZ_AUTH_TOKEN", "fixture-placeholder");
    const over = { ...headers, "X-0": "Bearer ${R0_XYZ_AUTH_TOKEN}", "X-4": "Bearer ${R0_XYZ_AUTH_TOKEN}", "X-8": "Bearer ${R0_XYZ_AUTH_TOKEN}", "X-12": "Bearer ${R0_XYZ_AUTH_TOKEN}" };
    expect(summaryFor({ revision: entryRevision(current), headers: over }, current, name)).toContain("SENDS 4 ${VAR} refs, OVER LIMIT (refused)");
    // The same entry with the url unchanged: the url piece is no longer.
    const unchanged = summaryFor(
      { revision: entryRevision({ ...current, url: `https://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/${"a".repeat(45)}?q=1` }), transport: "streamable-http", toolFilter: { include: ["b*"], exclude: ["c"] }, headers },
      { ...current, url: `https://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/${"a".repeat(45)}?q=1` },
      name,
    );
    expect(unchanged.slice(0, unchanged.indexOf(mark) + mark.length).length).toBeLessThanOrEqual(398);
    for (const ref of refs) expect(unchanged).toContain(`\${${ref}}`);
  });

  it("F3: an idempotent retry still reports restartRequired for a var the running gateway lacks", () => {
    const dir = makeDir({ mcp: { servers: {} } });
    const svc = createMcpServersService({
      fsModule: fs,
      openclawDir: dir,
      log: { log: () => {} },
      env: { NEW_AUTH_TOKEN: "fixture-placeholder" },
      classifyEnv: () => ({ forwarded: true, rule: "test" }),
      getLaunchedEnvKeys: () => new Set(["PATH"]),
    });
    // The retry resends the same body, revision "absent" included: stale, but
    // it changes nothing, so it is a no-op rather than 409.
    const body = { revision: "absent", url: "https://mcp.example.test/mcp", headers: { Authorization: "Bearer ${NEW_AUTH_TOKEN}" } };
    expect(svc.setServer("svc", body)).toMatchObject({ changed: true, restartRequired: true });
    const retry = svc.setServer("svc", body);
    expect(retry).toMatchObject({ changed: false, restartRequired: true });
    expect(retry.warning).toContain("${NEW_AUTH_TOKEN}");
    const stored = JSON.parse(fs.readFileSync(configPath(dir), "utf8")).mcp.servers.svc;
    expect(svc.setServer("svc", { revision: entryRevision(stored), requestTimeoutMs: 5000 })).toMatchObject({ changed: true, restartRequired: true });
  });

  it("F4: shows scheme and redacted path, marks a downgrade and an unchanged url", () => {
    expect(summaryFor({ url: "http://d.example.test/mcp" })).toContain(
      "url http://d.example.test/mcp (was https); SENDS ${GBRAIN_TEST_AUTH_TOKEN}",
    );
    // The route refuses such a url; the display path still goes through redactUrl.
    expect(describeServerSet({ name: "docs", current: undefined, patch: { url: "https://d.example.test/mcp/sk-live-a1B2c3D4e5F6g7H8i9J0" } })).toBe(
      'server "docs" NEW rev MISSING; url https://d.example.test/mcp/<redacted>; SENDS no credential',
    );
    expect(summaryFor({ url: "https://d.example.test/mcp", transport: "sse" })).toContain(
      "url unchanged https://d.example.test/mcp; SENDS ${GBRAIN_TEST_AUTH_TOKEN}; transport sse",
    );
  });

  it("F5: a long legitimate tool name is shown, a credential-shaped one is still redacted", () => {
    const toolName = "inc_tool_name_number_0_abcdefghij";
    expect(looksLikeCredential(toolName)).toBe(true); // whole-string entropy rule (urls)
    const summary = describeServerSet({ name: "docs", current: docs, patch: { toolFilter: { exclude: [toolName, "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"] } } });
    expect(summary).toContain('exclude +2 ["inc_tool_name_number_0_abcdefghi~", <redacted>]');
  });

  it("F6: a tool name carrying []() is not a tool name and renders <redacted>", () => {
    expect(describeServerSet({ name: "docs", current: docs, patch: { toolFilter: { include: ["a[b](c)d"] } } })).toBe(
      'server "docs" UPDATE rev MISSING; url unchanged https://d.example.test/mcp; SENDS ${GBRAIN_TEST_AUTH_TOKEN}; filter narrowed; include +1 [<redacted>]',
    );
  });
});

describe("round 4: url keys, registrable label, header caps, host escaping, unknown launch env (R4)", () => {
  // Credential-shaped fixtures are assembled at runtime; they are not real credentials.
  const tokenShape = "gh" + "p_" + "Q7xZ2kLm9PwR4tYb8NcV3hJd6FsA1eGu0Kio";
  const uuidShape = "3f2b8c1e-9d4a-4e7b-a6c5-1b2d3e4f5a6b";
  const docs = { url: "https://d.example.test/mcp" };
  const tierFor = (body, current = docs) =>
    createServerSetTier({ readConfig: () => ({ mcp: { servers: current ? { docs: current } : {} } }) })({
      baseUrl: "/api",
      path: "/mcp/servers/docs",
      body: withRev(body, current),
    });
  const manyHeaders = (n, prefix = "X") =>
    Object.fromEntries(Array.from({ length: n }, (_, i) => [`${prefix}-${i}`, "Bearer ${DOCS_AUTH_TOKEN}"]));

  it("R4-1: refuses a credential-shaped query or ;matrix key and redacts one already on disk", () => {
    for (const url of [
      `https://api.example.test/mcp?${tokenShape}`,
      `https://api.example.test/mcp?${tokenShape}=`,
      `https://api.example.test/mcp;${tokenShape}`,
      `https://api.example.test/mcp;${tokenShape}=1`,
      `https://api.example.test/mcp?${uuidShape}`,
    ]) {
      expect(codeOf(() => parseServerPatch({ url })), "url shape").toBe("literal_secret");
      expect(redactMcpServerEntry({ url }).url).not.toContain(tokenShape);
      expect(redactMcpServerEntry({ url }).url).not.toContain(uuidShape);
    }
    expect(parseServerPatch({ url: "https://api.example.test/mcp?page=2;v=1" }).url).toBe("https://api.example.test/mcp?page=2;v=1");
  });

  it("R4-2: keeps the registrable label, cut inside from its left, and the TLD", () => {
    const one = `${"mcp-".repeat(20)}mcp.com`;
    const two = `api.${"exgenius-".repeat(8)}host.net`;
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: `https://${one}/mcp` } })).toBe(
      'server "s" NEW rev MISSING; url https://~mcp-mcp-mcp-mcp-mcp-mcp-mcp-mcp-mcp.com/mcp; SENDS no credential',
    );
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: `https://${two}/mcp` } })).toBe(
      'server "s" NEW rev MISSING; url https://~ius-exgenius-exgenius-exgenius-host.net/mcp; SENDS no credential',
    );
  });

  it("R4-3: caps headers per call and per resulting entry before any merge, and merges case-insensitively", async () => {
    expect(codeOf(() => parseServerPatch({ headers: manyHeaders(33) }))).toBe("too_many_headers");
    expect(Object.keys(parseServerPatch({ headers: manyHeaders(32) }).headers)).toHaveLength(32);
    const current = { url: "https://d.example.test/mcp", headers: manyHeaders(31, "Old") };
    const dir = makeDir({ mcp: { servers: { docs: current } } });
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: manyHeaders(2) });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("too_many_headers");
    expect(readConfig(dir).mcp.servers.docs).toEqual(current);
    expect(tierFor({ headers: manyHeaders(33) })).toBe("write");
    expect(tierFor({ headers: manyHeaders(2) }, current)).toBe("write");
    const merged = applyServerPatch(
      { headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}", "X-Keep": "${OTHER_AUTH_TOKEN}" } },
      { headers: { authorization: "Bearer ${EXTRA_AUTH_TOKEN}", "x-keep": null } },
    );
    expect(merged.headers).toEqual({ authorization: "Bearer ${EXTRA_AUTH_TOKEN}" });
  });

  it("R4-4: renders IPv6 literals in brackets and escapes, never drops, odd host characters", () => {
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: "http://[::1]:3131/mcp" } })).toBe(
      'server "s" NEW rev MISSING; url http://[::1]:3131/mcp; SENDS no credential',
    );
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: "https://trusted!.example.test/mcp" } })).toContain(
      "url https://trusted%21.example.test/mcp",
    );
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: "https://ex_genius.example.test/mcp" } })).toContain(
      "url https://ex_genius.example.test/mcp",
    );
  });

  it("R4-5: with an unknown launch env, only a changing call with references asks for a restart", () => {
    const dir = makeDir({ mcp: { servers: {} } });
    const svc = createMcpServersService({
      fsModule: fs,
      openclawDir: dir,
      log: { log: () => {} },
      env: { NEW_AUTH_TOKEN: "fixture-placeholder" },
      classifyEnv: () => ({ forwarded: true, rule: "test" }),
      getLaunchedEnvKeys: () => null,
    });
    const body = { revision: "absent", url: "https://mcp.example.test/mcp", headers: { Authorization: "Bearer ${NEW_AUTH_TOKEN}" } };
    const first = svc.setServer("svc", body);
    expect(first).toMatchObject({ changed: true, restartRequired: true, launchEnvUnknown: true });
    expect(first.warning).toMatch(/unknown/);
    const retry = svc.setServer("svc", body);
    expect(retry).toMatchObject({ changed: false, restartRequired: false, launchEnvUnknown: true });
    expect(retry).not.toHaveProperty("warning");
    const stored = JSON.parse(fs.readFileSync(configPath(dir), "utf8")).mcp.servers.svc;
    expect(svc.setServer("svc", { revision: entryRevision(stored), requestTimeoutMs: 5000 })).toMatchObject({ changed: true, restartRequired: false });
  });

  it("R4-6: a body the route refuses for its bounds resolves to write tier, and the manifest documents both codes", () => {
    const five = { "X-1": "${DOCS_AUTH_TOKEN}", "X-2": "${OTHER_AUTH_TOKEN}", "X-3": "${EXTRA_AUTH_TOKEN}", "X-4": "${ROTATED_AUTH_TOKEN}", "X-5": "${TENANT_AUTH_TOKEN}" };
    expect(tierFor({ headers: five })).toBe("write");
    expect(tierFor({ url: "https://n.example.test/mcp", headers: five }, undefined)).toBe("write");
    expect(tierFor({ headers: { "X-1": "${DOCS_AUTH_TOKEN}" } })).toBe("dangerous");
    const fields = manifest.findOp("PUT", "/api/mcp/servers/brain").params.fields;
    expect(fields.find((f) => f.name === "url").description).toContain("too_many_env_refs");
    expect(fields.find((f) => f.name === "headers").description).toContain("too_many_headers");
  });

  it("R4-7: a %-encoded ${VAR} in the path is shown decoded in the url piece", () => {
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: "https://h.example.test/%24%7BPATH_API_KEY%7D/mcp" } })).toBe(
      'server "s" NEW rev MISSING; url https://h.example.test/${PATH_API_KEY}~; SENDS no credential',
    );
  });
});

describe("round 5: revision binding, credential-shaped TLS/auth fields, config shape, merge, clip, keys (R5)", () => {
  const docs = { url: "https://good.example.test/mcp" };
  const tierAt = (dir) =>
    createServerSetTier({ readConfig: () => readConfig(dir) });
  const tierReq = (body, name = "docs") => ({ baseUrl: "/api", path: `/mcp/servers/${name}`, body });

  it("P1-a: list carries a stable 16-hex revision per entry", async () => {
    const dir = makeDir({ mcp: { servers: { docs, brain: baseEntry() } } });
    const res = await request(makeApp(dir).app).get("/api/mcp/servers");
    expect(res.body.servers.docs.revision).toBe(entryRevision(docs));
    expect(res.body.servers.brain.revision).toMatch(/^[0-9a-f]{16}$/);
    expect(entryRevision({ b: 2, a: { d: 1, c: [1, 2] } })).toBe(entryRevision({ a: { c: [1, 2], d: 1 }, b: 2 }));
    expect(entryRevision({ a: 1 })).not.toBe(entryRevision({ a: 2 }));
    expect(entryRevision(undefined)).toBe("absent");
  });

  it("P1-a: every set and every remove without revision is 400 revision_required; a bad one is 400 invalid_revision", async () => {
    const dir = makeDir({ mcp: { servers: { docs } } });
    const { app } = makeApp(dir);
    for (const body of [
      { url: "https://other.example.test/mcp" },
      { headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } },
      { toolFilter: null },
      { toolFilter: { include: ["*"] } },
      { transport: "sse" },
      { requestTimeoutMs: 5 },
    ]) {
      const res = await request(app).put("/api/mcp/servers/docs").send(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(res.body.code).toBe("revision_required");
      expect(tierAt(dir)(tierReq(body))).toBe("write");
    }
    expect((await request(app).put("/api/mcp/servers/new").send({ url: "https://n.example.test/mcp" })).body.code).toBe("revision_required");
    expect((await request(app).put("/api/mcp/servers/docs").send({ revision: "nope", url: "https://o.example.test/mcp" })).body.code).toBe("invalid_revision");
    const removed = await request(app).delete("/api/mcp/servers/docs");
    expect(removed.status).toBe(400);
    expect(removed.body.code).toBe("revision_required");
    expect(readConfig(dir).mcp.servers).toEqual({ docs });
  });

  it("P1-a: a filter-clear, transport or remove code minted before another write is refused (refuter pa.js)", async () => {
    vi.stubEnv("GBRAIN_X_AUTH_TOKEN", "fixture-placeholder");
    const entry = { url: "https://good.example.test/mcp", headers: { Authorization: "Bearer ${GBRAIN_X_AUTH_TOKEN}" }, toolFilter: { include: ["search"] } };
    const dir = makeDir({ mcp: { servers: { x: entry } } });
    const r0 = revOf(dir, "x");
    const { app } = makeApp(dir);
    const bUrl = { revision: r0, url: "https://other.example.test/mcp" };
    const bWide = { revision: r0, toolFilter: { include: null } };
    const bTr = { revision: r0, transport: "sse" };
    for (const body of [bUrl, bWide, bTr]) expect(tierAt(dir)(tierReq(body, "x"))).toBe("dangerous");
    const summary = createServerSetConfirmSummary({ readConfig: () => readConfig(dir) });
    expect(summary({ pathParams: { name: "x" }, body: bWide })).toContain(
      `rev ${r0.slice(0, 8)}; url unchanged https://good.example.test/mcp; SENDS \${GBRAIN_X_AUTH_TOKEN}; FILTER CLEARED`,
    );
    expect((await request(app).put("/api/mcp/servers/x").send(bUrl)).status).toBe(200);
    for (const body of [bWide, bTr]) {
      const res = await request(app).put("/api/mcp/servers/x").send(body);
      expect(res.status).toBe(409);
      expect(res.body.code).toBe("entry_changed");
    }
    // A remove code minted for the old entry cannot remove its replacement.
    const oldRemove = await request(app).delete("/api/mcp/servers/x").query({ revision: r0 });
    expect(oldRemove.status).toBe(409);
    expect(readConfig(dir).mcp.servers.x).toEqual({ ...entry, url: "https://other.example.test/mcp" });
  });

  it("P1-a: two codes minted against the same state cannot combine: the second redemption is 409 entry_changed", async () => {
    vi.stubEnv("GBRAIN_X_AUTH_TOKEN", "fixture-placeholder");
    const dir = makeDir({ mcp: { servers: { x: docs } } });
    const r0 = revOf(dir, "x");
    const b1 = { revision: r0, headers: { Authorization: "Bearer ${GBRAIN_X_AUTH_TOKEN}" } };
    const b2 = { revision: r0, url: "https://evil.example.test/mcp" };
    const tier = tierAt(dir);
    expect(tier(tierReq(b1, "x"))).toBe("dangerous");
    expect(tier(tierReq(b2, "x"))).toBe("dangerous");
    const summary = createServerSetConfirmSummary({ readConfig: () => readConfig(dir) });
    expect(summary({ pathParams: { name: "x" }, body: b2 })).toContain(`rev ${r0.slice(0, 8)}`);
    const { app } = makeApp(dir);
    expect((await request(app).put("/api/mcp/servers/x").send(withRev(b1, serversOf(dir)["x"]))).status).toBe(200);
    const second = await request(app).put("/api/mcp/servers/x").send(withRev(b2, serversOf(dir)["x"]));
    expect(second.status).toBe(409);
    expect(second.body.code).toBe("entry_changed");
    expect(second.body.currentRevision).toBe(revOf(dir, "x"));
    expect(readConfig(dir).mcp.servers.x.url).toBe("https://good.example.test/mcp");
    // After the first write the same body no longer summarises as bound.
    expect(summary({ pathParams: { name: "x" }, body: b2 })).toContain("rev STALE");
    expect(tierAt(dir)(tierReq(b2, "x"))).toBe("write");
  });

  it("P1-a: the entry changing between tier time and the write is caught under the lock (round-5 minor 1)", async () => {
    const dir = makeDir({ mcp: { servers: { docs } } });
    const body = { revision: revOf(dir, "docs"), headers: { "X-1": "${DOCS_AUTH_TOKEN}" } };
    expect(tierAt(dir)(tierReq(body))).toBe("dangerous"); // bounds pass at tier time
    // Another writer fills the entry before the redemption.
    const crowded = { ...docs, headers: { a: "${OTHER_AUTH_TOKEN}", b: "${EXTRA_AUTH_TOKEN}", c: "${ROTATED_AUTH_TOKEN}", d: "${TENANT_AUTH_TOKEN}" } };
    fs.writeFileSync(configPath(dir), JSON.stringify({ mcp: { servers: { docs: crowded } } }));
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send(withRev(body, serversOf(dir)["docs"]));
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("entry_changed");
    expect(readConfig(dir).mcp.servers.docs).toEqual(crowded);
  });

  it("P1-a: \"absent\" against an existing entry is 409; a stale retry that changes nothing is a no-op", async () => {
    const dir = makeDir({ mcp: { servers: { docs } } });
    const { app } = makeApp(dir);
    const clash = await request(app).put("/api/mcp/servers/docs").send({ revision: "absent", url: "https://o.example.test/mcp" });
    expect(clash.status).toBe(409);
    const create = { revision: "absent", url: "https://n.example.test/mcp" };
    expect((await request(app).put("/api/mcp/servers/fresh").send(withRev(create, serversOf(dir)["fresh"]))).status).toBe(201);
    const retry = await request(app).put("/api/mcp/servers/fresh").send(withRev(create, serversOf(dir)["fresh"]));
    expect(retry.status).toBe(200);
    expect(retry.body).toMatchObject({ changed: false, revision: revOf(dir, "fresh") });
  });

  it("P1-a: remove takes ?revision and answers 409 when the entry changed", async () => {
    const dir = makeDir({ mcp: { servers: { docs, other: docs } } });
    const { app } = makeApp(dir);
    const stale = await request(app).delete("/api/mcp/servers/docs").query({ revision: entryRevision({ url: "x" }) });
    expect(stale.status).toBe(409);
    expect(stale.body.currentRevision).toBe(revOf(dir, "docs"));
    expect((await request(app).delete("/api/mcp/servers/docs").query({ revision: "bad" })).body.code).toBe("invalid_revision");
    expect((await request(app).delete("/api/mcp/servers/docs").query({ revision: revOf(dir, "docs") })).status).toBe(200);
    expect((await request(app).delete("/api/mcp/servers/other").query({ revision: delRev(dir, "other") })).status).toBe(200);
    const remove = manifest.findOp("DELETE", "/api/mcp/servers/docs");
    expect(remove.params.fields.find((f) => f.name === "revision")).toMatchObject({ location: "query", required: true });
    expect(remove.params.fields.find((f) => f.name === "revision").description).toContain("revision_required");
    const set = manifest.findOp("PUT", "/api/mcp/servers/docs");
    const revField = set.params.fields.find((f) => f.name === "revision");
    expect(revField.required).toBe(true);
    expect(revField.description).toContain("revision_required");
    expect(revField.description).toContain("entry_changed");
  });

  it("P1-b: auth is shown only as \"oauth\", clientCert/clientKey only as plain absolute paths, and set cannot write any of them", async () => {
    // Fixture key material assembled at runtime; not a real key.
    const base64Line = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "BKcwggSjAgEAAoIBAQC7Vx3", "Yq9Lm2Pz"].join("");
    const pemOneLine = "-----BEGIN PRIVATE KEY-----\\nMIIfixture\\n-----END PRIVATE KEY-----";
    const secretPath = `/run/secrets/${"sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"}`;
    expect(redactMcpServerEntry({ auth: "oauth", clientCert: "/etc/mcp/client.crt", clientKey: "/run/secrets/mcp-client.key" })).toEqual({
      auth: "oauth",
      clientCert: "/etc/mcp/client.crt",
      clientKey: "/run/secrets/mcp-client.key",
    });
    for (const value of [
      base64Line,
      `/${base64Line}`,
      secretPath,
      // Low-entropy as a whole, credential-prefixed in one segment: only the
      // per-segment check catches it.
      `/srv/${"a".repeat(30)}/${"gh" + "p_"}x`,
      pemOneLine,
      "-----BEGIN PRIVATE KEY-----\nMIIfixture\n-----END PRIVATE KEY-----",
      "relative/client.key",
      "/etc/../root/client.key",
      `/${"a".repeat(1024)}`,
      "/etc/mcp/client key.pem",
      7,
    ]) {
      expect(redactMcpServerEntry({ clientKey: value }).clientKey, String(value).slice(0, 20)).toBe("<redacted>");
    }
    for (const auth of [kLiteralCore, "${DOCS_AUTH_TOKEN}", { token: kLiteralCore }, { ref: "${DOCS_AUTH_TOKEN}" }, ["oauth"], 5, null]) {
      const shown = JSON.stringify(redactMcpServerEntry({ auth }));
      expect(shown).toBe('{"auth":"<redacted>"}');
    }
    for (const key of ["auth", "clientCert", "clientKey"]) {
      expect(codeOf(() => parseServerPatch({ [key]: "/tmp/x" })), key).toBe("unknown_key");
    }
  });

  it("P2: a non-object mcp or mcp.servers is refused with 409 and the file is left unchanged", async () => {
    for (const config of [{ mcp: [] }, { mcp: "x" }, { mcp: null }, { mcp: { servers: [] } }, { mcp: { servers: "x" } }]) {
      const dir = makeDir(config);
      const before = fs.readFileSync(configPath(dir), "utf8");
      const { app } = makeApp(dir);
      const set = await request(app).put("/api/mcp/servers/docs").send({ revision: "absent", url: "https://n.example.test/mcp" });
      expect(set.status, JSON.stringify(config)).toBe(409);
      expect(set.body.code).toBe("OPENCLAW_CONFIG_UNEXPECTED_SHAPE");
      expect((await request(app).get("/api/mcp/servers")).status).toBe(409);
      expect((await request(app).delete("/api/mcp/servers/docs").query({ revision: delRev(dir, "docs") })).status).toBe(409);
      expect(fs.readFileSync(configPath(dir), "utf8")).toBe(before);
    }
  });

  it("m3: a patched header name replaces or removes every case spelling on disk", () => {
    const current = { headers: { Authorization: "Bearer ${DOCS_AUTH_TOKEN}", authorization: "Bearer ${OTHER_AUTH_TOKEN}" } };
    expect(applyServerPatch(current, { headers: { AUTHORIZATION: null, Authorization: "Bearer ${DOCS_AUTH_TOKEN}" } }).headers).toEqual({
      Authorization: "Bearer ${DOCS_AUTH_TOKEN}",
    });
    expect(applyServerPatch(current, { headers: { AUTHORIZATION: null } })).not.toHaveProperty("headers");
    expect(applyServerPatch(current, { headers: { "x-a": null, AUTHORIZATION: "Bearer ${EXTRA_AUTH_TOKEN}" } }).headers).toEqual({
      AUTHORIZATION: "Bearer ${EXTRA_AUTH_TOKEN}",
    });
  });

  it("m4: clipping never cuts a %XX escape, and a long TLD still shows the registrable label", () => {
    for (let pad = 0; pad < 6; pad += 1) {
      const host = `${"q".repeat(pad)}${"a!".repeat(30)}${"z".repeat(pad)}.com`;
      const summary = describeServerSet({ name: "s", current: undefined, patch: { url: `https://${host}/mcp` } });
      const shown = summary.match(/url https:\/\/(\S+?)\/mcp/)[1];
      expect(shown.replace(/%[0-9A-F]{2}/g, "")).not.toContain("%");
      // Clipped inside the registrable label, at a character or escape boundary
      // (the label is "a%21" units, so a cut escape would start with a digit).
      expect(shown).toMatch(/^~(?:[a-z]|%[0-9A-F]{2})/);
      expect(shown.endsWith(".com")).toBe(true);
    }
    expect(describeServerSet({ name: "s", current: undefined, patch: { url: `https://owned.${"t".repeat(50)}/mcp` } })).toContain(
      `url https://~owned.${"t".repeat(32)}~/mcp`,
    );
  });

  it("m5: a long plain-word key passes, a ${VAR} key is a reference counted in SENDS, credential-shaped keys still fail", () => {
    expect(parseServerPatch({ url: "https://x.example.test/mcp?includeDeprecatedEndpointsForCompatibility=1" }).url).toContain("include");
    const withRef = parseServerPatch({ url: "https://x.example.test/mcp?${DOCS_AUTH_TOKEN}" });
    expect(describeServerSet({ name: "s", current: undefined, patch: { ...withRef, revision: "absent" } })).toContain("SENDS ${DOCS_AUTH_TOKEN}");
    expect(redactMcpServerEntry({ url: withRef.url }).url).toContain("?${DOCS_AUTH_TOKEN}=");
    for (const key of ["QxZkLmPwRtYbNcVhJdFsAeGuKio", "abcdefghijklmnopqrstuvwxyzabcdefgh", "gh" + "p_" + "Q7xZ2kLm9PwR4tYb8NcV3hJd6FsA1eGu0Kio"]) {
      expect(codeOf(() => parseServerPatch({ url: `https://x.example.test/mcp?${key}=1` })), "key shape").toBe("literal_secret");
    }
  });
});

describe("round 6: word-key caps (R6 m4)", () => {
  const { looksLikeCredentialKey } = require("../../lib/server/mcp-servers");
  it("a word key is at most 48 characters with at most 2 words of 15+ letters; anything else gets the full check", () => {
    const w1 = "qwxzjkvbnmplrty";
    const w2 = "hgfdsazxcvbnmlk";
    const w3 = "poiuytrewqmnbvc";
    expect(looksLikeCredentialKey("includeDeprecatedEndpointsForCompatibility")).toBe(false); // 42 chars
    expect(looksLikeCredentialKey(`${w1}-${w2}`)).toBe(false); // two long words
    expect(looksLikeCredentialKey(`${w1}-${w2}-${w3}`)).toBe(true); // three long words: full check
    const long = "includeDeprecatedEndpointsForCompatibilityAndMore"; // 49 chars
    expect(long.length).toBeGreaterThan(48);
    expect(looksLikeCredentialKey(long)).toBe(true);
    expect(codeOf(() => parseServerPatch({ url: `https://x.example.test/mcp?${w1}-${w2}-${w3}=1` }))).toBe("literal_secret");
  });
});

describe("round 7: summaries survive secret redaction; strict list projection; remove summary (R7)", () => {
  const { buildAdminSkillContent } = require("../../lib/server/agent-admin/skill");
  const { createServerRemoveConfirmSummary } = require("../../lib/server/admin-manifest/domains/mcp");
  const { describeServerRemove } = require("../../lib/server/mcp-servers");
  // Credential-shaped fixtures are assembled at runtime; none is real.
  const ghToken = "gh" + "p_" + "Q7xZ2kLm9PwR4tYb8NcV3hJd6FsA1eGu0Kio";
  const setSummary = (stored, body) => {
    const op = {
      ...manifest.findOp("PUT", "/api/mcp/servers/brain"),
      confirmSummary: createServerSetConfirmSummary({ readConfig: () => ({ mcp: { servers: { brain: stored } } }) }),
    };
    return buildConfirmSummary(op, {
      method: "PUT",
      baseUrl: "/api",
      path: "/mcp/servers/brain",
      body: { revision: entryRevision(stored), ...body },
      query: {},
    });
  };
  const widenWithHeader = { toolFilter: { include: ["*"] }, headers: { "X-Other": "Bearer ${OTHER_AUTH_TOKEN}" } };
  const expectCriticalIntact = (summary, label) => {
    expect(summary, label).toContain("; SENDS ${GBRAIN_TEST_AUTH_TOKEN}, ${OTHER_AUTH_TOKEN}; FILTER WIDENED; GLOB IN FILTER; headers +1 -0");
    expect(summary.length, label).toBeLessThanOrEqual(400);
  };

  it("R7 major: a stored url with cookie: / set-cookie: keeps SENDS, FILTER WIDENED and GLOB through the full confirm pipeline", () => {
    for (const url of ["https://brain.example.test/cookie:/mcp", "https://brain.example.test/set-cookie:", "https://x.cookie:8443/mcp"]) {
      const stored = { url, headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" }, toolFilter: { include: ["search"] } };
      const summary = setSummary(stored, widenWithHeader);
      expectCriticalIntact(summary, url);
      expect(summary).not.toContain("***");
    }
  });

  it("R7 major: for every redactSecretShapes pattern, a url carrying its trigger does not truncate the critical part", () => {
    const triggers = {
      "provider key sk-": "https://h.example.test/a.sk-abcdefghijklmnop/mcp",
      bearer: "https://h.example.test/Bearer/abcdefghijklmnop",
      jwt: "https://h.example.test/eyJabcdefg.hijklmnop.qrstuvwxy",
      "google key": `https://h.example.test/AIza${"a".repeat(32)}`,
      "github token": `https://h.example.test/${ghToken}`,
      "slack token": "https://h.example.test/xoxb-abcdefghijkl",
      "aws key id": "https://h.example.test/AKIAABCDEFGHIJKLMNOP",
      "slack webhook": "https://hooks.slack.com/services/T000/B000/xyz",
      userinfo: "https://user:pw-fixture@h.example.test/mcp",
      cookie: "https://h.example.test/set-cookie:/mcp",
      "signed query": "https://h.example.test/mcp?token=abc&key=1",
    };
    // One trigger per pattern in lib/server/utils/redact.js: a new pattern
    // there fails this count until it gets a trigger here.
    const source = fs.readFileSync(path.join(__dirname, "../../lib/server/utils/redact.js"), "utf8");
    const block = source.slice(source.indexOf("const kSecretShapePatterns"), source.indexOf("const redactSecretShapes"));
    expect(Object.keys(triggers)).toHaveLength((block.match(/\bpattern:/g) || []).length);
    for (const [label, url] of Object.entries(triggers)) {
      const stored = { url, headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" }, toolFilter: { include: ["search"] } };
      expectCriticalIntact(setSummary(stored, widenWithHeader), label);
    }
  });

  it("R7 major: the escapes never lengthen the critical part past the IPv6 worst case", () => {
    const refs = ["R0_XY_AUTH_TOKEN", "R1_XY_AUTH_TOKEN", "R2_X_AUTH_TOKEN", "R3_X_AUTH_TOKEN"];
    for (const ref of refs) vi.stubEnv(ref, "fixture-placeholder");
    const literal = Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`L-${i}`, "plain"]));
    const current = { url: "http://x.example.test/mcp", toolFilter: { include: ["a"] }, headers: literal };
    const headers = {};
    for (let i = 0; i < 16; i += 1) headers[`X-${i}`] = `Bearer \${${refs[i % 4]}}`;
    for (let i = 0; i < 16; i += 1) headers[`L-${i}`] = null;
    const name = "n".repeat(64);
    for (const url of [
      `https://mcpserver.mcpserver.mcpserver.mcpserver.a-cookie:65535/cookie:${"a".repeat(45)}?q=1`,
      `https://hooks.slack.com/services/${"a".repeat(45)}?q=1`,
    ]) {
      const op = { ...manifest.findOp("PUT", `/api/mcp/servers/${name}`), confirmSummary: createServerSetConfirmSummary({ readConfig: () => ({ mcp: { servers: { [name]: current } } }) }) };
      const summary = buildConfirmSummary(op, {
        method: "PUT",
        baseUrl: "/api",
        path: `/mcp/servers/${name}`,
        body: { revision: entryRevision(current), url, transport: "streamable-http", toolFilter: { include: ["b*"], exclude: ["c"] }, headers },
        query: {},
      });
      const mark = "headers +16 -16";
      expect(summary, url).toContain(mark);
      expect(summary.indexOf(mark) + mark.length, url).toBeLessThanOrEqual(398);
      for (const ref of refs) expect(summary).toContain(`\${${ref}}`);
    }
  });

  it("R7 m2: a non-http(s) stored scheme renders as other: and cannot overflow the clamp", () => {
    const stored = { url: `${"x".repeat(300)}://h.example.test/mcp`, headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" }, toolFilter: { include: ["search"] } };
    const summary = setSummary(stored, widenWithHeader);
    expect(summary).toContain("url unchanged other://h.example.test/mcp; SENDS");
    expectCriticalIntact(summary, "long scheme");
    const moved = setSummary({ url: `${"y".repeat(200)}://h.example.test/mcp` }, { url: "https://h.example.test/mcp" });
    expect(moved).toContain("url https://h.example.test/mcp (was other); SENDS no credential");
  });

  it("R7 m3: ordinary absolute cert and key paths are shown; only segments are credential-checked", () => {
    for (const p of ["/data/.openclaw/certs/client.pem", "/var/lib/openclaw/mcp/gbrain.client.crt", "/data/certs/mtls-client-2026-09-01.crt"]) {
      expect(redactMcpServerEntry({ clientCert: p, clientKey: p })).toEqual({ clientCert: p, clientKey: p });
    }
    expect(redactMcpServerEntry({ clientKey: `/data/certs/${ghToken}` }).clientKey).toBe("<redacted>");
  });

  it("codex P1: list projection shows schema-typed values only, and unknown keys as a count", () => {
    const sk = "sk" + "-live-" + "a1B2c3D4e5F6g7H8i9J0";
    const out = redactMcpServerEntry({
      url: "https://h.example.test/mcp",
      enabled: ghToken,
      supportsParallelToolCalls: true,
      sslVerify: "false",
      connectionTimeoutMs: ghToken,
      requestTimeoutMs: 30000,
      transport: sk,
      cwd: `/home/svc/${ghToken}`,
      oauth: { identity: ghToken, authProfileId: ghToken, scope: `docs.read ${ghToken}`, redirectUrl: "https://h.example.test/cb", [ghToken]: 1 },
      toolFilter: { include: ["search", ghToken], exclude: ghToken, [sk]: ["x"] },
      codex: { agents: ["tiflis", sk], defaultToolsApprovalMode: ghToken, [ghToken]: true },
      headers: { [ghToken]: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}", "X-Ok": "${OTHER_AUTH_TOKEN}" },
      env: { [sk]: "x" },
      [ghToken]: "unknown key named like a token",
      another: 1,
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(ghToken);
    expect(text).not.toContain(sk);
    expect(out).toMatchObject({
      enabled: "<redacted>",
      supportsParallelToolCalls: true,
      sslVerify: "<redacted>",
      connectionTimeoutMs: "<redacted>",
      requestTimeoutMs: 30000,
      transport: "<redacted>",
      cwd: "<redacted>",
      oauth: { identity: "<redacted>", authProfileId: "<redacted>", scope: "<redacted>", redirectUrl: "https://h.example.test/cb", otherKeys: 1 },
      toolFilter: { include: ["search", "<redacted>"], exclude: "<redacted>", otherKeys: 1 },
      codex: { agents: ["tiflis", "<redacted>"], defaultToolsApprovalMode: "<redacted>", otherKeys: 1 },
      headers: { "<redacted-1>": "Bearer ${GBRAIN_TEST_AUTH_TOKEN}", "X-Ok": "${OTHER_AUTH_TOKEN}" },
      env: { "<redacted-1>": "<literal>" },
      otherKeys: 2,
    });
    expect(redactMcpServerEntry({ cwd: "/srv/mcp", oauth: { identity: "shared", scope: "docs.read docs.write" }, transport: "stdio" })).toEqual({
      cwd: "/srv/mcp",
      oauth: { identity: "shared", scope: "docs.read docs.write" },
      transport: "stdio",
    });
  });

  it("codex P1: the remove summary names the entry's url and what it sends, or that it is not found", () => {
    const stored = { url: "https://brain.example.test/mcp", headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}", "X-Raw": kLiteralCore } };
    const rev = entryRevision(stored);
    const op = {
      ...manifest.findOp("DELETE", "/api/mcp/servers/brain"),
      confirmSummary: createServerRemoveConfirmSummary({ readConfig: () => ({ mcp: { servers: { brain: stored } } }) }),
    };
    const remove = (name, query) => buildConfirmSummary(op, { method: "DELETE", baseUrl: "/api", path: `/mcp/servers/${name}`, body: null, query });
    expect(remove("brain", { revision: rev })).toBe(
      `Remove an MCP server: server "brain" REMOVE rev ${rev.slice(0, 8)}; url https://brain.example.test/mcp; SENDS \${GBRAIN_TEST_AUTH_TOKEN}, 1 literal header`,
    );
    expect(remove("brain", { revision: "0000000000000000" })).toContain("REMOVE rev STALE; url https://brain.example.test/mcp");
    expect(remove("brain", {})).toContain("REMOVE rev MISSING");
    expect(remove("nope", { revision: rev })).toBe('Remove an MCP server: server "nope" not found');
    expect(remove("brain", { revision: rev })).not.toContain(kLiteralCore);
    // Worst case: 64-char name, IPv6 host with port, clipped path, refs at
    // the 80-character bound, 32 literal headers.
    const refs = ["R0_XY_AUTH_TOKEN", "R1_XY_AUTH_TOKEN", "R2_X_AUTH_TOKEN", "R3_X_AUTH_TOKEN"];
    const big = {
      url: `https://[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/${"a".repeat(45)}?q=1`,
      headers: {
        ...Object.fromEntries(refs.map((r, i) => [`X-${i}`, `Bearer \${${r}}`])),
        ...Object.fromEntries(Array.from({ length: 28 }, (_, i) => [`L-${i}`, "plain"])),
      },
    };
    const worst = describeServerRemove({ name: "n".repeat(64), current: big, revision: entryRevision(big) });
    const full = `Remove an MCP server: ${worst}`;
    expect(full.length).toBeLessThanOrEqual(400);
    for (const r of refs) expect(full).toContain(`\${${r}}`);
    expect(full).toContain("28 literal headers");
  });

  it("R7 m4: the skill table tells agents to send revision on set and ?revision= on remove", () => {
    const content = buildAdminSkillContent({ fs, manifest: manifest.getManifest(), liveState: { adminTargets: [], activeChannels: [], releaseChannel: "stable" } });
    const setRow = content.split("\n").find((line) => line.includes("PUT /api/mcp/servers/:name"));
    const removeRow = content.split("\n").find((line) => line.includes("DELETE /api/mcp/servers/:name"));
    expect(setRow).toContain('Body needs "revision"');
    expect(removeRow).toContain("?revision=<rev>");
  });
});

describe("round 8: one tool-name rule, merged-entry checks, safe server names (R8)", () => {
  const { isAcceptableToolName } = require("../../lib/server/mcp-servers");
  const ghToken = "gh" + "p_" + "Q7xZ2kLm9PwR4tYb8NcV3hJd6FsA1eGu0Kio";
  const legitNames = [
    "listRepositories2",
    "getIssueComments2",
    "searchCodebaseV2",
    "createPullRequest2",
    "route53ListZones",
    "ec2DescribeInstances",
    "ListObjectsV2Command",
    "listRepositoriesV3",
  ];

  it("R8 major: set and list share one tool-name rule; real names pass both, <redacted> and credential shapes fail both", () => {
    const patch = parseServerPatch({ toolFilter: { include: legitNames } });
    expect(patch.toolFilter.include).toEqual(legitNames);
    expect(redactMcpServerEntry({ toolFilter: { include: legitNames } }).toolFilter.include).toEqual(legitNames);
    const summary = describeServerSet({ name: "s", current: { url: "https://h.example.test/mcp" }, patch: { toolFilter: { include: legitNames.slice(0, 3) } } });
    expect(summary).toContain('["listRepositories2", "getIssueComments2", "searchCodebaseV2"]');
    for (const bad of ["<redacted>", ghToken, "3f2b8c1e-9d4a-4e7b-a6c5-1b2d3e4f5a6b", "a b", "x".repeat(129)]) {
      expect(isAcceptableToolName(bad), bad.slice(0, 12)).toBe(false);
      expect(codeOf(() => parseServerPatch({ toolFilter: { include: [bad] } }))).toBe("invalid_tool_filter");
    }
    expect(isAcceptableToolName("get_*")).toBe(true);
  });

  it("R8 major: rewriting a list that holds a hidden stored name is 409 filter_has_hidden_items; clearing it or a timeout change is allowed", async () => {
    const stored = { url: "https://h.example.test/mcp", toolFilter: { include: ["search", ghToken] } };
    const dir = makeDir({ mcp: { servers: { docs: stored } } });
    const { app } = makeApp(dir);
    expect(redactMcpServerEntry(stored).toolFilter.include).toEqual(["search", "<redacted>"]);
    const narrow = { revision: revOf(dir, "docs"), toolFilter: { include: ["search"] } };
    expect(createServerSetTier({ readConfig: () => readConfig(dir) })({ baseUrl: "/api", path: "/mcp/servers/docs", body: narrow })).toBe("write");
    // A widening rewrite would be dangerous; the route refuses it (409), so write.
    const widen = { revision: revOf(dir, "docs"), toolFilter: { include: ["search", "put_page"] } };
    expect(createServerSetTier({ readConfig: () => readConfig(dir) })({ baseUrl: "/api", path: "/mcp/servers/docs", body: widen })).toBe("write");
    expect((await request(app).put("/api/mcp/servers/docs").send(widen)).body.code).toBe("filter_has_hidden_items");
    const res = await request(app).put("/api/mcp/servers/docs").send(narrow);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("filter_has_hidden_items");
    expect(res.text).not.toContain(ghToken);
    expect(readConfig(dir).mcp.servers.docs).toEqual(stored);
    expect((await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), requestTimeoutMs: 5 })).status).toBe(200);
    expect((await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), toolFilter: { include: null } })).status).toBe(200);
    expect(readConfig(dir).mcp.servers.docs).not.toHaveProperty("toolFilter");
  });

  it("R8 minor: a tool name with cookie: cannot eat the summary tail", () => {
    const stored = { url: "https://h.example.test/mcp", headers: { Authorization: "Bearer ${GBRAIN_TEST_AUTH_TOKEN}" } };
    const op = {
      ...manifest.findOp("PUT", "/api/mcp/servers/docs"),
      confirmSummary: createServerSetConfirmSummary({ readConfig: () => ({ mcp: { servers: { docs: stored } } }) }),
    };
    const summary = buildConfirmSummary(op, {
      method: "PUT",
      baseUrl: "/api",
      path: "/mcp/servers/docs",
      body: { revision: entryRevision(stored), toolFilter: { include: ["cookie:x", "set-cookie:y"] }, headers: { "X-Other": "Bearer ${OTHER_AUTH_TOKEN}" } },
      query: {},
    });
    expect(summary).toContain('include +2 ("cookie%3Ax", "set-cookie%3Ay")');
    expect(summary).toContain("; set X-Other=Bearer ${OTHER_AUTH_TOKEN}");
    expect(summary).not.toContain("***");
  });

  it("codex P1-a: list shows only valid, non-credential server names; others are <redacted-N> with their revision", async () => {
    const entry = { url: "https://h.example.test/mcp" };
    const dir = makeDir({ mcp: { servers: { good: entry, [ghToken]: entry, "bad name": { url: "https://b.example.test/mcp" } } } });
    const { app } = makeApp(dir);
    const res = await request(app).get("/api/mcp/servers");
    expect(res.text).not.toContain(ghToken);
    expect(res.text).not.toContain("bad name");
    expect(res.body.names).toHaveLength(3);
    expect(res.body.names).toContain("good");
    expect(res.body.names.filter((n) => /^<redacted-\d>$/.test(n))).toHaveLength(2);
    expect(Object.keys(res.body.servers).sort()).toEqual([...res.body.names].sort());
    const hiddenRevs = res.body.names.filter((n) => n.startsWith("<")).map((n) => res.body.servers[n].revision).sort();
    expect(hiddenRevs).toEqual([entryRevision(entry), entryRevision({ url: "https://b.example.test/mcp" })].sort());
    // The shown placeholder is not an addressable name, and a new
    // credential-shaped name is refused.
    expect((await request(app).delete("/api/mcp/servers/%3Credacted-1%3E").query({ revision: entryRevision(entry) })).body.code).toBe("invalid_name");
    const created = await request(app).put(`/api/mcp/servers/${"gh" + "p_" + "Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gFeDcBa"}`).send({ revision: "absent", url: "https://n.example.test/mcp" });
    expect(created.status).toBe(400);
    expect(created.body.code).toBe("invalid_name");
  });

  it("codex P1-b: a url or headers change validates the merged entry; values from disk are refused with field existing", async () => {
    const cases = [
      [{ url: "https://h.example.test/mcp", headers: { Authorization: "Bearer ${OPENCLAW_GATEWAY_TOKEN}" } }, { url: "https://new.example.test/mcp" }, "env_reserved"],
      [{ url: "https://h.example.test/mcp", headers: { "X-Key": kLiteralCore } }, { url: "https://new.example.test/mcp" }, "literal_secret"],
      [{ url: "https://h.example.test/mcp", headers: { "X-Key": "${FOO_BAR_NOT_FORWARDED}" } }, { headers: { "X-New": "${DOCS_AUTH_TOKEN}" } }, "env_not_forwarded"],
      [{ url: "https://h.example.test/mcp?token=plainvalue" }, { headers: { "X-New": "${DOCS_AUTH_TOKEN}" } }, "literal_secret"],
    ];
    for (const [stored, patch, code] of cases) {
      const dir = makeDir({ mcp: { servers: { docs: stored } } });
      const { app } = makeApp(dir);
      const body = { revision: revOf(dir, "docs"), ...patch };
      expect(createServerSetTier({ readConfig: () => readConfig(dir) })({ baseUrl: "/api", path: "/mcp/servers/docs", body }), code).toBe("write");
      const res = await request(app).put("/api/mcp/servers/docs").send(body);
      expect(res.status, code).toBe(400);
      expect(res.body.code).toBe(code);
      expect(res.body.field).toBe("existing");
      expect(res.text).not.toContain(kLiteralCore);
      expect(res.text).not.toContain("plainvalue");
      expect(readConfig(dir).mcp.servers.docs).toEqual(stored);
      // Round 10: the merged check runs on every set, so a timeout change on
      // the same entry is refused too (same code, field existing).
      const timeout = await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), requestTimeoutMs: 5 });
      expect(timeout.body).toMatchObject({ code, field: "existing" });
    }
    // A value the patch itself brings is refused without field.
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://h.example.test/mcp" } } } });
    const own = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { "X-Key": "Bearer ${OPENCLAW_GATEWAY_TOKEN}" } });
    expect(own.body.code).toBe("env_reserved");
    expect(own.body).not.toHaveProperty("field");
  });
});

describe("round 9: token-shape names, bounds on every set, repeated decoding (R9)", () => {
  const { looksLikeTokenName, isAcceptableToolName } = require("../../lib/server/mcp-servers");
  // Token-shaped fixtures are assembled at runtime; none is real.
  const liveKey = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
  const uuid = "3f2b8c1e-9d4a-4e7b-a6c5-1b2d3e4f5a6b";

  it("R9 1+2: one token-shape rule for server and tool names", async () => {
    const serverNames = [
      "gbrain-acmeholdings2026",
      "gbrain-northwind2025corp",
      "gbrain-dispatcher-simlinks-knowledge",
      "github-enterprise-cloud-production",
      "pk-db",
      "sk_internal",
    ];
    const dir = makeDir({ mcp: { servers: {} } });
    const { app } = makeApp(dir);
    for (const name of serverNames) {
      expect(looksLikeTokenName(name), name).toBe(false);
      const res = await request(app).put(`/api/mcp/servers/${name}`).send({ revision: "absent", url: "https://h.example.test/mcp" });
      expect(res.status, name).toBe(201);
    }
    const listed = await request(app).get("/api/mcp/servers");
    expect(listed.body.names).toEqual([...serverNames].sort());
    for (const tool of ["hf_fs", "hf_whoami", "hf_*", "npm_search", "sk_list_tables"]) {
      expect(isAcceptableToolName(tool), tool).toBe(true);
      expect(parseServerPatch({ toolFilter: { include: [tool] } }).toolFilter.include).toEqual([tool]);
      expect(redactMcpServerEntry({ toolFilter: { include: [tool] } }).toolFilter.include).toEqual([tool]);
    }
    for (const token of [liveKey, uuid]) {
      expect(looksLikeTokenName(token)).toBe(true);
      expect(codeOf(() => parseServerPatch({ toolFilter: { include: [token] } }))).toBe("invalid_tool_filter");
      expect(redactMcpServerEntry({ toolFilter: { include: [token] } }).toolFilter.include).toEqual(["<redacted>"]);
    }
    const created = await request(app).put(`/api/mcp/servers/${liveKey}`).send({ revision: "absent", url: "https://h.example.test/mcp" });
    expect(created.body.code).toBe("invalid_name");
  });

  it("R9 m4: a create the route refuses for its token-shaped name is write tier", () => {
    const tier = createServerSetTier({ readConfig: () => ({ mcp: { servers: {} } }) });
    expect(tier({ baseUrl: "/api", path: `/mcp/servers/${liveKey}`, body: { revision: "absent", url: "https://h.example.test/mcp" } })).toBe("write");
    expect(tier({ baseUrl: "/api", path: "/mcp/servers/sk_internal", body: { revision: "absent", url: "https://h.example.test/mcp" } })).toBe("dangerous");
  });

  it("R9 m3: hidden names come after the visible ones, numbered by revision, so their position leaks nothing", async () => {
    const tokenA = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const tokenB = "sk-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1";
    const entryA = { url: "https://a.example.test/mcp" };
    const entryB = { url: "https://b.example.test/mcp" };
    const byRev = [[tokenA, entryA], [tokenB, entryB]].sort(([, x], [, y]) => (entryRevision(x) < entryRevision(y) ? -1 : 1));
    for (const order of [[tokenA, tokenB], [tokenB, tokenA]]) {
      const servers = { zulu: entryA, alpha: entryA, mango: entryA };
      for (const name of order) servers[name] = name === tokenA ? entryA : entryB;
      const dir = makeDir({ mcp: { servers } });
      const res = await request(makeApp(dir).app).get("/api/mcp/servers");
      expect(res.body.names).toEqual(["alpha", "mango", "zulu", "<redacted-1>", "<redacted-2>"]);
      expect(res.body.servers["<redacted-1>"].revision).toBe(entryRevision(byRev[0][1]));
      expect(res.body.servers["<redacted-2>"].revision).toBe(entryRevision(byRev[1][1]));
    }
  });

  it("codex P1: the bounds hold on every set; a stored over-limit entry is refused with field existing", async () => {
    const refsOver = { a: "${DOCS_AUTH_TOKEN}", b: "${OTHER_AUTH_TOKEN}", c: "${EXTRA_AUTH_TOKEN}", d: "${ROTATED_AUTH_TOKEN}", e: "${TENANT_AUTH_TOKEN}" };
    const many = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`X-${i}`, "${DOCS_AUTH_TOKEN}"]));
    for (const [stored, code] of [
      [{ url: "https://h.example.test/mcp", headers: refsOver, toolFilter: { include: ["a", "b"] } }, "too_many_env_refs"],
      [{ url: "https://h.example.test/mcp", headers: many, toolFilter: { include: ["a", "b"] } }, "too_many_headers"],
    ]) {
      const dir = makeDir({ mcp: { servers: { docs: stored } } });
      const { app } = makeApp(dir);
      for (const patch of [{ transport: "sse" }, { toolFilter: { include: ["a"] } }, { requestTimeoutMs: 5 }]) {
        const body = { revision: revOf(dir, "docs"), ...patch };
        expect(createServerSetTier({ readConfig: () => readConfig(dir) })({ baseUrl: "/api", path: "/mcp/servers/docs", body }), code).toBe("write");
        const res = await request(app).put("/api/mcp/servers/docs").send(body);
        expect(res.status, `${code} ${JSON.stringify(patch)}`).toBe(400);
        expect(res.body.code).toBe(code);
        expect(res.body.field).toBe("existing");
        expect(res.body.hint).toMatch(/operator must fix openclaw\.json/);
      }
      expect(readConfig(dir).mcp.servers.docs).toEqual(stored);
    }
    // A patch that brings the entry back within the bounds passes.
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://h.example.test/mcp", headers: refsOver } } } });
    const fix = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { d: null, e: null } });
    expect(fix.status).toBe(200);
  });

  it("codex P1: 1x, 2x and 3x percent-encoded tokens in path, query key and query value are refused and redacted", () => {
    const enc = (text, times) => {
      let out = text.replace(/^s/, "%73");
      for (let i = 1; i < times; i += 1) out = out.replace(/%/g, "%25");
      return out;
    };
    // Low-entropy body, so only the decoded "sk_" prefix makes it a
    // credential: a check on fewer decode rounds misses it.
    const plainToken = "sk_" + "abcdefghijklmnop";
    expect(looksLikeCredential(plainToken)).toBe(true);
    for (const notYet of ["%73k_abcdefghijklmnop", "%2573k_abcdefghijklmnop", "%252573k_abcdefghijklmnop"]) {
      expect(looksLikeCredential(notYet), notYet).toBe(false);
    }
    const body = plainToken.slice(3);
    for (const times of [1, 2, 3]) {
      const token = enc(plainToken, times);
      for (const url of [
        `https://h.example.test/${token}/mcp`,
        `https://h.example.test/mcp?${token}=1`,
        `https://h.example.test/mcp?q=${token}`,
        `https://h.example.test/mcp;${token}=1`,
      ]) {
        expect(codeOf(() => parseServerPatch({ url })), `${times}x ${url}`).toBe("literal_secret");
        const shown = redactMcpServerEntry({ url }).url;
        expect(shown, `${times}x list ${url}`).not.toContain(body);
        const summary = describeServerSet({ name: "s", current: { url }, patch: { revision: entryRevision({ url }), requestTimeoutMs: 1 } });
        expect(summary, `${times}x summary ${url}`).not.toContain(body.slice(0, 8));
      }
    }
    // Malformed % stays as is and an ordinary encoded path is unaffected.
    expect(parseServerPatch({ url: "https://h.example.test/a%ZZb/mcp" }).url).toBe("https://h.example.test/a%ZZb/mcp");
    expect(parseServerPatch({ url: "https://h.example.test/my%2520docs/mcp" }).url).toBe("https://h.example.test/my%2520docs/mcp");
  });
});

describe("url components encoded deeper than three levels", () => {
  const { encodedTooDeep } = require("../../lib/server/mcp-servers");
  const enc = (text, times) => {
    let out = text.replace(/^s/, "%73");
    for (let i = 1; i < times; i += 1) out = out.replace(/%/g, "%25");
    return out;
  };
  // Low-entropy fixture; not a real token.
  const token = "sk_" + "abcdefghijklmnop";

  it("refuses a 4x-encoded component (400 invalid_url) and hides it when stored; 3 levels and malformed % stay as before", () => {
    const four = enc(token, 4);
    expect(encodedTooDeep(four)).toBe(true);
    expect(encodedTooDeep(enc(token, 3))).toBe(false);
    for (const url of [
      `https://h.example.test/${four}/mcp`,
      `https://h.example.test/mcp?${four}=1`,
      `https://h.example.test/mcp?q=${four}`,
      `https://h.example.test/mcp;${four}=1`,
      `https://h.example.test/mcp;k=${four}`,
    ]) {
      let error;
      try {
        parseServerPatch({ url });
      } catch (err) {
        error = err;
      }
      expect(error?.code, url).toBe("invalid_url");
      expect(error.hint).toBe("percent-encoded more than 3 levels");
      const shown = redactMcpServerEntry({ url }).url;
      expect(shown, url).not.toContain("abcdefgh");
      expect(shown).not.toContain(four);
      expect(describeServerSet({ name: "s", current: { url }, patch: { revision: entryRevision({ url }), requestTimeoutMs: 1 } })).not.toContain("abcdefgh");
    }
    // Deeper still: a stored 5x-encoded query key is hidden by the depth rule
    // alone (the credential check stops at three levels).
    const fiveKey = `https://h.example.test/mcp?${enc(token, 5)}=1`;
    expect(redactMcpServerEntry({ url: fiveKey }).url).toBe("https://h.example.test/mcp?<redacted>=<redacted>");
    expect(codeOf(() => parseServerPatch({ url: `https://h.example.test/${enc(token, 3)}/mcp` }))).toBe("literal_secret");
    for (const url of ["https://h.example.test/a%ZZb/mcp", "https://h.example.test/my%2520docs/mcp"]) {
      expect(parseServerPatch({ url }).url).toBe(url);
    }
    expect(redactMcpServerEntry({ url: "https://h.example.test/my%2520docs/mcp" }).url).toBe("https://h.example.test/my%2520docs/mcp");
  });
});

describe("round 10: decoded url forms only; retained refs on every set; safe header names in errors (R10)", () => {
  const { looksLikeTokenName, assertMergedEntryValid } = require("../../lib/server/mcp-servers");

  it("R10 major: an ordinary percent-encoded path is judged by its decoded text only", () => {
    for (const url of ["https://example.com/files/report%202026%20Q3.pdf", "https://example.com/my%20docs%202026/mcp"]) {
      expect(parseServerPatch({ url }).url).toBe(url);
      expect(redactMcpServerEntry({ url }).url).toBe(url);
    }
    // Raw-form skipping, pinned: this raw text is flagged on its own (whole
    // string, high entropy of the %XX runs) while its decoded text is not.
    const raw = "report%202026%20Q3.pdf";
    expect(looksLikeCredential(raw)).toBe(true);
    expect(looksLikeCredential(decodeURIComponent(raw))).toBe(false);
    expect(parseServerPatch({ url: `https://example.com/${raw}/mcp` }).url).toBe(`https://example.com/${raw}/mcp`);
    // An encoded token is still refused through its decoded form.
    const tokenEnc = ("sk_" + "live_" + "Ab12Cd34Ef56Gh78Ij90Kl12").split("").map((c) => `%${c.charCodeAt(0).toString(16)}`).join("");
    expect(codeOf(() => parseServerPatch({ url: `https://example.com/${tokenEnc}/mcp` }))).toBe("literal_secret");
  });

  it("R10 m2+m3: gbrain_ and pa- are token prefixes, and the body threshold is 20", () => {
    for (const token of ["gbrain_" + "a1B2c3D4e5F6g7H8i9J0k1", "pa-" + "a1B2c3D4e5F6g7H8i9J0k1"]) {
      expect(looksLikeTokenName(token)).toBe(true);
      expect(codeOf(() => parseServerPatch({ toolFilter: { include: [token] } }))).toBe("invalid_tool_filter");
    }
    for (const name of ["sk_" + "a1b2c3d4e5f6g7h8i9", "gbrain_" + "abcdefghij", "pa-" + "abcdefghijklmno"]) {
      expect(looksLikeTokenName(name), name).toBe(false);
      expect(parseServerPatch({ toolFilter: { include: [name] } }).toolFilter.include).toEqual([name]);
    }
    expect(looksLikeTokenName("sk_" + "a1b2c3d4e5f6g7h8i9j0")).toBe(true);
  });

  it("codex P1-1: a stored bad header blocks every change except one that removes it", async () => {
    const stored = { url: "https://h.example.test/mcp", headers: { Authorization: "Bearer ${OPENCLAW_GATEWAY_TOKEN}" }, toolFilter: { include: ["a", "b"] } };
    const dir = makeDir({ mcp: { servers: { docs: stored } } });
    const { app } = makeApp(dir);
    for (const patch of [{ requestTimeoutMs: 5 }, { toolFilter: { include: ["a"] } }, { transport: "sse" }]) {
      const body = { revision: revOf(dir, "docs"), ...patch };
      expect(createServerSetTier({ readConfig: () => readConfig(dir) })({ baseUrl: "/api", path: "/mcp/servers/docs", body })).toBe("write");
      const res = await request(app).put("/api/mcp/servers/docs").send(body);
      expect(res.body).toMatchObject({ code: "env_reserved", field: "existing" });
    }
    expect(readConfig(dir).mcp.servers.docs).toEqual(stored);
    const fix = await request(app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), headers: { Authorization: null } });
    expect(fix.status).toBe(200);
  });

  it("codex P1-2: a retained reference is checked against the env like a patch reference, except env_not_set with the launch env unknown", async () => {
    const stored = { url: "https://h.example.test/mcp", headers: { Authorization: "Bearer ${UNSET_RETAINED_AUTH_TOKEN}" } };
    // Launch env known: an unset retained var is env_not_set, field existing.
    const known = makeDir({ mcp: { servers: { docs: stored } } });
    const knownApp = makeApp(known, { getLaunchedEnvKeys: () => new Set(["PATH"]) }).app;
    const refused = await request(knownApp).put("/api/mcp/servers/docs").send({ revision: revOf(known, "docs"), requestTimeoutMs: 5 });
    expect(refused.body).toMatchObject({ code: "env_not_set", field: "existing" });
    // Launch env unknown: not refused for env_not_set; the response says so.
    const unknown = makeDir({ mcp: { servers: { docs: stored } } });
    const unknownApp = makeApp(unknown, { getLaunchedEnvKeys: () => null }).app;
    const passed = await request(unknownApp).put("/api/mcp/servers/docs").send({ revision: revOf(unknown, "docs"), requestTimeoutMs: 5 });
    expect(passed.status).toBe(200);
    expect(passed.body.launchEnvUnknown).toBe(true);
    // A retained var that is not forwarded is refused either way.
    expect(() =>
      assertMergedEntryValid({ url: "https://h.example.test/mcp", headers: { A: "${FOO_NOT_FORWARDED}" } }, { requestTimeoutMs: 1 }, { launchEnvKnown: false }),
    ).toThrow(expect.objectContaining({ code: "env_not_forwarded", field: "existing" }));
  });

  it("codex P1-3: errors and confirm detail never echo an unsafe stored header name", async () => {
    const tokenHeader = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3";
    const dir = makeDir({ mcp: { servers: { docs: { url: "https://h.example.test/mcp", headers: { [tokenHeader]: kLiteralCore } } } } });
    const res = await request(makeApp(dir).app).put("/api/mcp/servers/docs").send({ revision: revOf(dir, "docs"), requestTimeoutMs: 5 });
    expect(res.body).toMatchObject({ code: "literal_secret", field: "existing" });
    expect(res.text).not.toContain(tokenHeader);
    expect(res.text).not.toContain(kLiteralCore);
    expect(res.body.error).toContain('"<redacted-1>"');
    const summary = describeServerSet({
      name: "docs",
      current: { url: "https://h.example.test/mcp", headers: { [tokenHeader]: "${DOCS_AUTH_TOKEN}" } },
      patch: { headers: { [tokenHeader]: null, "X-Ok": "${DOCS_AUTH_TOKEN}" } },
    });
    expect(summary).not.toContain(tokenHeader);
    expect(summary).toContain("set X-Ok=${DOCS_AUTH_TOKEN}; removed <redacted-2>");
  });
});

describe("tolerant percent-decoding around malformed escapes", () => {
  const { safeDecode, encodedTooDeep } = require("../../lib/server/mcp-servers");

  it("decodes every valid escape, keeps malformed % and invalid UTF-8 bytes as they are", () => {
    expect(safeDecode("%61%70%69%5F%6B%65%79%ZZ")).toBe("api_key%ZZ");
    expect(safeDecode("a%ZZb")).toBe("a%ZZb");
    expect(safeDecode("%E2%82%AC%ZZ")).toBe("€%ZZ");
    expect(safeDecode("%F0%9F%98%80x%Z")).toBe("\u{1F600}x%Z");
    expect(safeDecode("%61%FF%62%")).toBe("a%FFb%");
    expect(safeDecode("%E2%82")).toBe("%E2%82");
    expect(encodedTooDeep("a%ZZb")).toBe(false);
  });

  it("a sensitive key hidden behind a malformed escape is judged like the plain key", () => {
    expect(codeOf(() => parseServerPatch({ url: "https://example.com/mcp?api_key=v" }))).toBe("literal_secret");
    expect(codeOf(() => parseServerPatch({ url: "https://example.com/mcp?%61%70%69%5F%6B%65%79%ZZ=v" }))).toBe("literal_secret");
    // A token prefix hidden by one escape next to a malformed one, in a path
    // segment (no URLSearchParams decoding there): only the tolerant decoder
    // sees "sk_".
    const hidden = "%73k_" + "abcdefghijklmnop" + "%ZZ";
    expect(looksLikeCredential(hidden)).toBe(false);
    expect(codeOf(() => parseServerPatch({ url: `https://example.com/${hidden}/mcp` }))).toBe("literal_secret");
    expect(redactMcpServerEntry({ url: `https://example.com/${hidden}/mcp` }).url).toBe("https://example.com/<redacted>/mcp");
    for (const url of [
      "https://h.example.test/a%ZZb/mcp",
      "https://h.example.test/my%2520docs/mcp",
      "https://example.com/files/report%202026%20Q3.pdf",
      "https://example.com/%E2%82%AC/mcp",
      "https://example.com/mcp?u=%F0%9F%98%80",
      "https://example.com/%E2%82%25/mcp",
    ]) {
      expect(parseServerPatch({ url }).url, url).toBe(url);
    }
  });
});
