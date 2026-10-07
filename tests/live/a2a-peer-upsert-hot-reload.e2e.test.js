const fs = require("fs");
const net = require("net");
const path = require("path");
const {
  kLiveEnabled,
  mkTemp,
  repoOpenclawBin,
  scrubTestRunnerEnv,
  waitFor,
} = require("./live-helpers");
const { startGatewayCapture, stopGatewayCapture } = require("./memory-gateway");
const { createA2aChannelService } = require("../../lib/server/a2a-channel");
const { updateOpenclawConfig } = require("../../lib/server/openclaw-config");

// channels.a2a.peer-upsert against the REAL pinned gateway. OpenClaw
// hot-reloads channels.a2a (the a2a plugin declares reload configPrefixes
// ["channels.a2a"]) and resolves ${VAR} from the running gateway's own env.
// A reference to a VAR the gateway was not spawned with stays the literal
// "${VAR}" string, which the channel then accepts as the peer bearer. The op
// therefore writes a reference only when the running gateway holds VAR.
//
// Last case is the contract this gate exists for, written the way the op
// used to write it. If it goes red, OpenClaw stopped accepting an unresolved
// literal: suspect upstream drift and revisit the gate, not this assertion.
const describeLive = kLiveEnabled ? describe : describe.skip;
const kReadyVar = "A2A_LIVE_READY_TOKEN";
const kReadyValue = "live-a2a-ready-value";
const kStagedVar = "A2A_LIVE_STAGED_TOKEN";
const kStagedValue = "live-a2a-staged-value";
const kHotReloadWaitMs = 8000;

const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close((error) => (error ? reject(error) : resolve(port)));
  });
});
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describeLive("channels.a2a.peer-upsert two-phase gate against the real gateway", () => {
  let gateway;
  let gatewayState;
  let configPath;
  let gatewayUrl;
  let launchEnv;

  const rpcStatus = async (bearer) => {
    const res = await fetch(`${gatewayUrl}/a2a/v1`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: "p", method: "GetTask", params: { id: "nope" } }),
      signal: AbortSignal.timeout(5000),
    });
    await res.text();
    return res.status;
  };
  const waitAccepted = (bearer, label) =>
    waitFor(async () => (await rpcStatus(bearer)) !== 401, 30000, label);

  const service = ({ envFile }) =>
    createA2aChannelService({
      openclawDir: gatewayState,
      readEnvFile: () => envFile,
      updateEnvFile: () => envFile,
      reloadEnv: () => false,
      processEnv: {},
      getGatewayLaunchEnvKeys: () =>
        new Set(Object.keys(launchEnv).filter((key) => launchEnv[key])),
    });

  beforeAll(async () => {
    const root = mkTemp("alphaclaw-live-a2a-upsert-");
    const home = path.join(root, "home");
    gatewayState = path.join(home, ".openclaw");
    fs.mkdirSync(path.join(gatewayState, "workspace"), { recursive: true });
    const port = await freePort();
    gatewayUrl = `http://127.0.0.1:${port}`;
    configPath = path.join(gatewayState, "openclaw.json");
    fs.writeFileSync(configPath, JSON.stringify({
      gateway: { mode: "local", port, bind: "loopback", auth: { mode: "token", token: "live-upsert-gw-token" } },
      agents: { defaults: { workspace: path.join(gatewayState, "workspace"), model: { primary: "fixture/fixture" } } },
      models: { providers: { fixture: {
        baseUrl: "http://127.0.0.1:9/v1",
        api: "openai-completions",
        apiKey: "x",
        models: [{ id: "fixture", name: "f", contextWindow: 128000, maxTokens: 1024 }],
      } } },
      plugins: { entries: { a2a: { enabled: true } } },
      channels: { a2a: { enabled: true, peers: { other: { token: "live-upsert-other-literal" } } } },
    }));
    launchEnv = {
      ...scrubTestRunnerEnv(),
      HOME: home,
      OPENCLAW_HOME: home,
      OPENCLAW_STATE_DIR: gatewayState,
      OPENCLAW_CONFIG_PATH: configPath,
      OPENCLAW_NO_AUTO_UPDATE: "1",
      [kReadyVar]: kReadyValue,
    };
    delete launchEnv[kStagedVar];
    gateway = startGatewayCapture({ bin: repoOpenclawBin(), port, env: launchEnv });
    await waitFor(async () => {
      if (gateway.didExit || gateway.spawnError) throw new Error(`Gateway failed: ${gateway.output.slice(-8000)}`);
      try {
        return (await fetch(`${gatewayUrl}/.well-known/agent-card.json`, { signal: AbortSignal.timeout(2000) })).ok;
      } catch {
        return false;
      }
    }, 150000, "real A2A plugin discovery");
  }, 180000);

  afterAll(async () => {
    await stopGatewayCapture(gateway);
  }, 20000);

  it("applies a peer whose variable the running gateway holds; the bearer is the value, never the literal", async () => {
    const result = await service({ envFile: [{ key: kReadyVar, value: kReadyValue }] })
      .upsertPeer("ready", { tokenEnv: kReadyVar });
    expect(result.state).toBe("applied");
    await waitAccepted(kReadyValue, "hot reload of the ready peer");
    expect(await rpcStatus(`\${${kReadyVar}}`)).toBe(401);
  }, 60000);

  it("stages a peer whose variable the running gateway lacks: openclaw.json untouched, literal bearer refused", async () => {
    const before = fs.readFileSync(configPath, "utf8");
    expect(await rpcStatus(`\${${kStagedVar}}`)).toBe(401);
    const result = await service({ envFile: [{ key: kStagedVar, value: kStagedValue }] })
      .upsertPeer("staged", { tokenEnv: kStagedVar });
    expect(result).toMatchObject({ status: 202, state: "restart_required", reason: "token_env_not_in_running_gateway" });
    expect(fs.readFileSync(configPath, "utf8")).toBe(before);
    await sleep(kHotReloadWaitMs);
    expect(await rpcStatus(`\${${kStagedVar}}`)).toBe(401);
    expect(await rpcStatus(kStagedValue)).toBe(401);
  }, 60000);

  it("contract behind the gate: an ungated reference to a missing variable makes the literal a valid bearer", async () => {
    updateOpenclawConfig({
      openclawDir: gatewayState,
      mutate: (cfg) => {
        cfg.channels.a2a.peers.ungated = { token: `\${${kStagedVar}}` };
      },
    });
    await waitAccepted(`\${${kStagedVar}}`, "hot reload accepting the unresolved literal");
  }, 60000);
});
