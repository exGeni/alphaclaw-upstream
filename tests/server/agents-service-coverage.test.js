const { createAgentsService } = require("../../lib/server/agents/service");
const {
  normalizeBindingMatch,
  normalizeChannelProvider,
  getConfiguredChannelEnvKeys,
  assertActiveChannelTokenEnvVars,
  normalizeChannelConfig,
  appendBindingToConfig,
  hasImplicitWhatsAppSelfPairing,
  withNormalizedAgentsConfig,
  resolveRequestedWorkspacePath,
  getSafeStat,
  calculatePathSizeBytes,
} = require("../../lib/server/agents/shared");

const OPENCLAW_DIR = "/tmp/openclaw";

const buildFsMock = ({ initialConfig = {}, fileContents = {} } = {}) => {
  let currentConfig = JSON.parse(JSON.stringify(initialConfig));
  const files = new Set();
  const directories = new Set();
  const extraFiles = new Map(Object.entries(fileContents));
  return {
    existsSync: vi.fn((targetPath) => {
      const normalizedTargetPath = String(targetPath || "");
      if (
        files.has(normalizedTargetPath) ||
        directories.has(normalizedTargetPath)
      ) {
        return true;
      }
      if (extraFiles.has(normalizedTargetPath)) {
        return true;
      }
      const prefix = normalizedTargetPath.endsWith("/")
        ? normalizedTargetPath
        : `${normalizedTargetPath}/`;
      return Array.from(extraFiles.keys()).some((filePath) =>
        String(filePath || "").startsWith(prefix),
      );
    }),
    mkdirSync: vi.fn((targetPath) => {
      directories.add(targetPath);
    }),
    rmSync: vi.fn(),
    readdirSync: vi.fn((targetPath) => {
      const normalizedTargetPath = String(targetPath || "");
      const prefix = normalizedTargetPath.endsWith("/")
        ? normalizedTargetPath
        : `${normalizedTargetPath}/`;
      return Array.from(extraFiles.keys())
        .filter((filePath) => filePath.startsWith(prefix))
        .map((filePath) => filePath.slice(prefix.length))
        .filter((fileName) => fileName && !fileName.includes("/"));
    }),
    readFileSync: vi.fn((targetPath) => {
      const normalizedTargetPath = String(targetPath || "");
      if (normalizedTargetPath.endsWith("openclaw.json")) {
        return JSON.stringify(currentConfig);
      }
      if (extraFiles.has(normalizedTargetPath)) {
        return String(extraFiles.get(normalizedTargetPath));
      }
      throw new Error(`ENOENT: ${normalizedTargetPath}`);
    }),
    writeFileSync: vi.fn((targetPath, content) => {
      if (String(targetPath || "").endsWith("openclaw.json")) {
        currentConfig = JSON.parse(String(content || "{}"));
        return;
      }
      files.add(targetPath);
      extraFiles.set(String(targetPath || ""), String(content || ""));
    }),
    readConfig: () => currentConfig,
  };
};

const buildService = ({
  initialConfig = {},
  fileContents = {},
  readEnvFile = () => [],
  writeEnvFile = vi.fn(),
  reloadEnv = vi.fn(),
  restartGateway = vi.fn(async () => {}),
  clawCmd = vi.fn(async () => ({ ok: true, stdout: "", stderr: "" })),
} = {}) => {
  const fsMock = buildFsMock({ initialConfig, fileContents });
  const service = createAgentsService({
    fs: fsMock,
    OPENCLAW_DIR,
    readEnvFile,
    writeEnvFile,
    reloadEnv,
    restartGateway,
    clawCmd,
  });
  return { fsMock, service, writeEnvFile, reloadEnv, restartGateway, clawCmd };
};

describe("server/agents/service coverage", () => {
  describe("agents domain", () => {
    it("reads global agent defaults with and without thinkingDefault", () => {
      const withDefault = buildService({
        initialConfig: { agents: { defaults: { thinkingDefault: " low " } } },
      });
      expect(withDefault.service.getAgentDefaults()).toEqual({
        thinkingDefault: "low",
      });

      const withoutDefault = buildService({ initialConfig: {} });
      expect(withoutDefault.service.getAgentDefaults()).toEqual({
        thinkingDefault: null,
      });

      const nonString = buildService({
        initialConfig: { agents: { defaults: { thinkingDefault: 42 } } },
      });
      expect(nonString.service.getAgentDefaults()).toEqual({
        thinkingDefault: null,
      });
    });

    it("reports empty workspace paths for blank workspace values", () => {
      const { service } = buildService({
        initialConfig: {
          agents: {
            list: [
              { id: "main", default: true },
              { id: "blank", workspace: " " },
            ],
          },
        },
      });

      expect(service.getAgentWorkspaceSize("blank")).toEqual({
        workspacePath: "",
        exists: false,
        sizeBytes: 0,
      });
    });

    it("reports missing workspaces when the fs offers no stat functions", () => {
      const { service } = buildService({
        initialConfig: {
          agents: { list: [{ id: "main", default: true }, { id: "nows" }] },
        },
      });

      expect(service.getAgentWorkspaceSize("nows")).toEqual({
        workspacePath: "/tmp/openclaw/workspace-nows",
        exists: false,
        sizeBytes: 0,
      });
    });

    it("computes workspace sizes through lstat when available", () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: { list: [{ id: "main", default: true }, { id: "sized" }] },
        },
      });
      fsMock.lstatSync = vi.fn(() => ({
        isSymbolicLink: () => false,
        isFile: () => true,
        isDirectory: () => false,
        size: 2048,
      }));

      expect(service.getAgentWorkspaceSize("sized")).toEqual({
        workspacePath: "/tmp/openclaw/workspace-sized",
        exists: true,
        sizeBytes: 2048,
      });
    });

    it("rejects invalid agent ids on create", () => {
      const { service } = buildService();
      expect(() => service.createAgent({ id: "Bad_ID" })).toThrow(
        "Agent id must be lowercase letters, numbers, and hyphens only",
      );
    });

    it("rejects duplicate agent ids on create", () => {
      const { service } = buildService();
      service.createAgent({ id: "ops" });
      expect(() => service.createAgent({ id: "ops" })).toThrow(
        'Agent "ops" already exists',
      );
    });

    it("keeps the legacy agent name when patching identity without a name", async () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            list: [
              { id: "main", default: true },
              { id: "ops", name: "Legacy Ops" },
            ],
          },
        },
      });

      const updated = await service.updateAgent("ops", {
        identity: { emoji: "E" },
      });

      expect(updated.identity).toEqual({ emoji: "E", name: "Legacy Ops" });
      expect(updated.name).toBe("Legacy Ops");
      expect(fsMock.readConfig().agents.list[1]).not.toHaveProperty("name");
    });

    it("falls back to a generated agent name for non-object identity patches", async () => {
      const { service } = buildService({
        initialConfig: {
          agents: { list: [{ id: "main", default: true }, { id: "ops-two" }] },
        },
      });

      const updated = await service.updateAgent("ops-two", {
        identity: "bogus",
      });

      expect(updated.identity).toEqual({ name: "Ops Two Agent" });
    });

    it("renames agents while preserving existing identity fields", async () => {
      const { service } = buildService({
        initialConfig: {
          agents: {
            list: [
              { id: "main", default: true },
              { id: "ops", identity: { role: "helper", name: "Old" } },
            ],
          },
        },
      });

      const updated = await service.updateAgent("ops", { name: "Renamed" });

      expect(updated.identity).toEqual({ role: "helper", name: "Renamed" });
    });

    it("clears tools config with tools: null; {} keeps an empty tools object", async () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            list: [
              { id: "main", default: true },
              { id: "tooly", tools: { profile: "full" } },
            ],
          },
        },
      });

      const updated = await service.updateAgent("tooly", { tools: null });

      expect(updated).not.toHaveProperty("tools");
      expect(fsMock.readConfig().agents.list[1]).not.toHaveProperty("tools");

      const emptied = await service.updateAgent("tooly", { tools: {} });
      expect(emptied.tools).toEqual({});
    });

    describe("deleteAgent unroutes the agent's Telegram topics (0.9.95-exgenius.7)", () => {
      const build = (registry) => {
        const fsMock = buildFsMock({
          initialConfig: {
            agents: { list: [{ id: "main", default: true }, { id: "dispatcher" }] },
            channels: {
              telegram: {
                groups: {
                  "-100": {
                    topics: {
                      "16": { agentId: "dispatcher" },
                      "17": { agentId: "Dispatcher", systemPrompt: "keep me" },
                      "39": { agentId: "main" },
                    },
                  },
                },
                accounts: {
                  work: { groups: { "-200": { topics: { "5": { agentId: "dispatcher" } } } } },
                },
              },
            },
          },
        });
        const service = createAgentsService({ fs: fsMock, OPENCLAW_DIR, topicRegistry: registry });
        return { fsMock, service };
      };

      it("clears topic agentId in openclaw.json and in the registry, and reports both", () => {
        const registry = {
          clearAgentReferences: vi.fn(() => [{ groupId: "-100", threadId: "16" }]),
        };
        const { fsMock, service } = build(registry);
        const result = service.deleteAgent("dispatcher");
        const telegram = fsMock.readConfig().channels.telegram;
        expect(telegram.groups["-100"].topics).toEqual({
          "17": { systemPrompt: "keep me" },
          "39": { agentId: "main" },
        });
        expect(telegram.accounts.work.groups["-200"]).not.toHaveProperty("topics");
        expect(registry.clearAgentReferences).toHaveBeenCalledWith("dispatcher", { source: "agent-delete" });
        expect(result).toEqual({
          ok: true,
          unroutedTopics: {
            config: [
              { groupId: "-100", threadId: "16" },
              { groupId: "-100", threadId: "17" },
              { accountId: "work", groupId: "-200", threadId: "5" },
            ],
            registry: [{ groupId: "-100", threadId: "16" }],
          },
        });
      });

      it("puts the registry routes back when the config write fails (codex)", () => {
        const registry = {
          clearAgentReferences: vi.fn(() => [{ groupId: "-100", threadId: "16", agentId: "dispatcher" }]),
          updateTopic: vi.fn(),
        };
        const { fsMock, service } = build(registry);
        fsMock.writeFileSync.mockImplementation(() => {
          throw new Error("disk full");
        });
        expect(() => service.deleteAgent("dispatcher")).toThrow();
        expect(registry.updateTopic).toHaveBeenCalledWith("-100", "16", { agentId: "dispatcher" }, {
          source: "agent-delete-rollback",
        });
      });

      it("names registry routes it could not restore after a failed config write (codex)", () => {
        const registry = {
          clearAgentReferences: vi.fn(() => [{ groupId: "-100", threadId: "16", agentId: "dispatcher" }]),
          updateTopic: vi.fn(() => {
            throw new Error("lock timeout");
          }),
        };
        const { fsMock, service } = build(registry);
        fsMock.writeFileSync.mockImplementation(() => {
          throw new Error("disk full");
        });
        expect(() => service.deleteAgent("dispatcher")).toThrow("NOT restored (re-add with a topic PUT): -100/16->dispatcher");
      });

      it("refuses the delete (openclaw.json untouched, retryable) when the registry clear fails", () => {
        const registry = {
          clearAgentReferences: vi.fn(() => {
            throw new Error("Refusing to touch topic-registry.json: file exists but is not valid JSON");
          }),
        };
        const { fsMock, service } = build(registry);
        expect(() => service.deleteAgent("dispatcher")).toThrow("not valid JSON");
        const cfg = fsMock.readConfig();
        expect(cfg.agents.list.map((a) => a.id)).toContain("dispatcher");
        expect(cfg.channels.telegram.groups["-100"].topics["16"]).toEqual({ agentId: "dispatcher" });
      });
    });

    describe("per-agent tools (profile / allow / alsoAllow / deny / fs)", () => {
      const buildToolsService = (receptionTools) =>
        buildService({
          initialConfig: {
            agents: {
              list: [
                { id: "main", default: true },
                { id: "reception", ...(receptionTools ? { tools: receptionTools } : {}) },
              ],
            },
          },
        });
      const savedTools = (fsMock) =>
        fsMock.readConfig().agents.list.find((a) => a.id === "reception").tools;

      it("keeps per-agent tools keys AlphaClaw does not manage, and fs when omitted", async () => {
        const { fsMock, service } = buildToolsService({
          profile: "coding",
          deny: ["exec"],
          elevated: { enabled: false },
          exec: { security: "deny" },
          fs: { workspaceOnly: true },
        });
        await service.updateAgent("reception", { tools: { profile: "messaging", deny: ["exec", "write"] } });
        expect(savedTools(fsMock)).toEqual({
          profile: "messaging",
          deny: ["exec", "write"],
          elevated: { enabled: false },
          exec: { security: "deny" },
          fs: { workspaceOnly: true },
        });
      });

      it("sets a strict allow list and refuses allow together with alsoAllow, or an empty allow", async () => {
        const { fsMock, service } = buildToolsService({ profile: "messaging" });
        await service.updateAgent("reception", {
          tools: { profile: "messaging", allow: [" message ", "message", "sessions_list"] },
        });
        expect(savedTools(fsMock)).toEqual({ profile: "messaging", allow: ["message", "sessions_list"] });
        await expect(
          service.updateAgent("reception", { tools: { allow: ["read"], alsoAllow: ["exec"] } }),
        ).rejects.toThrow("cannot set both allow and alsoAllow");
        await expect(service.updateAgent("reception", { tools: { allow: [] } })).rejects.toThrow(
          "must name at least one tool",
        );
        expect(savedTools(fsMock)).toEqual({ profile: "messaging", allow: ["message", "sessions_list"] });
      });

      it("keeps an allow list the patch omits (Setup UI shape); allow: null or a new alsoAllow replaces it (refuter)", async () => {
        const { fsMock, service } = buildToolsService({ profile: "messaging", allow: ["message"] });
        await service.updateAgent("reception", { tools: { profile: "messaging", deny: ["exec"] } });
        expect(savedTools(fsMock)).toEqual({ profile: "messaging", allow: ["message"], deny: ["exec"] });
        await service.updateAgent("reception", { tools: { profile: "minimal", alsoAllow: ["read"] } });
        expect(savedTools(fsMock)).toEqual({ profile: "minimal", alsoAllow: ["read"] });
        await service.updateAgent("reception", { tools: { profile: "messaging", allow: ["message"] } });
        await service.updateAgent("reception", { tools: { profile: "messaging", alsoAllow: [] } });
        // A supplied [] replaces allow and is kept as an own override of tools.alsoAllow (codex).
        expect(savedTools(fsMock)).toEqual({ profile: "messaging", alsoAllow: [] });
        await service.updateAgent("reception", { tools: { profile: "messaging", allow: ["message"] } });
        await service.updateAgent("reception", { tools: { profile: "messaging", allow: null } });
        expect(savedTools(fsMock)).toEqual({ profile: "messaging" });
      });

      it("patches fs.workspaceOnly field by field; fs: null removes it", async () => {
        const { fsMock, service } = buildToolsService({ profile: "messaging" });
        await service.updateAgent("reception", { tools: { profile: "messaging", fs: { workspaceOnly: true } } });
        expect(savedTools(fsMock).fs).toEqual({ workspaceOnly: true });
        await service.updateAgent("reception", { tools: { profile: "messaging", fs: { workspaceOnly: null } } });
        expect(savedTools(fsMock)).not.toHaveProperty("fs");
        await service.updateAgent("reception", { tools: { profile: "messaging", fs: { workspaceOnly: false } } });
        expect(savedTools(fsMock).fs).toEqual({ workspaceOnly: false });
        await service.updateAgent("reception", { tools: { profile: "messaging", fs: null } });
        expect(savedTools(fsMock)).not.toHaveProperty("fs");
      });

      it("rejects unknown keys, unknown profiles and non-object tools without writing", async () => {
        const { fsMock, service } = buildToolsService({ profile: "messaging", deny: ["exec"] });
        await expect(service.updateAgent("reception", { tools: { profile: "bogus" } })).rejects.toThrow(
          "tools.profile must be one of",
        );
        await expect(service.updateAgent("reception", { tools: { elevated: {} } })).rejects.toThrow(
          "unsupported keys: elevated",
        );
        await expect(service.updateAgent("reception", { tools: "none" })).rejects.toThrow(
          "tools must be an object",
        );
        await expect(
          service.updateAgent("reception", { tools: { fs: { workspaceOnly: "yes" } } }),
        ).rejects.toThrow("workspaceOnly must be true, false or null");
        expect(savedTools(fsMock)).toEqual({ profile: "messaging", deny: ["exec"] });
      });
    });

    describe("per-agent models (agentRuntime / params / codeMode)", () => {
      const buildModelsService = (receptionModels) =>
        buildService({
          initialConfig: {
            agents: {
              defaults: {
                models: { "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "claude-cli" } } },
              },
              list: [
                { id: "main", default: true },
                { id: "reception", ...(receptionModels ? { models: receptionModels } : {}) },
              ],
            },
          },
        });

      it("sets one agent's runtime without touching agents.defaults", async () => {
        const { fsMock, service } = buildModelsService();
        const updated = await service.updateAgent("reception", {
          models: { "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "openclaw" } } },
        });
        expect(updated.models).toEqual({
          "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "openclaw" } },
        });
        const saved = fsMock.readConfig().agents;
        expect(saved.defaults.models).toEqual({
          "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "claude-cli" } },
        });
        expect(saved.list.find((a) => a.id === "main")).not.toHaveProperty("models");
      });

      it("merges by model id, removes with null and clears with models: null", async () => {
        const { fsMock, service } = buildModelsService({
          "openai/gpt-5.6-luna": { agentRuntime: { id: "openclaw" } },
        });
        await service.updateAgent("reception", {
          models: { "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "openclaw" }, codeMode: false } },
        });
        let reception = fsMock.readConfig().agents.list.find((a) => a.id === "reception");
        expect(Object.keys(reception.models)).toEqual([
          "openai/gpt-5.6-luna",
          "anthropic/claude-sonnet-5-5",
        ]);
        await service.updateAgent("reception", { models: { "openai/gpt-5.6-luna": null } });
        reception = fsMock.readConfig().agents.list.find((a) => a.id === "reception");
        expect(Object.keys(reception.models)).toEqual(["anthropic/claude-sonnet-5-5"]);
        await service.updateAgent("reception", { models: null });
        reception = fsMock.readConfig().agents.list.find((a) => a.id === "reception");
        expect(reception).not.toHaveProperty("models");
      });

      it("patches an entry field by field, keeping the runtime and keys it does not edit", async () => {
        const { fsMock, service } = buildModelsService({
          "anthropic/claude-sonnet-5-5": {
            agentRuntime: { id: "openclaw" },
            alias: "sonnet",
            streaming: false,
            params: { temperature: 0.2 },
          },
        });
        await service.updateAgent("reception", {
          models: { "anthropic/claude-sonnet-5-5": { codeMode: false, params: null } },
        });
        const entry = fsMock
          .readConfig()
          .agents.list.find((a) => a.id === "reception").models["anthropic/claude-sonnet-5-5"];
        expect(entry).toEqual({
          agentRuntime: { id: "openclaw" },
          alias: "sonnet",
          streaming: false,
          codeMode: false,
        });
      });

      it("keeps an explicitly supplied empty entry (model registration)", async () => {
        const { fsMock, service } = buildModelsService();
        await service.updateAgent("reception", { models: { "vllm/*": {} } });
        const reception = fsMock.readConfig().agents.list.find((a) => a.id === "reception");
        expect(reception.models).toEqual({ "vllm/*": {} });
      });

      it("rejects unknown runtimes, keys and entry shapes without writing", async () => {
        const { fsMock, service } = buildModelsService();
        const before = JSON.stringify(fsMock.readConfig());
        const cases = [
          [{ "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "bogus" } } }, "agentRuntime.id must be one of"],
          [{ "anthropic/claude-sonnet-5-5": { foo: 1 } }, "unsupported keys: foo"],
          [{ "anthropic/claude-sonnet-5-5": { agentRuntime: { id: "openclaw", x: 1 } } }, "agentRuntime has unsupported keys"],
          [{ "no-slash": { agentRuntime: { id: "openclaw" } } }, "is not a provider/model id"],
          [{ "anthropic/claude-sonnet-5-5": { codeMode: "yes" } }, "codeMode must be true or false"],
          [["anthropic/claude-sonnet-5-5"], "models must be an object"],
          [{ "vllm/*": { codeMode: true } }, "codeMode is not allowed on a wildcard model ref"],
        ];
        for (const [models, message] of cases) {
          await expect(service.updateAgent("reception", { models })).rejects.toThrow(message);
        }
        expect(JSON.stringify(fsMock.readConfig())).toBe(before);
      });
    });

    describe("per-agent skills allowlist", () => {
      const buildSkillsService = (reception = {}) =>
        buildService({
          initialConfig: {
            agents: {
              defaults: { skills: ["github", "weather"] },
              list: [{ id: "main", default: true }, { id: "reception", ...reception }],
            },
          },
        });

      it("sets an exact list, [] for none, and null to inherit the defaults", async () => {
        const { fsMock, service } = buildSkillsService();
        const read = () => fsMock.readConfig().agents.list.find((a) => a.id === "reception");

        await service.updateAgent("reception", { skills: [" grant-intake ", "grant-intake", "faq"] });
        expect(read().skills).toEqual(["grant-intake", "faq"]);

        await service.updateAgent("reception", { skills: [] });
        expect(read().skills).toEqual([]);

        await service.updateAgent("reception", { skills: null });
        expect(read()).not.toHaveProperty("skills");
        expect(fsMock.readConfig().agents.defaults.skills).toEqual(["github", "weather"]);
      });

      it("rejects malformed skill lists without writing", async () => {
        const { fsMock, service } = buildSkillsService({ skills: ["faq"] });
        const before = JSON.stringify(fsMock.readConfig());
        for (const [skills, message] of [
          ["faq", "skills must be an array"],
          [[1], "skills entries must be strings"],
          [["two words"], "is not a skill name"],
          [[""], "is not a skill name"],
        ]) {
          await expect(service.updateAgent("reception", { skills })).rejects.toThrow(message);
        }
        expect(JSON.stringify(fsMock.readConfig())).toBe(before);
      });
    });

    it("rejects invalid thinkingDefault values", async () => {
      const { service } = buildService();
      await expect(
        service.updateAgent("main", { thinkingDefault: "bogus" }),
      ).rejects.toThrow("Invalid thinkingDefault value");
    });
  });

  describe("channels domain: tokens", () => {
    it("throws when the channel provider is not configured", () => {
      const { service } = buildService();
      expect(() =>
        service.getChannelAccountToken({ provider: "telegram" }),
      ).toThrow('Channel "telegram" not found');
    });

    it("throws when the channel account is not configured", () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
      });
      expect(() =>
        service.getChannelAccountToken({
          provider: "telegram",
          accountId: "ghost",
        }),
      ).toThrow('Channel account "telegram/ghost" not found');
    });
  });

  describe("channels domain: create", () => {
    it("requires an explicit account id once accounts exist", async () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
      });
      await expect(
        service.createChannelAccount({ provider: "telegram", agentId: "main" }),
      ).rejects.toThrow("Channel account id is required");
    });

    it("rejects invalid channel account ids", async () => {
      const { service } = buildService();
      await expect(
        service.createChannelAccount({
          provider: "telegram",
          agentId: "main",
          accountId: "Bad_Id",
        }),
      ).rejects.toThrow(
        "Channel account id must be lowercase letters, numbers, and hyphens only",
      );
    });

    it("rejects duplicate channel accounts", async () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
      });
      await expect(
        service.createChannelAccount({
          provider: "telegram",
          agentId: "main",
          accountId: "default",
        }),
      ).rejects.toThrow('Channel account "telegram/default" already exists');
    });

    it("rejects slack app tokens that duplicate configured channel env vars", async () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
        readEnvFile: () => [{ key: "TELEGRAM_BOT_TOKEN", value: "xapp-dup" }],
      });

      await expect(
        service.createChannelAccount({
          provider: "slack",
          agentId: "main",
          accountId: "work",
          token: "xoxb-1",
          appToken: "xapp-dup",
        }),
      ).rejects.toThrow("Channel token already exists in TELEGRAM_BOT_TOKEN");
    });

    it("overwrites orphaned env vars that duplicate a new slack app token", async () => {
      const writeEnvFile = vi.fn();
      const { fsMock, service, restartGateway } = buildService({
        // A stale channel-shaped key (e.g. left by a removed named account) is an
        // orphan; an unrelated key holding the same token is NOT (fix wave F091,
        // see agents-service.test.js).
        readEnvFile: () => [{ key: "SLACK_APP_TOKEN_LEGACY", value: "xapp-orphan" }],
        writeEnvFile,
      });

      const result = await service.createChannelAccount({
        provider: "slack",
        agentId: "main",
        token: "xoxb-1",
        appToken: "xapp-orphan",
      });

      expect(result.channel).toBe("slack");
      expect(result.account).toEqual({
        id: "default",
        name: "Slack",
        envKey: "SLACK_BOT_TOKEN",
      });
      expect(writeEnvFile).toHaveBeenCalledWith([
        { key: "SLACK_BOT_TOKEN", value: "xoxb-1" },
        { key: "SLACK_APP_TOKEN", value: "xapp-orphan" },
      ]);
      const config = fsMock.readConfig();
      expect(config.channels.slack.accounts.default.appToken).toBe(
        "${SLACK_APP_TOKEN}",
      );
      expect(restartGateway).toHaveBeenCalled();
    });

    it("rolls back and rethrows when agent binding fails", async () => {
      const writeEnvFile = vi.fn();
      const clawCmd = vi.fn(async (command) => {
        if (command.startsWith("agents bind")) {
          return { ok: false, stdout: "", stderr: "bind exploded" };
        }
        return { ok: true, stdout: "", stderr: "" };
      });
      const { service } = buildService({ writeEnvFile, clawCmd });

      await expect(
        service.createChannelAccount({
          provider: "telegram",
          agentId: "main",
          token: "123:abc",
        }),
      ).rejects.toThrow("bind exploded");

      expect(clawCmd).toHaveBeenCalledWith(
        expect.stringContaining("channels remove"),
        expect.anything(),
      );
      // Rollback restores the previous (empty) env file.
      expect(writeEnvFile).toHaveBeenLastCalledWith([]);
    });

    it("gives up after exhausting config-mutation-conflict retries", async () => {
      const conflict = {
        ok: false,
        stdout: "",
        stderr: "ConfigMutationConflictError: config changed since last load",
      };
      const clawCmd = vi.fn(async () => conflict);
      const { service } = buildService({ clawCmd });

      await expect(
        service.createChannelAccount({
          provider: "telegram",
          agentId: "main",
          token: "123:abc",
        }),
      ).rejects.toThrow("ConfigMutationConflictError");

      // Three retried "channels add" attempts plus the rollback remove.
      expect(clawCmd).toHaveBeenCalledTimes(4);
    });
  });

  describe("channels domain: update", () => {
    it("validates required update fields", () => {
      const { service } = buildService();
      expect(() =>
        service.updateChannelAccount({ provider: "telegram", agentId: "main" }),
      ).toThrow("Channel name is required");
      expect(() =>
        service.updateChannelAccount({ provider: "telegram", name: "X" }),
      ).toThrow("Agent is required");
      expect(() =>
        service.updateChannelAccount({
          provider: "telegram",
          name: "X",
          agentId: "ghost",
        }),
      ).toThrow('Agent "ghost" not found');
      expect(() =>
        service.updateChannelAccount({
          provider: "telegram",
          name: "X",
          agentId: "main",
        }),
      ).toThrow('Channel "telegram" not found');
    });

    it("throws for unknown accounts on update", () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
      });
      expect(() =>
        service.updateChannelAccount({
          provider: "telegram",
          accountId: "ghost",
          name: "X",
          agentId: "main",
        }),
      ).toThrow('Channel account "telegram/ghost" not found');
    });

    it("rejects slack app token updates that duplicate configured env vars", () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            slack: {
              accounts: {
                default: {
                  botToken: "${SLACK_BOT_TOKEN}",
                  appToken: "${SLACK_APP_TOKEN}",
                },
              },
            },
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
        readEnvFile: () => [{ key: "TELEGRAM_BOT_TOKEN", value: "xapp-dup" }],
      });

      expect(() =>
        service.updateChannelAccount({
          provider: "slack",
          accountId: "default",
          name: "Slack",
          agentId: "main",
          appToken: "xapp-dup",
        }),
      ).toThrow("Channel token already exists in TELEGRAM_BOT_TOKEN");
    });

    it("rejects bot token updates that duplicate configured env vars", () => {
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
            discord: {
              accounts: { default: { token: "${DISCORD_BOT_TOKEN}" } },
            },
          },
        },
        readEnvFile: () => [{ key: "DISCORD_BOT_TOKEN", value: "tok-x" }],
      });

      expect(() =>
        service.updateChannelAccount({
          provider: "telegram",
          accountId: "default",
          name: "TG",
          agentId: "main",
          token: "tok-x",
        }),
      ).toThrow("Channel token already exists in DISCORD_BOT_TOKEN");
    });

    it("updates tokens that only collide with orphaned env vars", () => {
      const writeEnvFile = vi.fn();
      const reloadEnv = vi.fn();
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
        readEnvFile: () => [
          { key: "TELEGRAM_BOT_TOKEN", value: "old-token" },
          { key: "UNUSED_TOKEN", value: "tok-new" },
          { value: "stray-entry-without-key" },
        ],
        writeEnvFile,
        reloadEnv,
      });

      const result = service.updateChannelAccount({
        provider: "telegram",
        accountId: "default",
        name: "TG",
        agentId: "main",
        token: "tok-new",
      });

      expect(result.tokenUpdated).toBe(true);
      expect(writeEnvFile).toHaveBeenCalledWith([
        { key: "UNUSED_TOKEN", value: "tok-new" },
        { value: "stray-entry-without-key" },
        { key: "TELEGRAM_BOT_TOKEN", value: "tok-new" },
      ]);
      expect(reloadEnv).toHaveBeenCalled();
    });

    it("renames legacy default channel configs in place", () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              enabled: true,
              botToken: "${TELEGRAM_BOT_TOKEN}",
            },
          },
        },
      });

      const result = service.updateChannelAccount({
        provider: "telegram",
        name: "Renamed",
        agentId: "main",
      });

      expect(result.account).toEqual({
        id: "default",
        name: "Renamed",
        boundAgentId: "main",
      });
      expect(result.tokenUpdated).toBe(false);
      const config = fsMock.readConfig();
      expect(config.channels.telegram.name).toBe("Renamed");
      expect(config.bindings).toEqual([
        {
          agentId: "main",
          match: { channel: "telegram", accountId: "default" },
        },
      ]);
    });
  });

  describe("channels domain: delete", () => {
    it("throws for unknown providers and accounts on delete", async () => {
      const empty = buildService();
      await expect(
        empty.service.deleteChannelAccount({ provider: "telegram" }),
      ).rejects.toThrow('Channel "telegram" not found');

      const configured = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
      });
      await expect(
        configured.service.deleteChannelAccount({
          provider: "telegram",
          accountId: "ghost",
        }),
      ).rejects.toThrow('Channel account "telegram/ghost" not found');
    });

    it("deletes discord accounts, prunes env vars, and rewrites pairing files", async () => {
      const writeEnvFile = vi.fn();
      const reloadEnv = vi.fn();
      const pairingPath = "/tmp/openclaw/credentials/discord-pairing.json";
      const { fsMock, service, restartGateway } = buildService({
        initialConfig: {
          channels: {
            discord: {
              accounts: {
                default: { token: "${DISCORD_BOT_TOKEN}" },
                alt: { token: "${DISCORD_BOT_TOKEN_ALT}" },
              },
            },
          },
          plugins: { entries: { discord: { enabled: true } } },
        },
        fileContents: {
          [pairingPath]: JSON.stringify({
            version: 1,
            requests: [
              { meta: { accountId: "default" } },
              { meta: { accountId: "alt" } },
              { meta: {} },
            ],
          }),
        },
        readEnvFile: () => [
          { key: "DISCORD_BOT_TOKEN", value: "d1" },
          { key: "DISCORD_BOT_TOKEN_ALT", value: "d2" },
          { value: "stray-entry-without-key" },
        ],
        writeEnvFile,
        reloadEnv,
      });

      const result = await service.deleteChannelAccount({
        provider: "discord",
      });

      expect(result).toEqual({ ok: true });
      const config = fsMock.readConfig();
      expect(Object.keys(config.channels.discord.accounts)).toEqual(["alt"]);
      expect(writeEnvFile).toHaveBeenCalledWith([
        { key: "DISCORD_BOT_TOKEN_ALT", value: "d2" },
        { value: "stray-entry-without-key" },
      ]);
      expect(reloadEnv).toHaveBeenCalled();
      expect(JSON.parse(fsMock.readFileSync(pairingPath))).toEqual({
        version: 1,
        requests: [{ meta: { accountId: "alt" } }],
      });
      expect(fsMock.rmSync).toHaveBeenCalledWith(
        "/tmp/openclaw/credentials/discord-default-allowFrom.json",
        { force: true },
      );
      expect(fsMock.rmSync).toHaveBeenCalledWith(
        "/tmp/openclaw/credentials/discord-allowFrom.json",
        { force: true },
      );
      expect(restartGateway).toHaveBeenCalled();
    });

    it("throws when the openclaw remove command fails", async () => {
      const clawCmd = vi.fn(async () => ({
        ok: false,
        stdout: "",
        stderr: "remove failed",
      }));
      const { service } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
        },
        clawCmd,
      });

      await expect(
        service.deleteChannelAccount({
          provider: "telegram",
          accountId: "default",
        }),
      ).rejects.toThrow("remove failed");
    });

    it("deletes telegram accounts, disables the plugin, and prunes env vars", async () => {
      const writeEnvFile = vi.fn();
      const reloadEnv = vi.fn();
      const { fsMock, service, restartGateway } = buildService({
        initialConfig: {
          channels: {
            telegram: {
              accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
            },
          },
          plugins: { entries: { telegram: { enabled: true } } },
        },
        readEnvFile: () => [
          { key: "TELEGRAM_BOT_TOKEN", value: "t1" },
          { key: "OTHER", value: "x" },
          { value: "stray-entry-without-key" },
        ],
        writeEnvFile,
        reloadEnv,
      });

      const result = await service.deleteChannelAccount({
        provider: "telegram",
        accountId: "default",
      });

      expect(result).toEqual({ ok: true });
      const config = fsMock.readConfig();
      expect(config.channels).not.toHaveProperty("telegram");
      expect(config.plugins.entries.telegram.enabled).toBe(false);
      expect(writeEnvFile).toHaveBeenCalledWith([
        { key: "OTHER", value: "x" },
        { value: "stray-entry-without-key" },
      ]);
      expect(reloadEnv).toHaveBeenCalled();
      expect(restartGateway).not.toHaveBeenCalled();
    });
  });

  describe("channels domain: whatsapp", () => {
    it("requires an owner number when creating whatsapp accounts", async () => {
      const { service } = buildService();
      await expect(
        service.createChannelAccount({ provider: "whatsapp", agentId: "main" }),
      ).rejects.toThrow("WhatsApp owner number is required");
    });

    it("creates whatsapp accounts with allowlist policies and restarts the gateway", async () => {
      const writeEnvFile = vi.fn();
      const { fsMock, service, restartGateway } = buildService({
        readEnvFile: () => [
          { key: "WHATSAPP_OWNER_NUMBER", value: "+1999" },
        ],
        writeEnvFile,
      });

      const result = await service.createChannelAccount({
        provider: "whatsapp",
        agentId: "main",
        token: "+15551230000",
        name: "WA",
      });

      expect(result.channel).toBe("whatsapp");
      expect(result.restartRequired).toBe(true);
      expect(result.account).toEqual({
        id: "default",
        name: "WA",
        envKey: "WHATSAPP_OWNER_NUMBER",
      });
      expect(writeEnvFile).toHaveBeenCalledWith([
        { key: "WHATSAPP_OWNER_NUMBER", value: "+15551230000" },
      ]);
      const config = fsMock.readConfig();
      expect(config.channels.whatsapp.accounts.default).toEqual({
        name: "WA",
        allowFrom: ["${WHATSAPP_OWNER_NUMBER}"],
        groupAllowFrom: ["${WHATSAPP_OWNER_NUMBER}"],
        dmPolicy: "allowlist",
        groupPolicy: "allowlist",
        selfChatMode: true,
      });
      expect(config.bindings).toEqual([
        { agentId: "main", match: { channel: "whatsapp", accountId: "default" } },
      ]);
      expect(restartGateway).toHaveBeenCalledTimes(1);
    });

    it("rolls back whatsapp account creation when the CLI add fails", async () => {
      const writeEnvFile = vi.fn();
      const clawCmd = vi.fn(async (command) => {
        if (command.startsWith("channels add")) {
          return { ok: false, stdout: "", stderr: "" };
        }
        return { ok: true, stdout: "", stderr: "" };
      });
      const { service } = buildService({
        readEnvFile: () => [{ key: "OTHER_VAR", value: "x" }],
        writeEnvFile,
        clawCmd,
      });

      await expect(
        service.createChannelAccount({
          provider: "whatsapp",
          agentId: "main",
          token: "+15551234567",
        }),
      ).rejects.toThrow("Could not add WhatsApp channel account");

      expect(writeEnvFile).toHaveBeenNthCalledWith(1, [
        { key: "OTHER_VAR", value: "x" },
        { key: "WHATSAPP_OWNER_NUMBER", value: "+15551234567" },
      ]);
      expect(writeEnvFile).toHaveBeenLastCalledWith([
        { key: "OTHER_VAR", value: "x" },
      ]);
      expect(clawCmd).toHaveBeenCalledWith(
        expect.stringContaining("channels remove"),
        expect.anything(),
      );
    });
  });

  describe("channels domain: login", () => {
    it("defaults to the default account for login and login status", async () => {
      const clawCmd = vi.fn(async () => ({
        ok: true,
        stdout: "linked",
        stderr: "",
        code: 0,
      }));
      const { service } = buildService({ clawCmd });

      const login = await service.runChannelAccountLogin({
        provider: "whatsapp",
      });
      expect(login).toEqual({
        ok: true,
        stdout: "linked",
        stderr: "",
        completed: true,
      });
      // Leader-only kill: the login CLI must keep linking after the QR call.
      expect(clawCmd).toHaveBeenCalledWith("channels login --channel 'whatsapp'", {
        quiet: true,
        timeoutMs: 12000,
        killSignal: "SIGKILL",
        killScope: "leader",
      });

      const status = service.getChannelAccountLoginStatus({
        provider: "whatsapp",
      });
      expect(status).toEqual({
        provider: "whatsapp",
        accountId: "default",
        linked: false,
      });
    });

    it("rejects login status for non-whatsapp providers", () => {
      const { service } = buildService();
      expect(() =>
        service.getChannelAccountLoginStatus({ provider: "telegram" }),
      ).toThrow("Channel login status is currently only supported for WhatsApp");
    });
  });

  describe("bindings domain", () => {
    it("throws when removing a binding that does not exist", () => {
      const { service } = buildService();
      expect(() =>
        service.removeBinding("main", { channel: "telegram" }),
      ).toThrow("Binding not found");
    });
  });

  describe("service defaults", () => {
    it("falls back to safe no-op env, gateway, and claw helpers", async () => {
      const fsMock = buildFsMock({
        initialConfig: {
          channels: {
            discord: {
              accounts: { default: { token: "${DISCORD_BOT_TOKEN}" } },
            },
          },
        },
      });
      const service = createAgentsService({ fs: fsMock, OPENCLAW_DIR });

      const updated = service.updateChannelAccount({
        provider: "discord",
        accountId: "default",
        name: "Disc",
        agentId: "main",
        token: "new-token",
      });
      expect(updated.tokenUpdated).toBe(true);

      await expect(
        service.deleteChannelAccount({ provider: "discord" }),
      ).resolves.toEqual({ ok: true });

      const login = await service.runChannelAccountLogin({
        provider: "whatsapp",
      });
      expect(login.ok).toBe(false);
      expect(login.stderr).toContain("openclaw command unavailable");
    });
  });

  describe("shared helpers", () => {
    it("requires a channel when normalizing binding matches", () => {
      expect(() => normalizeBindingMatch({})).toThrow(
        "Binding channel is required",
      );
    });

    it("normalizes peers, parent peers, and roles in binding matches", () => {
      expect(
        normalizeBindingMatch({
          channel: " telegram ",
          accountId: "work",
          guildId: "g1",
          teamId: "t1",
          peer: { kind: "dm", id: "123" },
          parentPeer: { id: "456" },
          roles: ["admin", ""],
        }),
      ).toEqual({
        channel: "telegram",
        accountId: "work",
        guildId: "g1",
        teamId: "t1",
        peer: { kind: "dm", id: "123" },
        roles: ["admin"],
      });
    });

    it("rejects unsupported channel providers", () => {
      expect(() => normalizeChannelProvider("smoke-signal")).toThrow(
        'Unsupported channel provider "smoke-signal"',
      );
    });

    it("collects configured channel env keys including extras and legacy defaults", () => {
      const withAccounts = getConfiguredChannelEnvKeys({
        channels: {
          slack: { accounts: { work: {} } },
          bogus: { accounts: { x: {} } },
        },
      });
      expect(withAccounts.has("SLACK_BOT_TOKEN_WORK")).toBe(true);
      expect(withAccounts.has("SLACK_APP_TOKEN_WORK")).toBe(true);

      const enabledOnly = getConfiguredChannelEnvKeys({
        channels: {
          slack: { enabled: true },
          telegram: { enabled: true },
        },
      });
      expect(enabledOnly.has("SLACK_BOT_TOKEN")).toBe(true);
      expect(enabledOnly.has("SLACK_APP_TOKEN")).toBe(true);
      expect(enabledOnly.has("TELEGRAM_BOT_TOKEN")).toBe(true);
    });

    it("asserts channel token env vars exist for active channels", () => {
      expect(() =>
        assertActiveChannelTokenEnvVars({
          cfg: {
            channels: {
              telegram: {
                accounts: { default: { botToken: "${TELEGRAM_BOT_TOKEN}" } },
              },
            },
          },
          envVars: [],
        }),
      ).toThrow(
        "Missing required channel token env var TELEGRAM_BOT_TOKEN for active channel telegram/default",
      );

      expect(() =>
        assertActiveChannelTokenEnvVars({
          cfg: {
            channels: {
              slack: {
                accounts: { default: { botToken: "${SLACK_BOT_TOKEN}" } },
              },
            },
          },
          envVars: [{ key: "SLACK_BOT_TOKEN", value: "xoxb" }],
        }),
      ).toThrow(
        "Missing required channel token env var SLACK_APP_TOKEN for active channel slack/default",
      );
    });

    it("rewrites raw slack tokens in accounts to env references", () => {
      const normalized = normalizeChannelConfig({
        provider: "slack",
        channelConfig: {
          accounts: { work: { botToken: "xoxb-raw", appToken: "xapp-raw" } },
        },
      });
      expect(normalized.accounts.work).toEqual({
        botToken: "${SLACK_BOT_TOKEN_WORK}",
        appToken: "${SLACK_APP_TOKEN_WORK}",
      });
    });

    it("rewrites legacy top-level slack tokens into a default account", () => {
      const normalized = normalizeChannelConfig({
        provider: "slack",
        channelConfig: {
          enabled: true,
          botToken: "xoxb-raw",
          appToken: "xapp-raw",
        },
      });
      expect(normalized.accounts.default).toEqual({
        botToken: "${SLACK_BOT_TOKEN}",
        appToken: "${SLACK_APP_TOKEN}",
      });
      expect(normalized.defaultAccount).toBe("default");

      const preserved = normalizeChannelConfig({
        provider: "slack",
        channelConfig: {
          enabled: true,
          botToken: "xoxb-raw",
          appToken: "${CUSTOM_APP_TOKEN}",
        },
      });
      expect(preserved.accounts.default.appToken).toBe("${CUSTOM_APP_TOKEN}");
    });

    it("returns the existing binding when re-binding the same agent", () => {
      const cfg = {
        bindings: [
          { agentId: "main", match: { channel: "telegram", accountId: "default" } },
        ],
      };
      const result = appendBindingToConfig({
        cfg,
        agentId: "main",
        match: { channel: "telegram", accountId: "default" },
      });
      expect(result).toEqual(cfg.bindings[0]);
      expect(cfg.bindings).toHaveLength(1);
    });

    it("evaluates implicit whatsapp self-pairing guards", () => {
      const fsImpl = { readFileSync: vi.fn(() => "creds") };
      const base = {
        fsImpl,
        OPENCLAW_DIR,
        channelId: "whatsapp",
        accountId: "default",
      };
      expect(
        hasImplicitWhatsAppSelfPairing({ ...base, channelId: "telegram", accountConfig: {} }),
      ).toBe(false);
      expect(
        hasImplicitWhatsAppSelfPairing({ ...base, accountConfig: null }),
      ).toBe(false);
      expect(
        hasImplicitWhatsAppSelfPairing({
          ...base,
          accountConfig: { selfChatMode: false },
        }),
      ).toBe(false);
      expect(
        hasImplicitWhatsAppSelfPairing({
          ...base,
          accountConfig: { dmPolicy: " Disabled " },
        }),
      ).toBe(false);
      expect(
        hasImplicitWhatsAppSelfPairing({ ...base, accountConfig: {} }),
      ).toBe(true);
    });

    it("normalizes agent lists with duplicate or missing defaults", () => {
      const demoted = withNormalizedAgentsConfig({
        OPENCLAW_DIR,
        cfg: {
          agents: {
            list: [
              { name: "no-id" },
              { id: "main", default: true },
              { id: "ops", default: true },
            ],
          },
        },
      });
      expect(demoted.agents.list.map((entry) => !!entry.default)).toEqual([
        false,
        true,
        false,
      ]);

      const promoted = withNormalizedAgentsConfig({
        OPENCLAW_DIR,
        cfg: { agents: { list: [{ id: "main" }, { id: "ops" }] } },
      });
      expect(promoted.agents.list[0].default).toBe(true);
      expect(promoted.agents.list[1].default).toBeFalsy();
    });

    it("keeps an explicit-ownership roster free of default markers (#126)", () => {
      const normalized = withNormalizedAgentsConfig({
        OPENCLAW_DIR,
        cfg: {
          agents: {
            ownership: "explicit",
            defaults: { systemAgent: { agentId: "ops" } },
            list: [
              { id: "ops" },
              { id: "stray", default: true },
              { id: "side", default: false },
            ],
          },
        },
      });

      expect(normalized.agents.ownership).toBe("explicit");
      expect(normalized.agents.defaults).toEqual({
        systemAgent: { agentId: "ops" },
      });
      expect(normalized.agents.list).toEqual([
        { id: "ops" },
        { id: "stray" },
        { id: "side", default: false },
      ]);
    });

    it("saves an explicit-ownership entries roster without stamping default (#126)", async () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            ownership: "explicit",
            defaults: { systemAgent: { agentId: "main" } },
            entries: {
              main: { workspace: "/tmp/openclaw/workspace" },
              second: { workspace: "/tmp/openclaw/workspace-second" },
            },
          },
        },
      });

      await service.updateAgent("second", { name: "Second" });

      const saved = fsMock.readConfig().agents;
      expect(saved.ownership).toBe("explicit");
      expect(saved).not.toHaveProperty("list");
      expect(Object.keys(saved.entries)).toEqual(["main", "second"]);
      for (const entry of Object.values(saved.entries)) {
        expect(entry).not.toHaveProperty("default");
      }
      expect(fsMock.writeFileSync).toHaveBeenCalled();
    });

    it("records the default as systemAgent on an explicit-ownership fleet (#126)", () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            ownership: "explicit",
            defaults: { systemAgent: { agentId: "main" } },
            entries: {
              main: { workspace: "/tmp/openclaw/workspace" },
              second: { workspace: "/tmp/openclaw/workspace-second" },
            },
          },
        },
      });

      expect(
        service.listAgents().map((agent) => [agent.id, agent.default]),
      ).toEqual([
        ["main", true],
        ["second", false],
      ]);

      const updated = service.setDefaultAgent("second");
      expect(updated.default).toBe(true);

      const saved = fsMock.readConfig().agents;
      expect(saved.ownership).toBe("explicit");
      expect(saved.defaults.systemAgent).toEqual({ agentId: "second" });
      for (const entry of Object.values(saved.entries)) {
        expect(entry).not.toHaveProperty("default");
      }
      expect(() => service.deleteAgent("second")).toThrow(
        "Default agent cannot be deleted",
      );
    });

    it("keeps the last agent of an explicit fleet (#126)", () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            ownership: "explicit",
            entries: { solo: { workspace: "/tmp/openclaw/workspace-solo" } },
          },
        },
      });

      expect(() => service.deleteAgent("solo")).toThrow(
        "The only configured agent cannot be deleted",
      );
      expect(Object.keys(fsMock.readConfig().agents.entries)).toEqual(["solo"]);
    });

    it("refuses to delete an explicit fleet's ownership targets (#126)", () => {
      const { fsMock, service } = buildService({
        initialConfig: {
          agents: {
            ownership: "explicit",
            defaults: {
              systemAgent: { agentId: "main" },
              authInheritance: { agentId: "creds" },
            },
            entries: {
              main: { workspace: "/tmp/openclaw/workspace" },
              creds: { workspace: "/tmp/openclaw/workspace-creds" },
              spare: { workspace: "/tmp/openclaw/workspace-spare" },
            },
          },
        },
      });

      expect(() => service.deleteAgent("creds")).toThrow(
        'Agent "creds" owns agents.defaults.authInheritance.agentId and cannot be deleted',
      );
      expect(service.deleteAgent("spare")).toMatchObject({ ok: true });
      expect(Object.keys(fsMock.readConfig().agents.entries)).toEqual([
        "main",
        "creds",
      ]);
    });

    it("rejects invalid workspace folder names", () => {
      expect(() =>
        resolveRequestedWorkspacePath({
          OPENCLAW_DIR,
          agentId: "ops",
          workspaceFolder: "Bad Folder",
        }),
      ).toThrow(
        "Workspace folder must be lowercase letters, numbers, and hyphens only",
      );
    });

    it("stats paths through lstat or stat and sizes directories recursively", () => {
      const lstatOnly = { lstatSync: vi.fn(() => ({ mode: 1 })) };
      expect(getSafeStat({ fsImpl: lstatOnly, targetPath: "/x" })).toEqual({
        mode: 1,
      });

      const statOnly = { statSync: vi.fn(() => ({ mode: 2 })) };
      expect(getSafeStat({ fsImpl: statOnly, targetPath: "/x" })).toEqual({
        mode: 2,
      });

      const statFor = {
        "/root": {
          isSymbolicLink: () => false,
          isFile: () => false,
          isDirectory: () => true,
        },
        "/root/a.txt": {
          isSymbolicLink: () => false,
          isFile: () => true,
          isDirectory: () => false,
          size: 10,
        },
        "/root/empty.txt": {
          isSymbolicLink: () => false,
          isFile: () => true,
          isDirectory: () => false,
        },
        "/root/link": { isSymbolicLink: () => true },
      };
      const fsImpl = {
        lstatSync: (targetPath) => {
          const stat = statFor[targetPath];
          if (!stat) throw new Error(`ENOENT: ${targetPath}`);
          return stat;
        },
        readdirSync: (targetPath) =>
          targetPath === "/root" ? ["a.txt", "empty.txt", "link"] : [],
      };
      expect(calculatePathSizeBytes({ fsImpl, targetPath: "/root" })).toBe(10);
      expect(calculatePathSizeBytes({ fsImpl, targetPath: "/missing" })).toBe(0);
    });
  });
});


it("preserves WhatsApp credentials and binding when restart is deferred by a hold", async () => {
  const { GatewayMutationBlockedError } = require("../../lib/server/gateway-mutation-policy");
  const restartGateway = vi.fn(async () => { throw new GatewayMutationBlockedError({
    code: "gateway_held", error: "held", hint: "Inspect Upgrade", statusCode: 409,
  }); });
  const { fsMock, service, clawCmd, writeEnvFile } = buildService({ restartGateway });
  const result = await service.createChannelAccount({ provider: "whatsapp", agentId: "main",
    token: "+15551230000", name: "WA" });
  expect(result).toMatchObject({ configSaved: true, restartDeferred: true,
    restartRequired: true, code: "gateway_held" });
  expect(fsMock.readConfig().channels.whatsapp.accounts.default).toBeTruthy();
  expect(fsMock.readConfig().bindings).toContainEqual({ agentId: "main",
    match: { channel: "whatsapp", accountId: "default" } });
  expect(clawCmd.mock.calls.some(([cmd]) => cmd.includes("channels remove"))).toBe(false);
  expect(writeEnvFile).toHaveBeenLastCalledWith(expect.arrayContaining([
    { key: "WHATSAPP_OWNER_NUMBER", value: "+15551230000" },
  ]));
});
