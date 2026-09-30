const path = require("path");
const { normalizeThinkingDefaultValue } = require("../openclaw-thinking");

const {
  kDefaultAgentId,
  resolveAgentWorkspacePath,
  loadConfig,
  saveConfig,
  cloneJson,
  getSafeStat,
  calculatePathSizeBytes,
  withNormalizedAgentsConfig,
  isExplicitAgentsOwnership,
  getExplicitDefaultAgentId,
  isValidAgentId,
  resolveRequestedWorkspacePath,
  ensureAgentScaffold,
} = require("./shared");

const toTitleWords = (value = "") =>
  String(value || "")
    .trim()
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const getFallbackAgentName = (agentId = "") => {
  const normalizedAgentId = String(agentId || "").trim();
  if (!normalizedAgentId) return "Agent";
  const title = toTitleWords(normalizedAgentId) || normalizedAgentId;
  return `${title} Agent`;
};

const getAgentDisplayName = (agent = {}) =>
  String(agent?.identity?.name || "").trim() ||
  String(agent?.name || "").trim() ||
  getFallbackAgentName(agent?.id || "");

// OpenClaw docs/gateway/config-agents/heartbeat-compaction-and-streaming.md.
const kExplicitAgentOwnerRoles = ["heartbeat", "authInheritance", "sessionStore"];

// Per-agent model settings (`agents.entries.<id>.models`), OpenClaw
// docs/gateway/config-agents/entries-and-multi-agent.md: keyed by full
// `provider/model` ids; each entry may carry `params`, `agentRuntime` and
// `codeMode`. Runtime ids from docs/concepts/agent-runtimes.md. OpenClaw
// 2026.9.5's validator accepts ANY agentRuntime.id (measured), so AlphaClaw
// checks it; unknown entry keys are rejected by both.
const kAgentRuntimeIds = new Set(["openclaw", "claude-cli", "codex", "copilot", "auto"]);
const kAgentModelEntryKeys = new Set(["params", "agentRuntime", "codeMode"]);
const kModelRefPattern = /^[a-z0-9][a-z0-9._-]*\/[^\s]+$/i;

const normalizeAgentModelsPatch = (models) => {
  if (!models || typeof models !== "object" || Array.isArray(models)) {
    throw new Error("models must be an object keyed by provider/model, or null");
  }
  const entries = [];
  for (const [rawKey, value] of Object.entries(models)) {
    const key = String(rawKey).trim();
    if (!kModelRefPattern.test(key)) {
      throw new Error(`models key "${rawKey}" is not a provider/model id`);
    }
    if (value === null) {
      entries.push([key, null]);
      continue;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`models["${key}"] must be an object or null`);
    }
    const unknown = Object.keys(value).filter((k) => !kAgentModelEntryKeys.has(k));
    if (unknown.length) {
      throw new Error(`models["${key}"] has unsupported keys: ${unknown.join(", ")}`);
    }
    const entry = {};
    if (value.agentRuntime !== undefined) {
      const runtime = value.agentRuntime;
      if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) {
        throw new Error(`models["${key}"].agentRuntime must be an object with an id`);
      }
      const extra = Object.keys(runtime).filter((k) => k !== "id");
      if (extra.length) {
        throw new Error(`models["${key}"].agentRuntime has unsupported keys: ${extra.join(", ")}`);
      }
      const id = String(runtime.id ?? "").trim();
      if (!kAgentRuntimeIds.has(id)) {
        throw new Error(
          `models["${key}"].agentRuntime.id must be one of ${[...kAgentRuntimeIds].join(", ")}`,
        );
      }
      entry.agentRuntime = { id };
    }
    if (value.params !== undefined) {
      if (!value.params || typeof value.params !== "object" || Array.isArray(value.params)) {
        throw new Error(`models["${key}"].params must be an object`);
      }
      entry.params = JSON.parse(JSON.stringify(value.params));
    }
    if (value.codeMode !== undefined) {
      if (typeof value.codeMode !== "boolean") {
        throw new Error(`models["${key}"].codeMode must be true or false`);
      }
      // OpenClaw rejects codeMode on wildcard entries such as "vllm/*".
      if (key.includes("*")) {
        throw new Error(`models["${key}"].codeMode is not allowed on a wildcard model ref`);
      }
      entry.codeMode = value.codeMode;
    }
    entries.push([key, entry]);
  }
  return entries;
};

const toReadableAgent = (agent = {}, cfg = {}) => ({
  ...agent,
  id: String(agent.id || "").trim(),
  name: getAgentDisplayName(agent),
  default: isExplicitAgentsOwnership(cfg)
    ? String(agent.id || "").trim() === getExplicitDefaultAgentId(cfg)
    : !!agent.default,
});

const createAgentsDomain = ({ fsImpl, OPENCLAW_DIR }) => {
  const readAgentsConfig = () =>
    withNormalizedAgentsConfig({
      OPENCLAW_DIR,
      cfg: loadConfig({ fsImpl, OPENCLAW_DIR }),
    });

  const getAgentDefaults = () => {
    const cfg = readAgentsConfig();
    const thinkingDefault = cfg.agents?.defaults?.thinkingDefault;
    return {
      thinkingDefault:
        typeof thinkingDefault === "string" && thinkingDefault.trim()
          ? thinkingDefault.trim()
          : null,
    };
  };

  const listAgents = () => {
    const cfg = readAgentsConfig();
    return (cfg.agents?.list || []).map((entry) => toReadableAgent(entry, cfg));
  };

  const getAgent = (agentId) => {
    const normalized = String(agentId || "").trim();
    return listAgents().find((entry) => entry.id === normalized) || null;
  };

  const getAgentWorkspaceSize = (agentId) => {
    const normalized = String(agentId || "").trim();
    const agent = getAgent(normalized);
    if (!agent) throw new Error(`Agent "${normalized}" not found`);
    const workspacePath = String(
      agent.workspace ||
        resolveAgentWorkspacePath({ OPENCLAW_DIR, agentId: normalized }),
    ).trim();
    if (!workspacePath) {
      return { workspacePath: "", exists: false, sizeBytes: 0 };
    }
    const stat = getSafeStat({ fsImpl, targetPath: workspacePath });
    if (!stat) {
      return { workspacePath, exists: false, sizeBytes: 0 };
    }
    return {
      workspacePath,
      exists: true,
      sizeBytes: calculatePathSizeBytes({ fsImpl, targetPath: workspacePath }),
    };
  };

  const createAgent = (input = {}) => {
    const agentId = String(input.id || "").trim();
    if (!isValidAgentId(agentId)) {
      throw new Error(
        "Agent id must be lowercase letters, numbers, and hyphens only",
      );
    }

    const cfg = withNormalizedAgentsConfig({
      OPENCLAW_DIR,
      cfg: loadConfig({ fsImpl, OPENCLAW_DIR }),
    });
    const existing = cfg.agents.list.find((entry) => entry.id === agentId);
    if (existing) {
      throw new Error(`Agent "${agentId}" already exists`);
    }

    const workspacePath = resolveRequestedWorkspacePath({
      OPENCLAW_DIR,
      agentId,
      workspaceFolder: input.workspaceFolder,
    });
    const { workspacePath: scaffoldWorkspacePath, agentDirPath } =
      ensureAgentScaffold({
        fsImpl,
        workspacePath,
        OPENCLAW_DIR,
        agentId,
      });
    const requestedIdentity =
      input.identity && typeof input.identity === "object"
        ? { ...input.identity }
        : {};
    const requestedName = String(input.name || "").trim();
    const identityName =
      requestedName ||
      String(requestedIdentity.name || "").trim() ||
      getFallbackAgentName(agentId);
    const nextAgent = {
      id: agentId,
      default: false,
      workspace: scaffoldWorkspacePath,
      agentDir: agentDirPath,
      identity: {
        ...requestedIdentity,
        name: identityName,
      },
      ...(input.model ? { model: input.model } : {}),
    };
    cfg.agents.list = [...cfg.agents.list, nextAgent];
    saveConfig({ fsImpl, OPENCLAW_DIR, config: cfg });
    return toReadableAgent(nextAgent, cfg);
  };

  const updateAgent = async (agentId, patch = {}) => {
    const normalized = String(agentId || "").trim();
    const cfg = readAgentsConfig();
    const index = cfg.agents.list.findIndex((entry) => entry.id === normalized);
    if (index < 0) throw new Error(`Agent "${normalized}" not found`);
    const current = cfg.agents.list[index];
    const next = { ...current };
    const identityPatched =
      patch.identity !== undefined || patch.name !== undefined;
    if (identityPatched) {
      const baseIdentity =
        patch.identity !== undefined
          ? patch.identity && typeof patch.identity === "object"
            ? { ...patch.identity }
            : {}
          : current.identity && typeof current.identity === "object"
            ? { ...current.identity }
            : {};
      const requestedName =
        patch.name !== undefined
          ? String(patch.name || "").trim()
          : String(baseIdentity.name || "").trim();
      const fallbackLegacyName = String(current.name || "").trim();
      baseIdentity.name =
        requestedName || fallbackLegacyName || getFallbackAgentName(normalized);
      next.identity = baseIdentity;
      // Only remove legacy top-level name once identity.name is persisted.
      delete next.name;
    }
    if (patch.model !== undefined) {
      if (patch.model === null) {
        delete next.model;
      } else {
        next.model = patch.model;
      }
    }
    if (patch.tools !== undefined) {
      if (patch.tools && typeof patch.tools === "object") {
        const toolsCfg = {};
        if (patch.tools.profile) toolsCfg.profile = String(patch.tools.profile);
        if (
          Array.isArray(patch.tools.alsoAllow) &&
          patch.tools.alsoAllow.length
        ) {
          toolsCfg.alsoAllow = patch.tools.alsoAllow.map(String);
        }
        if (Array.isArray(patch.tools.deny) && patch.tools.deny.length) {
          toolsCfg.deny = patch.tools.deny.map(String);
        }
        next.tools = toolsCfg;
      } else {
        delete next.tools;
      }
    }
    if (patch.models !== undefined) {
      if (patch.models === null) {
        delete next.models;
      } else {
        // Merge by model id: an entry replaces that model's settings, null
        // removes it; other models' settings are kept.
        const merged =
          current.models && typeof current.models === "object" ? { ...current.models } : {};
        for (const [key, entry] of normalizeAgentModelsPatch(patch.models)) {
          if (entry === null) delete merged[key];
          else merged[key] = entry;
        }
        if (Object.keys(merged).length > 0) next.models = merged;
        else delete next.models;
      }
    }
    if (patch.thinkingDefault !== undefined) {
      if (patch.thinkingDefault === null) {
        delete next.thinkingDefault;
      } else {
        const normalizedThinking = await normalizeThinkingDefaultValue(
          patch.thinkingDefault,
        );
        if (!normalizedThinking) {
          throw new Error("Invalid thinkingDefault value");
        }
        next.thinkingDefault = normalizedThinking;
      }
    }
    cfg.agents.list[index] = next;
    saveConfig({ fsImpl, OPENCLAW_DIR, config: cfg });
    return toReadableAgent(next, cfg);
  };

  const setDefaultAgent = (agentId) => {
    const normalized = String(agentId || "").trim();
    const cfg = withNormalizedAgentsConfig({
      OPENCLAW_DIR,
      cfg: loadConfig({ fsImpl, OPENCLAW_DIR }),
    });
    const exists = cfg.agents.list.some((entry) => entry.id === normalized);
    if (!exists) throw new Error(`Agent "${normalized}" not found`);
    if (isExplicitAgentsOwnership(cfg)) {
      // OpenClaw rejects `default` markers on an explicit fleet (#126); its
      // recorded default is the system agent.
      const defaults = cfg.agents.defaults || {};
      cfg.agents.defaults = {
        ...defaults,
        systemAgent: { ...(defaults.systemAgent || {}), agentId: normalized },
      };
      saveConfig({ fsImpl, OPENCLAW_DIR, config: cfg });
      const target = cfg.agents.list.find((entry) => entry.id === normalized);
      return toReadableAgent(target, cfg);
    }
    cfg.agents.list = cfg.agents.list.map((entry) => ({
      ...entry,
      default: entry.id === normalized,
    }));
    saveConfig({ fsImpl, OPENCLAW_DIR, config: cfg });
    return cfg.agents.list.find((entry) => entry.id === normalized) || null;
  };

  const deleteAgent = (agentId, { keepWorkspace = true } = {}) => {
    const normalized = String(agentId || "").trim();
    if (!normalized || normalized === kDefaultAgentId) {
      throw new Error("The default main agent cannot be deleted");
    }
    const cfg = withNormalizedAgentsConfig({
      OPENCLAW_DIR,
      cfg: loadConfig({ fsImpl, OPENCLAW_DIR }),
    });
    const target = cfg.agents.list.find((entry) => entry.id === normalized);
    if (!target) throw new Error(`Agent "${normalized}" not found`);
    if (isExplicitAgentsOwnership(cfg)) {
      // Explicit fleets record ownership in agents.defaults.*.agentId; deleting
      // an owner leaves a reference OpenClaw rejects and doctor cannot repair.
      // No implicit `main` backs an explicit roster, so keep one agent.
      if (cfg.agents.list.length <= 1) {
        throw new Error("The only configured agent cannot be deleted");
      }
      if (getExplicitDefaultAgentId(cfg) === normalized) {
        throw new Error("Default agent cannot be deleted");
      }
      const ownedRole = kExplicitAgentOwnerRoles.find(
        (role) =>
          String(cfg.agents.defaults?.[role]?.agentId || "").trim() ===
          normalized,
      );
      if (ownedRole) {
        throw new Error(
          `Agent "${normalized}" owns agents.defaults.${ownedRole}.agentId and cannot be deleted`,
        );
      }
    } else if (target.default) {
      throw new Error("Default agent cannot be deleted");
    }
    cfg.agents.list = cfg.agents.list.filter(
      (entry) => entry.id !== normalized,
    );
    if (Array.isArray(cfg.bindings)) {
      cfg.bindings = cfg.bindings.filter(
        (binding) => String(binding?.agentId || "") !== normalized,
      );
    }
    saveConfig({ fsImpl, OPENCLAW_DIR, config: cfg });

    if (!keepWorkspace) {
      const workspacePath = String(
        target.workspace ||
          resolveAgentWorkspacePath({
            OPENCLAW_DIR,
            agentId: normalized,
          }),
      ).trim();
      const agentDirPath = path.join(OPENCLAW_DIR, "agents", normalized);
      if (workspacePath) {
        fsImpl.rmSync(workspacePath, { recursive: true, force: true });
      }
      fsImpl.rmSync(agentDirPath, { recursive: true, force: true });
    }
    return { ok: true };
  };

  return {
    listAgents,
    getAgent,
    getAgentDefaults,
    getAgentWorkspaceSize,
    createAgent,
    updateAgent,
    setDefaultAgent,
    deleteAgent,
  };
};

module.exports = { createAgentsDomain };
