// Per-agent tool policy (`agents.entries.<id>.tools`) for agents.update.
//
// Documented contract (OpenClaw 2026.9.5): docs/gateway/config-tools/tool-policy.md
// (profiles, allow/deny, "allow and alsoAllow cannot both be set in the same
// scope"), docs/tools/multi-agent-sandbox-tools.md (filtering order: each layer
// can only further restrict; `agents.entries.*.tools.profile` overrides
// `tools.profile`), docs/cli/policy/rules.md (per-agent `tools.fs` overrides).
// Read from implementation (dist, same version): the effective profile is
// `agentTools.profile ?? tools.profile`; the profile's alsoAllow is
// `agentTools.alsoAllow ?? tools.alsoAllow`; the agent `allow` list is a later
// filter step (intersection) and an EMPTY allow list matches every tool;
// `fs.workspaceOnly` is `agentTools.fs.workspaceOnly ?? tools.fs.workspaceOnly`.
//
// AlphaClaw manages `profile`, `allow`, `alsoAllow`, `deny` (replaced as one
// unit, as the Setup UI derives them together) and `fs.workspaceOnly`
// (patched field by field). Every other per-agent tools key (elevated, exec,
// byProvider, toolsBySender, sandbox, message, codeMode, ...) is kept as is.

const kToolProfiles = ["minimal", "coding", "messaging", "full"];
const kSelectionKeys = ["profile", "allow", "alsoAllow", "deny"];
const kPatchKeys = new Set([...kSelectionKeys, "fs"]);
const kMaxToolEntries = 500;

const isPlainObject = (value) =>
  !!value && typeof value === "object" && !Array.isArray(value);

const normalizeToolList = (value, field) => {
  if (!Array.isArray(value)) throw new Error(`tools.${field} must be an array of tool names`);
  const out = [];
  const seen = new Set();
  for (const entry of value) {
    if (typeof entry !== "string") throw new Error(`tools.${field} entries must be strings`);
    const name = entry.trim();
    if (!name || /\s/.test(name) || name.length > 200) {
      throw new Error(`tools.${field} entry "${entry}" is not a tool name`);
    }
    if (!seen.has(name)) {
      seen.add(name);
      out.push(name);
    }
  }
  if (out.length > kMaxToolEntries) {
    throw new Error(`tools.${field} accepts at most ${kMaxToolEntries} entries`);
  }
  return out;
};

// Validates a `tools` patch. Returns null (remove the agent's tools config) or
// { selection, fs } where selection holds the managed selection keys and fs is
// undefined (keep), null (remove) or { workspaceOnly: true|false|null }.
const normalizeAgentToolsPatch = (tools) => {
  if (tools === null) return null;
  if (!isPlainObject(tools)) {
    throw new Error("tools must be an object ({profile, allow, alsoAllow, deny, fs}) or null");
  }
  const unknown = Object.keys(tools).filter((key) => !kPatchKeys.has(key));
  if (unknown.length) {
    throw new Error(`tools has unsupported keys: ${unknown.join(", ")}`);
  }
  const selection = {};
  if (tools.profile !== undefined && tools.profile !== null && tools.profile !== "") {
    const profile = String(tools.profile).trim();
    if (!kToolProfiles.includes(profile)) {
      throw new Error(`tools.profile must be one of ${kToolProfiles.join(", ")}`);
    }
    selection.profile = profile;
  }
  if (tools.allow === null) {
    selection.allow = null; // explicit removal
  } else if (tools.allow !== undefined) {
    const allow = normalizeToolList(tools.allow, "allow");
    // OpenClaw treats an empty allow list as "every tool": refuse it rather
    // than store something that reads as "no tools".
    if (!allow.length) {
      throw new Error(
        "tools.allow must name at least one tool (an empty allow list allows every tool; use deny to remove tools)",
      );
    }
    selection.allow = allow;
  }
  if (tools.alsoAllow !== undefined && tools.alsoAllow !== null) {
    const alsoAllow = normalizeToolList(tools.alsoAllow, "alsoAllow");
    if (alsoAllow.length) selection.alsoAllow = alsoAllow;
  }
  if (tools.deny !== undefined && tools.deny !== null) {
    const deny = normalizeToolList(tools.deny, "deny");
    if (deny.length) selection.deny = deny;
  }
  if (Array.isArray(selection.allow) && selection.alsoAllow) {
    throw new Error(
      "tools cannot set both allow and alsoAllow (merge alsoAllow into allow, or drop allow and use profile + alsoAllow)",
    );
  }
  let fs;
  if (tools.fs === null) {
    fs = null;
  } else if (tools.fs !== undefined) {
    if (!isPlainObject(tools.fs)) throw new Error("tools.fs must be an object ({workspaceOnly}) or null");
    const extra = Object.keys(tools.fs).filter((key) => key !== "workspaceOnly");
    if (extra.length) throw new Error(`tools.fs has unsupported keys: ${extra.join(", ")}`);
    const value = tools.fs.workspaceOnly;
    if (value !== undefined && value !== null && typeof value !== "boolean") {
      throw new Error("tools.fs.workspaceOnly must be true, false or null");
    }
    fs = value === undefined ? {} : { workspaceOnly: value };
  }
  // A supplied alsoAllow (even []) replaces the selection, so it also
  // replaces a kept allow list (codex).
  const alsoAllowSupplied = Array.isArray(tools.alsoAllow);
  return { selection, fs, alsoAllowSupplied };
};

// Next per-agent tools object after a patch, or undefined when removed.
// `allow` is kept when the patch omits it and sets no alsoAllow (the Setup UI
// edits profile/alsoAllow/deny only and must not drop an allow list set via
// the API); `allow: null` removes it, and an alsoAllow in the patch replaces
// it (OpenClaw refuses both in one scope).
const applyAgentToolsPatch = (currentTools, tools) => {
  const patch = normalizeAgentToolsPatch(tools);
  if (patch === null) return undefined;
  const current = isPlainObject(currentTools) ? currentTools : {};
  if (patch.selection.allow === null) {
    delete patch.selection.allow;
  } else if (
    patch.selection.allow === undefined &&
    !patch.alsoAllowSupplied &&
    Array.isArray(current.allow) &&
    current.allow.length > 0
  ) {
    patch.selection.allow = [...current.allow];
  }
  const next = {};
  for (const [key, value] of Object.entries(current)) {
    if (!kSelectionKeys.includes(key)) next[key] = value;
  }
  // Selection keys first, in a stable order.
  const ordered = {};
  for (const key of kSelectionKeys) {
    if (patch.selection[key] !== undefined) ordered[key] = patch.selection[key];
  }
  Object.assign(ordered, next);
  if (patch.fs === null) {
    delete ordered.fs;
  } else if (patch.fs !== undefined) {
    const fs = isPlainObject(current.fs) ? { ...current.fs } : {};
    if (patch.fs.workspaceOnly === null) delete fs.workspaceOnly;
    else if (patch.fs.workspaceOnly !== undefined) fs.workspaceOnly = patch.fs.workspaceOnly;
    if (Object.keys(fs).length) ordered.fs = fs;
    else delete ordered.fs;
  }
  return ordered;
};

// ---- tier classification -------------------------------------------------

const lowerSet = (list) =>
  new Set((Array.isArray(list) ? list : []).map((name) => String(name).trim().toLowerCase()));

const isSubset = (inner, outer) => [...inner].every((name) => outer.has(name));

// Profile inclusion. Only `full` is provably a superset of every profile
// (it contributes a wildcard to plugin tool selection). The docs table nests
// minimal inside messaging/coding for CORE tools, but a loaded plugin may
// declare a tool for one profile only, so any other profile change is not
// provably narrowing (codex) and stays dangerous.
const profileWithin = (inner, outer) => inner === outer || outer === "full";

// Core tool ids and groups as listed in docs/gateway/config-tools/tool-policy.md
// ("Tool groups"); a built-in missing from that table (e.g. `ls`) is treated
// conservatively as possibly plugin-owned. Read from implementation: every entry of an agent `allow` list is
// also collected into the explicit plugin-tool allowlist, which is what opts
// an OPTIONAL plugin tool in. So a NEW allow list narrows only when each entry
// is a core tool or core group (never group:plugins, a plugin id or a glob),
// or was already granted by the effective alsoAllow.
const kCoreToolNames = new Set([
  "exec", "bash", "process", "code_execution",
  "read", "write", "edit", "apply_patch",
  "sessions", "sessions_list", "sessions_history", "sessions_search",
  "conversations_list", "conversations_send", "conversations_turn",
  "sessions_send", "sessions_spawn", "sessions_yield", "subagents",
  "session_status", "suggest_task", "dismiss_task",
  "memory_search", "memory_get",
  "web_search", "x_search", "web_fetch",
  "browser", "screen", "dashboard", "terminal", "portal", "canvas", "show_widget",
  "heartbeat_respond", "automations", "cron", "gateway", "plugins", "openclaw",
  "message", "nodes", "computer",
  "agents_list", "get_goal", "create_goal", "update_goal", "progress_card",
  "ask_user", "skill_workshop",
  "view_image", "image_generate", "music_generate", "video_generate", "tts", "pdf",
  "group:runtime", "group:fs", "group:sessions", "group:memory", "group:web",
  "group:ui", "group:automation", "group:messaging", "group:nodes",
  "group:agents", "group:media", "group:openclaw",
]);

const effectiveToolState = (agentTools, globalTools) => {
  const own = isPlainObject(agentTools) ? agentTools : {};
  const global = isPlainObject(globalTools) ? globalTools : {};
  const profile = own.profile || global.profile || "unset";
  const alsoAllow = Array.isArray(own.alsoAllow)
    ? own.alsoAllow
    : Array.isArray(global.alsoAllow)
      ? global.alsoAllow
      : [];
  const allow =
    Array.isArray(own.allow) && own.allow.length > 0 && !own.allow.some((n) => String(n).trim() === "*")
      ? lowerSet(own.allow)
      : null; // null: the agent step does not restrict
  const ownWorkspaceOnly = isPlainObject(own.fs) ? own.fs.workspaceOnly : undefined;
  const globalWorkspaceOnly = isPlainObject(global.fs) ? global.fs.workspaceOnly : undefined;
  return {
    profile,
    alsoAllow: lowerSet(alsoAllow),
    allowEntries: lowerSet(own.allow),
    allow,
    deny: lowerSet(own.deny),
    workspaceOnly: (ownWorkspaceOnly ?? globalWorkspaceOnly) === true,
  };
};

// True when `next` exposes no tool and no filesystem reach that `current`
// did not. Conservative: anything not provably narrowing counts as widening
// (a deny entry swapped for a covering group, for example).
const isToolsNarrowing = ({ currentTools, nextTools, globalTools }) => {
  const before = effectiveToolState(currentTools, globalTools);
  const after = effectiveToolState(nextTools, globalTools);
  if (!profileWithin(after.profile, before.profile)) return false;
  if (!isSubset(after.alsoAllow, before.alsoAllow)) return false;
  if (before.allow && (!after.allow || !isSubset(after.allow, before.allow))) return false;
  const optsInPluginTool = [...after.allowEntries].some(
    (name) =>
      !before.allowEntries.has(name) && !kCoreToolNames.has(name) && !before.alsoAllow.has(name),
  );
  if (optsInPluginTool) return false;
  if (!isSubset(before.deny, after.deny)) return false;
  if (before.workspaceOnly && !after.workspaceOnly) return false;
  // Keys AlphaClaw does not manage (elevated, exec, byProvider, ...) must
  // come through unchanged; any difference there is not proven narrowing.
  const own = (tools) => (isPlainObject(tools) ? tools : {});
  const unmanaged = (tools) =>
    Object.keys(own(tools)).filter((key) => !kPatchKeys.has(key));
  const keys = new Set([...unmanaged(currentTools), ...unmanaged(nextTools)]);
  for (const key of keys) {
    if (JSON.stringify(own(currentTools)[key]) !== JSON.stringify(own(nextTools)[key])) return false;
  }
  return true;
};

module.exports = {
  kToolProfiles,
  normalizeAgentToolsPatch,
  applyAgentToolsPatch,
  isToolsNarrowing,
  effectiveToolState,
};
