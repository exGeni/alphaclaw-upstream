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
  if (tools.allow !== undefined && tools.allow !== null) {
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
  if (selection.allow && selection.alsoAllow) {
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
  return { selection, fs };
};

// Next per-agent tools object after a patch, or undefined when removed.
const applyAgentToolsPatch = (currentTools, tools) => {
  const patch = normalizeAgentToolsPatch(tools);
  if (patch === null) return undefined;
  const current = isPlainObject(currentTools) ? currentTools : {};
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

// Profile inclusion (docs table): minimal is inside messaging and coding;
// every profile is inside `full`; an unset profile leaves core tools
// unfiltered (so it holds messaging/coding/minimal) but, unlike `full`, does
// not opt into optional plugin tools.
const profileWithin = (inner, outer) => {
  if (inner === outer) return true;
  if (outer === "full") return true;
  if (inner === "minimal") return true;
  if (outer === "unset") return inner !== "full";
  return false;
};

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
