// Per-agent tool policy (`agents.list[].tools`) for agents.update.
//
// Documented contract (OpenClaw 2026.10.6): docs/gateway/config-tools/tool-policy.md
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
    // An own empty alsoAllow is kept: OpenClaw reads an absent key as "use
    // tools.alsoAllow" but an own [] as "no additions".
    selection.alsoAllow = normalizeToolList(tools.alsoAllow, "alsoAllow");
  }
  if (tools.deny !== undefined && tools.deny !== null) {
    const deny = normalizeToolList(tools.deny, "deny");
    if (deny.length) selection.deny = deny;
  }
  if (Array.isArray(selection.allow) && selection.alsoAllow?.length) {
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
  // OpenClaw rejects allow together with a NON-EMPTY alsoAllow in one scope
  // (an empty alsoAllow is valid next to allow).
  const alsoAllowSupplied = (selection.alsoAllow?.length ?? 0) > 0;
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
    Array.isArray(current.allow) &&
    current.allow.length > 0
  ) {
    if (patch.alsoAllowSupplied) {
      // Replacing a strict allow list silently would widen the agent.
      throw new Error(
        "this agent has a strict tools.allow list and allow cannot be combined with alsoAllow; send allow: null to replace it with profile + alsoAllow",
      );
    }
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

module.exports = {
  kToolProfiles,
  normalizeAgentToolsPatch,
  applyAgentToolsPatch,
};
