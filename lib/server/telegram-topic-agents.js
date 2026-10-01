// Topic → agent integrity for Telegram forum topics.
//
// OpenClaw routes a topic to `channels.telegram[.accounts.<id>].groups.<g>.topics.<t>.agentId`
// (docs/channels/telegram/threads-and-sessions.md, "Per-topic agent routing").
// Read from implementation (2026.9.5): the route override uses that id as is
// (sanitized, no roster check), and `openclaw config validate` accepts an id
// that names no configured agent. So AlphaClaw checks the id against the roster
// before it writes one, and clears references when it deletes an agent.

const { withNormalizedAgentsConfig } = require("./agents/shared");

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);

// Agent ids the gateway knows: the configured roster plus the implicit main
// agent AlphaClaw presents for a non-explicit config (withNormalizedAgentsConfig).
const listKnownAgentIds = ({ cfg, openclawDir }) => {
  const normalized = withNormalizedAgentsConfig({ OPENCLAW_DIR: openclawDir, cfg: cfg || {} });
  const list = Array.isArray(normalized?.agents?.list) ? normalized.agents.list : [];
  return list.map((entry) => String(entry?.id || "").trim()).filter(Boolean);
};

// Returns null when `agentId` may be written to a topic, else an error
// message. An empty id unroutes the topic and is always allowed.
const checkTopicAgentId = ({ cfg, openclawDir, agentId }) => {
  const id = String(agentId ?? "").trim();
  if (!id) return null;
  if (!cfg) return `Cannot check agent "${id}": openclaw.json is missing or unreadable`;
  const known = listKnownAgentIds({ cfg, openclawDir });
  if (known.includes(id)) return null;
  return `Unknown agent "${id}" for topic routing (configured agents: ${known.join(", ") || "none"})`;
};

// Every group container of the Telegram channel: the top-level config and
// each account.
const forEachTelegramGroups = (cfg, visit) => {
  const telegram = cfg?.channels?.telegram;
  if (!isRecord(telegram)) return;
  if (isRecord(telegram.groups)) visit({ accountId: null, groups: telegram.groups });
  if (isRecord(telegram.accounts)) {
    for (const [accountId, account] of Object.entries(telegram.accounts)) {
      if (isRecord(account?.groups)) visit({ accountId, groups: account.groups });
    }
  }
};

// Removes `agentId` from every topic routed to `agentId` in openclaw.json
// (mutates cfg). A topic left with no keys is removed; an emptied `topics`
// object is removed. Returns the cleared references.
const clearTopicAgentRefsInConfig = (cfg, agentId) => {
  const id = String(agentId || "").trim();
  const cleared = [];
  if (!id) return cleared;
  forEachTelegramGroups(cfg, ({ accountId, groups }) => {
    for (const [groupId, group] of Object.entries(groups)) {
      if (!isRecord(group?.topics)) continue;
      for (const [threadId, topic] of Object.entries(group.topics)) {
        if (!isRecord(topic) || String(topic.agentId || "").trim() !== id) continue;
        delete topic.agentId;
        if (Object.keys(topic).length === 0) delete group.topics[threadId];
        cleared.push({ ...(accountId ? { accountId } : {}), groupId, threadId });
      }
      if (Object.keys(group.topics).length === 0) delete group.topics;
    }
  });
  return cleared;
};

// Key-level diff of one group's `topics` object before and after a rebuild.
const diffTopicConfig = (before, after) => {
  const prev = isRecord(before) ? before : {};
  const next = isRecord(after) ? after : {};
  const removed = Object.keys(prev).filter((key) => !(key in next));
  const added = Object.keys(next).filter((key) => !(key in prev));
  const changed = Object.keys(next).filter(
    (key) => key in prev && JSON.stringify(prev[key]) !== JSON.stringify(next[key]),
  );
  return { removed, added, changed };
};

const hasTopicChanges = (diff) =>
  !!diff && (diff.removed.length > 0 || diff.added.length > 0 || diff.changed.length > 0);

const formatTopicChanges = (diff) => {
  if (!hasTopicChanges(diff)) return "";
  const parts = [];
  if (diff.removed.length) parts.push(`removed=${diff.removed.join(",")}`);
  if (diff.added.length) parts.push(`added=${diff.added.join(",")}`);
  if (diff.changed.length) parts.push(`changed=${diff.changed.join(",")}`);
  return parts.join(" ");
};

module.exports = {
  listKnownAgentIds,
  checkTopicAgentId,
  clearTopicAgentRefsInConfig,
  diffTopicConfig,
  hasTopicChanges,
  formatTopicChanges,
};
