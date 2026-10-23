// Topic → agent integrity for Telegram forum topics.
//
// OpenClaw routes a topic to `channels.telegram[.accounts.<id>].groups.<g>.topics.<t>.agentId`
// (docs/channels/telegram/threads-and-sessions.md, "Per-topic agent routing").
// Read from implementation (2026.10.6, dist/conversation-route-*.mjs): the
// route override uses that id after id normalization, with no roster check,
// and `openclaw config validate` accepts an id that names no configured agent.
// So AlphaClaw checks the id against the roster before it writes one, and
// clears references when it deletes an agent.

const { withNormalizedAgentsConfig } = require("./agents/shared");
const { normalizeOpenclawAgentId } = require("./topic-name-cache");
const { isNonArrayObject } = require("./utils/object");

// Agent ids the gateway knows: the configured roster plus the implicit main
// agent AlphaClaw presents for a non-explicit config (withNormalizedAgentsConfig).
// Compared in OpenClaw's normalized form, which is what the topic route applies.
const listKnownAgentIds = ({ cfg, openclawDir }) => {
  const normalized = withNormalizedAgentsConfig({ OPENCLAW_DIR: openclawDir, cfg: cfg || {} });
  const list = Array.isArray(normalized?.agents?.list) ? normalized.agents.list : [];
  return list.map((entry) => normalizeOpenclawAgentId(entry?.id));
};

// Returns null when `agentId` may be written to a topic, else an error
// message. An empty id unroutes the topic and is always allowed.
const checkTopicAgentId = ({ cfg, openclawDir, agentId }) => {
  const id = String(agentId ?? "").trim();
  if (!id) return null;
  const known = listKnownAgentIds({ cfg, openclawDir });
  if (known.includes(normalizeOpenclawAgentId(id))) return null;
  return `Unknown agent "${id}" for topic routing (configured agents: ${known.join(", ") || "none"})`;
};

// Every group container of the Telegram channel: the top-level config and
// each account.
const forEachTelegramGroups = (cfg, visit) => {
  const telegram = cfg?.channels?.telegram;
  if (!isNonArrayObject(telegram)) return;
  if (isNonArrayObject(telegram.groups)) visit({ accountId: null, groups: telegram.groups });
  if (isNonArrayObject(telegram.accounts)) {
    for (const [accountId, account] of Object.entries(telegram.accounts)) {
      if (isNonArrayObject(account?.groups)) visit({ accountId, groups: account.groups });
    }
  }
};

// Removes `agentId` from every topic routed to `agentId` in openclaw.json
// (mutates cfg). A topic left with no keys is removed; an emptied `topics`
// object is removed. Returns the cleared references.
const clearTopicAgentRefsInConfig = (cfg, agentId) => {
  const id = normalizeOpenclawAgentId(agentId);
  const cleared = [];
  forEachTelegramGroups(cfg, ({ accountId, groups }) => {
    for (const [groupId, group] of Object.entries(groups)) {
      if (!isNonArrayObject(group?.topics)) continue;
      for (const [threadId, topic] of Object.entries(group.topics)) {
        if (!isNonArrayObject(topic) || !topic.agentId) continue;
        if (normalizeOpenclawAgentId(topic.agentId) !== id) continue;
        delete topic.agentId;
        if (Object.keys(topic).length === 0) delete group.topics[threadId];
        cleared.push({ ...(accountId ? { accountId } : {}), groupId, threadId });
      }
      if (Object.keys(group.topics).length === 0) delete group.topics;
    }
  });
  return cleared;
};

module.exports = {
  listKnownAgentIds,
  checkTopicAgentId,
  clearTopicAgentRefsInConfig,
};
