// Names (never values) of the non-empty variables in the environment the
// CURRENT long-running gateway daemon was spawned with. gateway.js records it
// at every daemon spawn (launch and cold restart); in-gateway supervisor
// restarts re-exec with the daemon's own env, so the record stays valid
// across them. null = this AlphaClaw process has not spawned a daemon (yet),
// so the running gateway's env is unknown.
//
// Consumer: channels.a2a.peer-upsert, which must not write a peer's
// "${VAR}" token reference while VAR is absent from the running gateway's env
// (generated or added by env.update after the spawn): OpenClaw hot-reloads
// channels.a2a and would keep the unresolved literal as the bearer.
let launchedKeys = null;

const recordGatewayLaunchEnv = (env) => {
  const source = env && typeof env === "object" ? env : {};
  launchedKeys = new Set(
    Object.keys(source).filter((key) => typeof source[key] === "string" && source[key] !== ""),
  );
};

const getGatewayLaunchEnvKeys = () => launchedKeys;

const resetGatewayLaunchEnvForTests = () => {
  launchedKeys = null;
};

module.exports = {
  recordGatewayLaunchEnv,
  getGatewayLaunchEnvKeys,
  resetGatewayLaunchEnvForTests,
};
