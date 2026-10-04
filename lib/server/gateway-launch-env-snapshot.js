// Names (never values) of the non-empty variables in the environment the
// CURRENT long-running gateway daemon was spawned with. gateway.js records it
// at every daemon spawn (launch and cold restart); in-gateway supervisor
// restarts re-exec with the daemon's own env, so the record stays valid
// across them. null = this AlphaClaw process has not spawned a daemon (yet),
// so the running gateway's env is unknown.
//
// Consumer: mcp.server-set, which must tell the caller when a header's
// ${VAR} exists in AlphaClaw's env but not in the running gateway's (it was
// added by env.update after the spawn), so a restart is needed before
// OpenClaw can resolve it.
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
