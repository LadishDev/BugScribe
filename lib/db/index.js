// Resolve provider in the same forgiving way server.js uses so users don't have to
// set DB_PROVIDER explicitly. Prefer explicit DB_PROVIDER, otherwise infer from
// other env vars.
function resolveProvider() {
  const p = (process.env.DB_PROVIDER || '').toLowerCase();
  if (p) return p;
  if (process.env.DATABASE_URL) return 'postgres';
  if (process.env.DB_HOST || process.env.DB_USER || process.env.DB_PASSWORD) return 'postgres';
  if (process.env.DB_DATABASE || process.env.SQLITE_PATH) return 'sqlite';
  return 'sqlite';
}

const provider = resolveProvider();
let impl;
if (provider === 'postgres' || provider === 'pg') {
  impl = require('./postgres');
} else {
  impl = require('./sqlite');
}

module.exports = {
  init: (...args) => impl.init(...args),
  readBugReports: (...args) => impl.readBugReports(...args),
  writeBugReports: (...args) => impl.writeBugReports(...args),
  addBugReport: (...args) => impl.addBugReport(...args),
  readSuggestions: (...args) => impl.readSuggestions(...args),
  writeSuggestions: (...args) => impl.writeSuggestions(...args),
  addSuggestion: (...args) => impl.addSuggestion(...args),
  // IP history and spam/bot logs
  readIPHistory: (...args) => impl.readIPHistory ? impl.readIPHistory(...args) : Promise.resolve({}),
  appendIPHistory: (...args) => impl.appendIPHistory ? impl.appendIPHistory(...args) : Promise.resolve(),
  readSpamLog: (...args) => impl.readSpamLog ? impl.readSpamLog(...args) : Promise.resolve([]),
  appendSpamLog: (...args) => impl.appendSpamLog ? impl.appendSpamLog(...args) : Promise.resolve(),
  readBotAttempts: (...args) => impl.readBotAttempts ? impl.readBotAttempts(...args) : Promise.resolve([]),
  appendBotAttempt: (...args) => impl.appendBotAttempt ? impl.appendBotAttempt(...args) : Promise.resolve(),
  // Close/cleanup DB connections (optional)
  close: (...args) => impl.close ? impl.close(...args) : Promise.resolve(),
  // Event emitter from implementation (e.g. 'connected', 'disconnected')
  events: impl.events || null,
  // Readonly connected status
  isConnected: typeof impl.isConnected === 'function' ? impl.isConnected : () => false,
};
