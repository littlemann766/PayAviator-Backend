// Minimal structured (JSON lines) logger. Never pass access tokens, public
// tokens, secrets or full axios errors in fields: axios errors carry request
// headers, which include PLAID-SECRET.
function emit(level, msg, fields = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields });
  if (level === 'error' || level === 'warn') console.error(line);
  else console.log(line);
}

export const log = {
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};

export const silentLog = { info() {}, warn() {}, error() {} };
