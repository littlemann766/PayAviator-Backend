-- Reviewed schema for subscription-restore holds and checkout idempotency.
-- Not executed against production by this change.
-- The server's PgStore.init() creates the same tables with IF NOT EXISTS on the next boot
-- of this build. Do not run this by hand against the live database from the agent environment.

CREATE TABLE IF NOT EXISTS billing_recovery_holds (
  user_id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  duplicate_checkout_blocked BOOLEAN NOT NULL DEFAULT TRUE,
  token_hash TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE billing_recovery_holds ADD COLUMN IF NOT EXISTS token_hash TEXT;

CREATE TABLE IF NOT EXISTS stripe_checkout_sessions (
  user_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- token_hash is sha256 of a Play purchase token. Do not add a raw token, receipt, email, or other user's id.
-- stripe_checkout_sessions.session_id is the Checkout Session id our server created for that uid.
