# PayAviator Backend

PayAviator Connected Accounts backend for Railway + Plaid + PostgreSQL.

**Authoritative deployment/setup instructions:** see `PAYAVIATOR-BACKEND.md` (Railway variables, encryption key generation, endpoints, and the required Android app changes).

Quick start (local Sandbox):

```bash
cp .env.example .env   # fill PLAID_CLIENT_ID / PLAID_SECRET, choose an auth mode
npm ci
npm test
npm start
```

What the Android app must send: `Authorization: Bearer <ID token>` on every `/api/plaid/*` request. The backend takes the user from the verified token, never from a `userId` in the URL or body. See "Android app changes required" in `PAYAVIATOR-BACKEND.md`.

Do not add version-specific `DEPLOY_*.md` files. Update the authoritative guide instead.
