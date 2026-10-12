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


## Bank persistence fix (backend 3.1.8)
This complete backend requires a configured Railway PostgreSQL `DATABASE_URL` and a
Firebase ID token from the signed-in PayAviator Android app on each `/api/plaid` request.
Bank connections are tied to the verified Firebase UID and retained in PostgreSQL, not
the server's temporary memory. Authentication uses Google's official Firebase
Secure Token signing certificates with RS256 verification using Node.js crypto.

Railway variables: `PLAID_CLIENT_ID`, `PLAID_SECRET`, `PLAID_ENV`,
`DATABASE_URL`, and `FIREBASE_PROJECT_ID=payaviator-app`. The health endpoint
`/api/health` must report `storage: postgres` and `databaseReady: true`.
If the database is down, banking returns HTTP 503 instead of claiming a connection
was saved. No banking secrets belong in GitHub.

Deploy the extracted project files to the **PayAviator-Backend** repository root.
Do not upload the ZIP as a single file into the repo. Existing bank links created
under the former generic identity or transient memory may require one reconnect.
