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

## Billing: one bank free (backend 4.1.0, PR billing-one-free-bank)

- Signed-in users get **1 active linked bank** (Plaid Item; revoked items don't count) for free. Adding another needs an active Google Play subscription.
- Enforced on `POST /api/plaid/create-link-token` and on the token exchange (`POST /api/plaid/exchange-public-token` and hosted-status add mode), **before** any Plaid exchange, so no extra Item is created. Update mode (`/api/plaid/update-link-token`, `/api/plaid/update-complete`) and re-sending an already-exchanged public token are never blocked.
- Over the limit: `402 {"error":"subscription_required","code":"SUBSCRIPTION_REQUIRED","limit":1,"linked":n}`.
- **Grandfathering:** users who already have more than one bank keep all of them and can reconnect them; they just can't add another without subscribing. Nothing is removed. `GET /api/billing/status` shows `grandfathered: true` for them.
- `GET /api/billing/status` → `{plan:"free"|"premium", linkedBanks, limit:1|null, expiresAt:ISO|null, productId, state, grandfathered, billingConfigured}`.
- `POST /api/billing/google-play/verify {productId, purchaseToken}` → checks Google Play `purchases.subscriptionsv2.get`, stores an entitlement (sha256 of the token only), acknowledges it. 200 with the status body when active; 402 `subscription_inactive`; 400 `missing_purchase|unknown_product|product_mismatch|invalid_purchase`; 409 `purchase_in_use`; 502 `verify_failed`; 503 `billing_not_configured`.
- `POST /api/billing/google-play/rtdn` (Pub/Sub push, OIDC bearer verified; needs `GOOGLE_PLAY_RTDN_AUDIENCE`) refreshes known entitlements on renewals/cancels/expiry.
- Env: see `.env.example` (Google Play section).
