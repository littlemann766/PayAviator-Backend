# PayAviator Backend Authority — 9.5.8

This is the single deployment authority for the PayAviator banking backend.

## Runtime
- Node/Express backend for Plaid read-only connected accounts.
- Railway production service remains the app backend.
- App version: 9.5.8.

## Required endpoints
- Health/version endpoint
- Plaid link-token / hosted-link flow
- Public-token exchange / completion flow
- Connected account balance retrieval
- Transaction retrieval for the app Sync action
- Multi-institution persistence

## Financial rule
Transactions returned to the app are history/information. The app uses live included balances for Available Now, so transaction history must not be subtracted a second time.

## Security
Keep Plaid secrets and database credentials only in Railway environment variables. Never place secrets in the Android/WebView app.

## 3.1.8 — Stable connected banks
- Firebase-verified UID scopes every Plaid API call and prevents cross-user access.
- PostgreSQL is required before creating/linking bank accounts.
- Saved Plaid items remain listed when one institution's balance refresh fails.
- Direct item disconnect endpoint supports the PayAviator app.
