# PayAviator backend PR #8 - one free bank + Google Play subscription (NOT merged)
https://github.com/littlemann766/PayAviator-Backend/pull/8  (branch billing-one-free-bank)
All calls: Authorization: Bearer <Firebase ID token>

- Over limit (create-link-token / exchange-public-token): 402 {"error":"subscription_required","code":"SUBSCRIPTION_REQUIRED","limit":1,"linked":n}
  hosted-status (add mode): 402 same + connected:false,pending:false,status:"subscription_required"; multi-bank partial: 200 with skipped:{402 body}
- Relinking existing banks (update-link-token / update-complete) never blocked. Users with 2+ banks already are grandfathered.
- GET /api/billing/status -> {plan:"free"|"premium"|"comp", linkedBanks, limit:1|null, expiresAt, productId, state, cancelAtPeriodEnd, periodEnd, grandfathered, billingConfigured}
  - `cancelAtPeriodEnd` (boolean): Stripe subs only; true when the user cancelled and premium stays on until `periodEnd`. Always false for Play/comp/free.
  - `periodEnd` (ISO 8601 string|null): Stripe subs only; end of the current paid period (same instant as `expiresAt`). null otherwise.
  - `plan:"comp"` = owner/comp account from `COMP_FIREBASE_UIDS` (comma-separated Firebase UIDs): unlimited banks (`limit:null`), no subscription, skips X-Device-Id/fingerprint/Play Integrity checks, records no free-tier claims; `grandfathered` always false. Same shape otherwise; app should treat `comp` like `premium` (hide upgrade).
- POST /api/billing/google-play/verify {productId, purchaseToken}  (call after each purchase and on app start to restore)
  200 active (+subscriptionState) | 402 subscription_inactive | 400 missing_purchase/unknown_product/product_mismatch/invalid_purchase | 409 purchase_in_use | 502 verify_failed | 503 billing_not_configured
- Until Play is configured, billing endpoints return 503 and the 1-bank limit still applies.

Boss setup needed (Play Console): service account + JSON key (send to Lucian privately), grant it View financial data + Manage orders and subscriptions, create subscription (e.g. payaviator_premium) at the chosen price, license testers.

## Update 2026-10-12: free-tier anti-abuse (same PR #8, still NOT merged)
New-bank calls (POST /api/plaid/create-link-token, POST /api/plaid/exchange-public-token, GET /api/plaid/hosted-status in add mode):
- Header X-Device-Id: <app-generated stable install ID, 8-256 printable chars>  REQUIRED for free users (send it always; harmless for subscribers)
- Header X-Play-Integrity-Token: optional, accepted, ignored for now
- 403 {"error":"email_not_verified","code":"EMAIL_NOT_VERIFIED"}  -> show "verify your email" (Firebase sendEmailVerification, then refresh ID token)
- 400 {"error":"device_id_required","code":"DEVICE_ID_REQUIRED"}
- 402 subscription_required, optional "reason":
    "device_already_used_free"  -> this phone already used a free bank on another account
    "account_already_used_free" -> this bank account is already someone's free bank (connection was cancelled at Plaid)
    (no reason) -> normal 1-bank limit
- 503 {"error":"free_tier_not_configured","code":"FREE_TIER_NOT_CONFIGURED"} -> server misconfigured; retry later
hosted-status gate errors: same status code + body, plus connected:false, pending:false, status:<error>
Update mode / reconnect is never affected.
Env: FREE_TIER_FINGERPRINT_SECRET (>=32 chars, required), FREE_TIER_COOLDOWN_DAYS (default 30)
Privacy notes for Beth: docs/PRIVACY-DATA-NOTES.md in the repo.

## Update 2026-10-12 (2): reinstall-proof device ID + Play Integrity (same PR #8, still NOT merged)
Supersedes the X-Device-Id / X-Play-Integrity-Token lines above.
- X-Device-Id = Settings.Secure.ANDROID_ID, exactly 16 hex chars (case-insensitive; server lowercases, stores only HMAC).
  Kotlin: Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
  Stable across reinstall / clear data for the same signing key + Android user (changes only on factory reset).
  400 {"error":"device_id_required"} if missing; 400 {"error":"device_id_invalid","code":"DEVICE_ID_INVALID"} if not 16 hex.
- When server PLAY_INTEGRITY_ENFORCE=true, free users also send X-Play-Integrity-Token on the same three calls.
  Use the Play Integrity STANDARD request (com.google.android.play:integrity):
    prepare once: IntegrityManagerFactory.createStandard(ctx).prepareIntegrityToken(PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(<GCP project number>).build())
    per link: provider.request(StandardIntegrityTokenRequest.builder().setRequestHash(H).build()).token()
  H = lowercase hex SHA-256 of UTF-8 "<androidId lowercased>|<firebase uid>"  (e.g. "a1b2c3d4e5f60718|abcUID123")
  Token must be <=5 min old when it reaches the server; reuse one token for create-link-token, hosted-status polls and exchange,
  and request a new one if older than ~4 min. Max header length 8192.
  403 {"error":"integrity_failed","code":"INTEGRITY_FAILED","reason":...}; reasons:
    token_missing, token_invalid, package_mismatch, stale_token, request_hash_mismatch, app_not_recognized, device_integrity_failed
    -> show "This device/app version can't use the free plan; install from Google Play or subscribe".
  503 {"error":"integrity_not_configured","code":"INTEGRITY_NOT_CONFIGURED"} -> server misconfigured; retry later.
  Flag off: header ignored. Subscribers never need it.
- Play Console: enable Play Integrity API and link the Cloud project; the same service account (GOOGLE_PLAY_SERVICE_ACCOUNT_JSON) must be in that project with the Play Integrity API enabled.
Env: PLAY_INTEGRITY_ENFORCE=true|false (default false; uses GOOGLE_PLAY_SERVICE_ACCOUNT_JSON + ANDROID_PACKAGE_NAME)

## Update 2026-10-12 (3): Plaid audit logging (same PR #8, still NOT merged) - app changes OPTIONAL
Server now logs one JSON line per Plaid call/webhook (request_id, item_id, account_ids, error_type/code, user_ref = hashed uid). No tokens, balances, names, emails ever.
Optional for the app (helps Plaid support trace a failed link; nothing breaks without it):
- Header X-Link-Session-Id: <link_session_id> on any authenticated /api/plaid/* call (create-link-token, hosted-status polls, exchange-public-token, update-complete).
  Source: Plaid Link SDK LinkSuccess.metadata.linkSessionId / LinkExit.metadata.linkSessionId (Android), or onEvent metadata.
- Or body field "link_session_id" on POST /api/plaid/exchange-public-token. (hosted-status is GET: use the header.)
- Format [A-Za-z0-9-]{1,64}; invalid values are ignored, never rejected. CORS allows the header.
- Hosted Link: not needed, the server reads link_session_ids from /link/token/get itself.

## Update 2026-10-13: Stripe web subscriptions + 30-day hash expiry (PR on branch stripe-web-billing, NOT merged)
- GET /api/billing/status: same shape as before, plus `source: "play"|"stripe"|"comp"|null` and `stripeConfigured: bool`.
  Stripe entitlements fill plan/limit/expiresAt/productId (Stripe price id)/state with the same Play-style states
  (ACTIVE, CANCELED = cancels at period end, IN_GRACE_PERIOD = card failed and Stripe is retrying, ON_HOLD, EXPIRED...).
  Premium = an active Play OR an active Stripe subscription; whichever is active wins, no migration between them.
- POST /api/billing/stripe/checkout (Firebase auth) {plan:"monthly"|"yearly"} (default monthly)
  200 {url,id} -> redirect to url | 400 unknown_plan | 409 already_premium {source} | 502 checkout_failed | 503 stripe_not_configured
  Success: https://payaviator.app/billing/success?session_id=... ; cancel: https://payaviator.app/billing/cancel
- POST /api/billing/stripe/portal (Firebase auth) -> 200 {url} (Stripe customer portal; returns to https://payaviator.app/account)
  | 404 no_stripe_customer | 502 portal_failed | 503 stripe_not_configured
- POST /api/billing/stripe/webhook (public, Stripe-Signature verified on raw body). Handles checkout.session.completed,
  customer.subscription.created/updated/deleted, invoice.payment_failed, invoice.paid. Event ids stored (idempotent, kept 30 days).
  400 invalid_signature | 500 webhook_failed (Stripe retries) | 503 stripe_not_configured
- All Stripe routes return 503 stripe_not_configured unless all four env vars are set, so it is safe to deploy before Stripe exists.
Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_MONTHLY ($3.99/mo; actual price comes from the Stripe price id), STRIPE_PRICE_YEARLY ($29.99/yr)
Website calling from the browser: add https://payaviator.app to CORS_ORIGINS.
Boss setup (Stripe Dashboard, when approved): create product + 2 prices, webhook endpoint
https://<backend>/api/billing/stripe/webhook with the events above, enable the customer portal with "cancel subscription" (one-click cancel).
- Anti-abuse hash expiry: device/bank fingerprints from removed banks or deleted user data are ignored after 30 days
  (FREE_TIER_COOLDOWN_DAYS) and deleted by a cleanup job on startup + hourly. Still-linked banks keep theirs. See docs/PRIVACY-DATA-NOTES.md.
- Future work (not built): phone-only sign-in. Server still requires a verified email for bank linking; phone-only accounts need that check changed.

- Stripe Checkout is cards only (`payment_method_types:['card']`). New Stripe customers get `customer_email` prefilled from the Firebase token's `email` claim; returning customers reuse their stored Stripe customer.

## Subscription restore and duplicate checkout (2026-11-07)

This does **not** claim the billing system is fully secure or compliant. It closes one gap: a deleted Firebase Auth user left `billing_entitlements` and `stripe_customers` behind, so a new uid could not restore a Play purchase (`409 purchase_in_use`) and could start a second subscription while the old one still renewed.

### What the app sends (unchanged request)

`POST /api/billing/google-play/verify` body is still only:

```json
{ "productId": "string", "purchaseToken": "string" }
```

Email, `customer` / `customerId`, `obfuscatedExternalAccountId`, and any purchase JSON in the body are **ignored**. The server accepts the purchase only after `purchases.subscriptionsv2.get` succeeds. Play's `externalAccountIdentifiers` are read from that response, not from the phone.

`POST /api/billing/stripe/checkout` body is still `{ "plan": "monthly"|"yearly" }`. A customer id or email in the body is ignored. `POST /api/billing/stripe/portal` is still an empty body; the customer id is loaded from the signed-in uid only. There is no email search and no client-supplied customer id.

`DELETE /api/plaid/user` still takes no reason and no survey. It does **not** cancel Play or Stripe, and it does **not** delete entitlement rows or the Stripe customer id. It also does not restore or relink banks later.

### Verify responses the app should branch on

| Situation | HTTP | Body |
|---|---|---|
| This uid already owns the token, or Play has no stored owner, and the sub is entitled (active, grace, or canceled-but-unexpired) | 200 | Existing status fields, plus `subscriptionState`, `recoveryRequired:false`, `duplicateCheckoutBlocked` (true while Plus is on). `recovered` is omitted. |
| Same, but the sub is not entitled | 402 | `error:"subscription_inactive"`, `code:"SUBSCRIPTION_INACTIVE"`, status fields, `subscriptionState`, and the two booleans. |
| Stored owner **still exists** in Firebase Auth (including disabled) | 409 | Exactly `{ "error":"purchase_in_use", "code":"PURCHASE_IN_USE" }`. Nothing is moved. Checkout is not blocked for this reason. |
| Stored owner is **auth/user-not-found**, Play confirms a sub that can still bill, and Play did not name some other account id | 200 or 402 | Same as a normal verify for this uid, plus `"recovered": true`. Only the entitlement row moves. Banks are not restored. |
| Auth lookup is not configured, errors, or Play's account id is neither this uid nor the stored owner, and the sub can still bill | 409 | `purchase_in_use` / `PURCHASE_IN_USE` plus `recoveryRequired:true`, `duplicateCheckoutBlocked:true`, `recoveryCode:"OWNERSHIP_UNCONFIRMED"`. Nothing is moved. |
| Play HTTP 400/404/410, product mismatch, unknown product, missing token | 400 | Unchanged codes. Nothing is moved. |
| Play otherwise fails | 502 | `verify_failed`. Nothing is moved. No entitlement is created. |
| Billing not configured | 503 | `billing_not_configured`. |

`GET /api/billing/status` adds two booleans and does not remove old fields:

- `recoveryRequired` — this sign-in presented a Play purchase the server could not safely move, and that purchase can still bill. Not a promise that support can restore it automatically.
- `duplicateCheckoutBlocked` — do not start another Stripe Checkout. True when `plan` is not `free`, when a stored sub can still resume (`PAUSED`, `ON_HOLD`, `PENDING`), or when `recoveryRequired` is true.

Show `OWNERSHIP_UNCONFIRMED` as "we could not safely move this subscription; it was not moved; don't buy again while it may still renew." Do not tell the person that another named account has it unless the body is the exact two-field `purchase_in_use` object (that one means Auth still has the stored owner). Never display the other uid; the API does not return it.

### Checkout responses

- `409 already_premium` — this uid is already Plus (local entitlement or a Stripe subscription just read for this uid). Unchanged `source`.
- `409 duplicate_checkout_blocked` / `DUPLICATE_CHECKOUT_BLOCKED` — `{ duplicateCheckoutBlocked:true, recoveryRequired:boolean, source?: "play"|"stripe" }`. No Checkout Session is created.
- `502 checkout_failed` — Stripe list/retrieve failed. No second session is created and nothing is granted.
- `200 {url,id}` — new session, or the same open session this uid already started (idempotent retry).
- `404 no_stripe_customer` on the portal — this uid has no stored customer. A matching email is not used to find one.

### Security assumptions (not a compliance claim)

- A Play purchase token is not proof by itself. Reassignment also needs Firebase Admin `getUser(storedUid)` to return `auth/user-not-found`. Any other error, including `auth/insufficient-permission` and timeouts, does not move the row.
- `auth/user-not-found` is also what Auth returns for a uid that was never in this project. Entitlement rows are created only for a uid that was signed in at verify time. Disabled users still exist and block transfer.
- The lookup uses `FIREBASE_SERVICE_ACCOUNT_JSON` and `FIREBASE_PROJECT_ID` (the FCM credential). It is not the Play Console service account. If it is missing, transfer stays off.
- Email, Subscribe with Google email, a bearer ID token, a client purchase blob, and a client Stripe customer id are not proofs. Stripe customers are not searched or moved across uids.
- If Play returns `obfuscatedExternalAccountId` or `externalAccountId`, it must equal this uid or the stored owner (exact string). The current app does not set that field. A hash we cannot read fails closed (`OWNERSHIP_UNCONFIRMED`) instead of being treated as a match.
- A living stored owner is never overwritten, including when a replacement token's `linkedPurchaseToken` still belongs to them.
- Two concurrent restores lock the token hash. One successor wins; the other gets `409 purchase_in_use`.
- Refunded / expired / revoked (`EXPIRED`, `PENDING_PURCHASE_CANCELED`, or any state that cannot still bill) are not moved and do not block a new checkout. Paused, on hold, and pending are moved when the owner is gone but do **not** grant Plus until Play reports an entitled state.
- Acknowledgement runs only after a grant. Provider failures are not acknowledged and not stored.
- Logs must not contain the raw purchase token. The server scrubs token strings and Play token URLs. Recovery holds store a sha256 and a code, not the token and not the other uid.

### Limits that remain

- Orphaned **Stripe** subscriptions are not automatically attached to a new uid. Someone who deletes Auth and makes a new account can still be charged by the old Stripe customer until that subscription is cancelled in Stripe. The server will not look the customer up by email. Portal access requires the original uid's stored customer id, which a new uid does not have.
- A person who has the Play token after the original Auth user is gone can receive that Play entitlement. That is the accepted restore rule, not a proof of legal identity.
- Checkout is blocked only when this uid's own rows, a recovery hold, or Stripe's API for **this uid's stored customer** show a subscription that may still bill. A brand-new uid with no Play token and no Stripe customer is not matched to an orphan.
- Bank connections, transactions, and Plaid items are not restored and bank links are not reopened.
- Package `app.payaviator` and product `payaviator_premium` are backend test fixtures. The Android applicationId in the app review is `com.payaviator.app`. This change does not set production package, product, or provider keys.
- Cancellation stays in Google Play (package `com.payaviator.app`, sku from `status.productId` when it is a Play product id) or the Stripe portal for the signed-in uid. Deleting the account is separate and does not ask why.
