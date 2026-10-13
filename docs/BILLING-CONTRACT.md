# PayAviator backend PR #8 - one free bank + Google Play subscription (NOT merged)
https://github.com/littlemann766/PayAviator-Backend/pull/8  (branch billing-one-free-bank)
All calls: Authorization: Bearer <Firebase ID token>

- Over limit (create-link-token / exchange-public-token): 402 {"error":"subscription_required","code":"SUBSCRIPTION_REQUIRED","limit":1,"linked":n}
  hosted-status (add mode): 402 same + connected:false,pending:false,status:"subscription_required"; multi-bank partial: 200 with skipped:{402 body}
- Relinking existing banks (update-link-token / update-complete) never blocked. Users with 2+ banks already are grandfathered.
- GET /api/billing/status -> {plan:"free"|"premium"|"comp", linkedBanks, limit:1|null, expiresAt, productId, state, grandfathered, billingConfigured}
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
Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_MONTHLY ($2.99/mo), STRIPE_PRICE_YEARLY ($29.99/yr)
Website calling from the browser: add https://payaviator.app to CORS_ORIGINS.
Boss setup (Stripe Dashboard, when approved): create product + 2 prices, webhook endpoint
https://<backend>/api/billing/stripe/webhook with the events above, enable the customer portal with "cancel subscription" (one-click cancel).
- Anti-abuse hash expiry: device/bank fingerprints from removed banks or deleted user data are ignored after 30 days
  (FREE_TIER_COOLDOWN_DAYS) and deleted by a cleanup job on startup + hourly. Still-linked banks keep theirs. See docs/PRIVACY-DATA-NOTES.md.
- Future work (not built): phone-only sign-in. Server still requires a verified email for bank linking; phone-only accounts need that check changed.
