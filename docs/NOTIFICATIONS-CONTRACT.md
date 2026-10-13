# Bank-reconnect push notifications (FCM), Phase 2 — contract

Status: staged on branch `fcm-reconnect-push`, NOT merged or deployed until the boss approves.
FCM is free and works on the Firebase Spark plan. No Blaze upgrade is needed.

## Device token endpoints
Both require `Authorization: Bearer <Firebase ID token>`. They work even when Plaid is not configured.

### POST /api/devices/fcm
Request: `{"token": "<FCM registration token>", "platform": "android" | "ios" | "web"}` (platform is optional and defaults to `android`)
- Call it after sign-in, whenever `FirebaseMessaging.onNewToken` fires, and on app start (it's idempotent).
- Upsert: if the token is already registered to another account (for example, a different user signs in on the same phone), it moves to the current account.
- Each user keeps up to `FCM_MAX_TOKENS_PER_USER` tokens (default 10). Registering more drops the least recently registered tokens.

200: `{"registered": true, "devices": <n>, "max_devices": 10, "push_configured": <bool>}`

### DELETE /api/devices/fcm
Request: `{"token": "<FCM registration token>"}`. Call it before sign-out, while the ID token is still valid.
200: `{"unregistered": true, "removed": <bool>}`. The response is always 200, even when the token wasn't registered or belongs to another user, in which case `removed` is false.

### Errors
| Status | Body |
|---|---|
| 400 | `{"error":"invalid_token","code":"INVALID_FCM_TOKEN"}` (the token is missing, isn't a string, isn't 20 to 4096 characters, or contains characters outside `A-Za-z0-9_:.-`) |
| 400 | `{"error":"invalid_platform","code":"INVALID_PLATFORM"}` |
| 400 | `{"error":"Bad request.","code":"BAD_REQUEST"}` (malformed JSON, or a body over 16 KB) |
| 401 | `UNAUTHENTICATED` / `INVALID_TOKEN` (same as the other endpoints) |
| 429 | rate limited (60 requests per user per 15 minutes) |
| 500 | `FCM_REGISTER_FAILED` / `FCM_UNREGISTER_FAILED` |

Account deletion (`DELETE /api/plaid/user`) also deletes all of the user's FCM tokens.

## When a push is sent
These are triggered by verified Plaid webhooks for a known Item, after the item status is stored:
- `ITEM` / `ERROR` with `error.error_code == "ITEM_LOGIN_REQUIRED"`, reason `ITEM_LOGIN_REQUIRED`
- `ITEM` / `PENDING_EXPIRATION`, reason `PENDING_EXPIRATION`
- `ITEM` / `PENDING_DISCONNECT`, reason `PENDING_DISCONNECT`

Each push goes to every registered device of the Item's owner. Each Item sends at most one push per 24 hours, no matter which reason triggered it. If every send fails, the 24-hour slot is released so a later webhook can try again.
Tokens that FCM reports as `registration-token-not-registered` or `invalid-registration-token` are deleted.
If FCM isn't configured, the user has no devices, or the push fails, the result is logged and the push is skipped. The webhook still returns 200, and the push runs in the background after the response.

## Push payload
```json
{
  "notification": { "title": "Reconnect your bank",
                    "body": "One of your bank connections needs attention. Open PayAviator to reconnect." },
  "data": { "type": "bank_reconnect", "item_id": "<plaid item_id>",
            "reason": "ITEM_LOGIN_REQUIRED|PENDING_EXPIRATION|PENDING_DISCONNECT" },
  "android": { "priority": "high", "collapseKey": "bank_reconnect_<item_id>",
               "notification": { "channelId": "bank_reconnect", "tag": "bank_reconnect_<item_id>", "visibility": "private" } }
}
```
The payload never includes balances, amounts, account numbers, or bank names.
App side: create the Android notification channel `bank_reconnect`. When the user taps the notification, or when `data.type == "bank_reconnect"` arrives in the foreground, open the reconnect (update-mode) flow for `data.item_id`. Use the existing `POST /api/plaid/update-link-token` and `update-complete` calls.

## Server config (Railway env)
- `FIREBASE_SERVICE_ACCOUNT_JSON`: a service-account key for the Firebase project, as raw JSON or base64. The firebase-adminsdk account in Firebase console → Project settings → Service accounts works. Push stays disabled until this is set.
- `FIREBASE_PROJECT_ID`: already used for auth. It is also used as the FCM project, and `FCM_PROJECT_ID` overrides it.
- Optional: `FCM_USE_PLAY_SERVICE_ACCOUNT=true` reuses `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON`, which only works if that account belongs to the same Firebase project and has the FCM send permission. Other optional settings: `FCM_MAX_TOKENS_PER_USER` (default 10, maximum 50) and `PUSH_DISABLED=true` as a kill switch.
- New Postgres tables, created automatically on startup: `fcm_tokens(token PK, user_id, platform, created_at, updated_at)` and `push_dedupe(item_id PK, sent_at)`.
- New dependency: `firebase-admin`.
- `/api/health` now includes `pushConfigured`.
