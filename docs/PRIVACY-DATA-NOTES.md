# PayAviator: free-tier anti-abuse data (plain-words notes for the privacy policy)

## Why we keep anything at all
The free plan includes one linked bank. To stop one person from making extra email accounts
to get more free banks, the server remembers, in scrambled form, which bank accounts and
which phones have already used a free slot.

## What we keep (only scrambled "fingerprints")
For a **free** bank link only, the server keeps:
1. A fingerprint of each linked account made from the bank's ID plus the account's last 4 digits.
2. A fingerprint of Plaid's long-lived account ID (`persistent_account_id`), when Plaid gives one.
3. A fingerprint of the phone's Android ID (`Settings.Secure.ANDROID_ID`, sent by the app as
   `X-Device-Id`). Only the HMAC is stored; the raw Android ID is never written to the database or logs.

Each fingerprint is a keyed hash (HMAC-SHA256) using a secret that only the server holds.
We never store the last 4 digits, the Plaid account ID, or the device ID themselves. The
fingerprint can't be turned back into the original, and without the server secret it can't
be matched against anything outside PayAviator. Each fingerprint is linked only to the user's
sign-in ID and that bank connection.

Subscribers' links are **not** fingerprinted.

We also require a **verified email** before any bank can be linked (Google sign-ins are verified already).

## How it's used
When someone links a free bank, we check whether that bank account or that phone has already
used a free slot on a **different** account. If so, we cancel the new connection right away
(it's removed at Plaid and never saved) and offer the subscription.

## How long we keep it
- While the bank stays linked: kept.
- When the user removes that bank, or deletes their account: the fingerprints are kept for
  **30 days** (the "cooldown", so removing and re-adding on another email doesn't work), then
  permanently deleted. The server deletes expired fingerprints on startup and every hour, and
  lookups ignore any fingerprint past 30 days even before that cleanup runs.
- Bank data itself (access tokens, transactions) is still deleted right away as before; only
  these fingerprints wait out the 30 days.

## Google Play Integrity
When `PLAY_INTEGRITY_ENFORCE=true`, a free bank link also needs a Play Integrity token
(`X-Play-Integrity-Token`). The server sends it to Google's `decodeIntegrityToken` API and checks
the verdict (genuine app from Play, genuine device, our package, fresh, bound to this device and
account). The token and verdict are **not stored**; only a pass/fail reason may appear in logs.
When the flag is off the header is ignored.

## Suggested policy wording
"To prevent misuse of our free plan, when you link a bank on the free plan we keep a
one-way, encrypted fingerprint of the bank account (based on the bank and the account's last
four digits) and of your device's Android ID. We cannot read the original details from these
fingerprints. They're deleted 30 days after you remove the bank or delete your account."

## Exact retention table (server)
| Data | Kept while | Deleted |
|---|---|---|
| Bank/device fingerprints (HMAC) for a linked free bank | bank linked (incl. Plaid-revoked items kept for "Reconnect") | 30 days after the bank is removed or the account data is deleted (`FREE_TIER_COOLDOWN_DAYS`) |
| Stripe customer id <-> sign-in id | while the account exists | not yet auto-deleted (needed for the billing portal); TODO on account deletion |
| Stripe webhook event ids (no payment data) | 30 days | hourly purge |
| Subscription entitlement (store, plan id, state, expiry; Play token only as sha256) | while the account exists | — |
No card numbers or payment details are ever received; Stripe Checkout handles them.
