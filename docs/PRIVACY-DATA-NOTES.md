# PayAviator: free-tier anti-abuse data (plain-words notes for the privacy policy)

## Why we keep anything at all
The free plan includes one linked bank. To stop one person from making extra email accounts
to get more free banks, the server remembers, in scrambled form, which bank accounts and
which phones have already used a free slot.

## What we keep (only scrambled "fingerprints")
For a **free** bank link only, the server keeps:
1. A fingerprint of each linked account made from the bank's ID plus the account's last 4 digits.
2. A fingerprint of Plaid's long-lived account ID (`persistent_account_id`), when Plaid gives one.
3. A fingerprint of the phone's app-generated device ID (sent by the app as `X-Device-Id`).

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
  permanently deleted. The server checks for expired fingerprints on startup and once a day.
- Bank data itself (access tokens, transactions) is still deleted right away as before; only
  these fingerprints wait out the 30 days.

## Not yet in use
The app may send a Google Play Integrity token (`X-Play-Integrity-Token`). The server accepts
it but does not read or store it yet; that's a planned follow-up.

## Suggested policy wording
"To prevent misuse of our free plan, when you link a bank on the free plan we keep a
one-way, encrypted fingerprint of the bank account (based on the bank and the account's last
four digits) and of your device's app ID. We cannot read the original details from these
fingerprints. They're deleted 30 days after you remove the bank or delete your account."
