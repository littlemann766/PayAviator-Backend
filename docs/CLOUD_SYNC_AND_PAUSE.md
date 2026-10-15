# Cloud sync + pause-extra-banks (branch cloud-sync-pause-banks)

## Cloud sync: /api/sync (Bearer Firebase ID token, verified email required)
- GET /api/sync/changes?since=<seq>&limit=<1..500> -> { items:[{kind,id,data|null,updatedAt,deleted,seq}], next, more }
- POST /api/sync/push { items:[{kind,id,data,updatedAt,deleted?}] } (max 200) -> { results:[{kind,id,status:"accepted"|"rejected",reason?,winner?}] }
- DELETE /api/sync/all -> { deleted:<n> }
kinds: bill income spending cushion budget goal category. Last-write-wins on updatedAt (ms); ties -> higher sha256 of content wins.
updatedAt clamped to now+5min. Tombstones (deleted:true) clear data, purged after 90 days. Item <=8KB, <=20000 items/user, body <=512KB.
DELETE /api/plaid/user also wipes sync data.

## Pause-extra-banks (no active premium/comp)
Oldest non-revoked item stays active; the rest are virtually 'paused' (computed per request, never stored, so auto-resume is instant).
Paused: no accountsGet, no transactions sync, no itemGet, webhook SYNC_UPDATES_AVAILABLE skipped, update-link-token -> 402 ITEM_PAUSED. Disconnect works.
itemSummary: paused, pause_reason ('plus_ended'). /api/billing/status: pausedBanks. grandfathered unchanged (true = extra banks exist and are paused).
