# ThresholdSafe

ThresholdSafe is a small backend for hosting secrets split with Shamir's
threshold scheme. A secret is issued as one share per registered holder, and it
can only be brought back together when at least `threshold` distributed shares
of the current version are presented together with the required number of
holder approvals. Rotation issues a new version and makes the previous shares
unusable.

> **Security notice.** This project demonstrates API and engineering structure;
> it does not claim production-grade cryptographic security. The sharing
> arithmetic is plain Python integer modular arithmetic (no constant-time code,
> no side-channel hardening), share material is stored unsealed in SQLite, and
> the service keeps every share of every secret. The "at least `k` shares"
> invariant is enforced by this service and by the approval policy, not by the
> storage layout: anybody who can read the database file can recover every
> hosted secret. Use a purpose-built threshold-cryptography or HSM product for
> real key custody.

The initial release supports a compact public contract:

- `(threshold, share_count)` sharing over the Mersenne prime `2**521 - 1`;
- one share per registered holder per version, named `<secret>.<version>.<holder>`;
- shares are created with the secret and handed to holders one at a time later;
- an undistributed share is never accepted for reconstruction;
- reconstruction needs `threshold` distributed shares **and**
  `approvals_required` distinct approvals for the current version;
- the approver roster is either the holder roster itself (`legacy` mode) or
  an explicit, disjoint `approvers` list (`separated` mode) chosen at
  creation and adjustable at rotation, so two-person review and separation
  of duties can be enforced;
- approvals are version-scoped and single-use, consumed by a successful
  reconstruction or rotation;
- rotation issues a new version, invalidates every previous share, and is
  itself gated by the approval policy;
- a secret can be emergency-frozen: while `frozen`, share distribution,
  approvals, reconstruction and rotation all return `409 secret_frozen`, and
  unfreezing leaves the current version, shares and approvals untouched;
- a secret can carry a persistent authorization policy — a strict JSON
  expression over the facts of an attempted action — that gates
  reconstruction and rotation beyond the fixed approval requirement;
- every accepted or rejected custody action is appended to a per-secret
  hash-linked audit stream;
- any audit event can be certified by an Ed25519-signed receipt that clients
  verify independently against the service's published public key;
- a secret can be exported as a self-contained, checksummed JSON backup, and
  any backup document can be verified independently without touching service
  state, or restored into a fresh or existing database as a new secret;
- the plaintext secret is never written to the database: only its SHA-256
  commitment and byte length are kept, to verify what reconstruction recovers.

## Requirements

- Python 3.11 or newer
- `cryptography` (for the Ed25519 audit-receipt signatures); no other
  third-party runtime dependencies

## Run the service

```bash
PYTHONPATH=src python -m thresholdsafe.server --host 127.0.0.1 --port 8080 --database thresholdsafe.db
```

The process prints `ThresholdSafe listening on http://127.0.0.1:8080` after it
has bound the port.

## HTTP API

All request and response bodies are JSON. Unknown fields are rejected. Every
request that changes state must carry an `Idempotency-Key` header; repeating a
request with the same key replays the stored response, and reusing a key for a
different operation is a conflict. Identifiers (secret `id`, holder names,
approvers) must start with a letter or digit and may contain only letters,
digits, `.`, `_` and `-`.

### Health

```http
GET /health
```

Returns `{"status":"ok"}`.

### Create a secret

```http
POST /secrets
Idempotency-Key: demo-create
Content-Type: application/json

{
  "id": "prod-db-root",
  "name": "Production database root key",
  "threshold": 3,
  "holders": ["alice", "bob", "carol", "dave", "erin"],
  "approvals_required": 2,
  "secret": "demo-root-key"
}
```

Field rules: `id` is unique and at most 100 characters; `name` is a non-empty
description of at most 200 characters; `threshold` is an integer `>= 2` and
`<=` the number of holders; `holders` is a non-empty array of unique holder
identifiers; `approvals_required` is an integer `>= 1` and `<=` the number of
holders; `secret` is a non-empty string encoding to at most 64 UTF-8 bytes
(the sharing field is `2**521 - 1`); the optional `seed` is an integer in
`[0, 2**63]` that makes share issuance reproducible (see Determinism); the
optional `policy` is an authorization-policy expression (see Authorization
policy) that gates later reconstructions and rotations.

The optional `approvers` selects the approval mode. Omitting it (or passing
`null`) keeps the `legacy` mode, where every holder is an approver. An
explicit array selects the `separated` mode: it must contain at least two
unique identifiers, none of which may be a holder, and `approvals_required`
must then lie between 2 and the number of approvers (inclusive). Any
violation is a `400 validation_error`.

Returns HTTP 201 with the custody record, which never contains share material
or the secret itself:

```json
{"id":"prod-db-root","name":"Production database root key","version":1,"threshold":3,"holders":["alice","bob","carol","dave","erin"],"approvals_required":2,"approval_mode":"legacy","approvers":["alice","bob","carol","dave","erin"],"share_count":5,"distributed_shares":0,"approvals":{"recorded":0,"required":2,"satisfied":false},"secret_length":13,"status":"active","status_reason":null,"status_changed_at":"2026-10-02T05:53:59.148364Z","created_at":"2026-10-02T05:53:59.148364Z","updated_at":"2026-10-02T05:53:59.148364Z"}
```

`approval_mode` is `legacy` or `separated`, and `approvers` is the effective
approver roster of the current version — the holders themselves in legacy
mode, the explicit roster in separated mode.

### Inspect a secret

```http
GET /secrets/prod-db-root
```

Returns the same custody record, so a client can see the current version, the
roster, the approval mode and approver roster, how many shares have been
distributed, and whether the approval policy is currently satisfied. The
record also carries `status` (`active` or `frozen`), `status_reason` (the
reason recorded by the latest freeze or unfreeze, or `null` when the secret
has never been frozen) and `status_changed_at`. Unknown secrets return 404.

### Freeze a secret

```http
POST /secrets/prod-db-root/freeze
Idempotency-Key: demo-freeze
Content-Type: application/json

{"reason": "suspected holder compromise"}
```

An emergency freeze blocks every custody write while an incident is
investigated. The body must contain exactly `reason`: a string whose
whitespace-trimmed form is non-empty and at most 200 characters; the trimmed
value is what is stored. Returns HTTP 200 with the custody record, now
`"status": "frozen"`, and appends a `secret_frozen` event carrying
`{"version", "reason"}`.

Freezing changes only `status`, `status_reason` and `status_changed_at`. The
current version, threshold, holders, issued and distributed shares, recorded
approvals, secret length and the secret commitment are all left untouched.

### Unfreeze a secret

```http
POST /secrets/prod-db-root/unfreeze
Idempotency-Key: demo-unfreeze
Content-Type: application/json

{"reason": "investigation complete, no compromise"}
```

Returns the custody record to `"status": "active"` and appends a
`secret_unfrozen` event with `{"version", "reason"}`. Already distributed
shares and unconsumed approvals keep working under the existing rules; no
version or policy change takes place.

### Behaviour while frozen

While a secret is frozen, the four write endpoints each return
`409 secret_frozen` with the standard error shape and change nothing:

- `POST /secrets/{id}/shares`
- `POST /secrets/{id}/approvals`
- `POST /secrets/{id}/reconstruct`
- `POST /secrets/{id}/rotate`

Each rejected attempt appends an `operation_blocked` event with
`{"operation", "code"}` (`operation` is one of `distribute_share`,
`record_approval`, `reconstruct`, `rotate`; `code` is `secret_frozen`). No
success is recorded, no idempotency record is stored, and no share, approval,
version or commitment changes. Repeating the rejected request (even with the
same `Idempotency-Key`) is blocked again and appends another event. Once the
secret is unfrozen, that same key performs the operation normally.

State transitions themselves follow the status contract:

| Request | Current status | Result |
| --- | --- | --- |
| freeze | `active` | 200, becomes `frozen` |
| freeze | `frozen` | 409 `secret_frozen` |
| unfreeze | `frozen` | 200, becomes `active` |
| unfreeze | `active` | 409 `secret_not_frozen` |

As elsewhere, repeating the same transition with the same `Idempotency-Key`
replays the stored success response; using the key for anything else,
including the opposite transition or a later freeze cycle after an unfreeze,
is `409 conflict`.

### Authorization policy

```http
GET /secrets/prod-db-root/policy
```

A secret can carry a persistent authorization policy, set at creation with
the optional `policy` field and changed by rotation (`policy` in the rotation
body replaces it, `null` clears it, and omitting the field preserves it).
This endpoint returns the current expression:

```json
{"policy":{"all":[{"fact":{"fact":"action","op":"eq","value":"reconstruct"}},{"fact":{"fact":"presented_shares","op":"gte","value":4}}]}}
```

or `{"policy":null}` when none is attached. Reading the policy is read-only:
it works while the secret is frozen, and no audit event or idempotency
record is written. Unknown secrets return 404.

A policy is a strict JSON expression. Every node is an object with exactly
one of these fields:

- `all`: a non-empty array of child nodes; holds when every child holds;
- `any`: a non-empty array of child nodes; holds when any child holds;
- `not`: a single child node; holds when the child does not;
- `fact`: an object with exactly `fact`, `op` and `value`, comparing one
  fact of the attempted action.

The facts are `action` (`"reconstruct"` or `"rotate"`, comparable only with
`eq`/`ne`) and the non-negative integers `version`, `threshold`, `approvals`
and `presented_shares` (comparable with `eq`, `ne`, `gte`, `lte`). All facts
take their pre-execution values; `presented_shares` is the number of
distinct submitted shares that passed the version, distribution and
commitment checks (always `0` for rotation). Unknown fields, empty `all`/
`any` arrays, and illegal facts, ops or value types are
`400 validation_error` wherever a policy is accepted (creation, rotation,
v2 backups).

The policy is evaluated only after the request shape, status, share and
approval checks have all passed. When it holds, the action proceeds exactly
as before. When it does not, the action fails with `409 policy_denied`: the
secret is not returned, no approvals are consumed, no shares are distributed
or invalidated, and no idempotency response is stored (a retry with the same
key re-evaluates the policy). The denial is appended to the audit stream as
an `authorization_denied` event whose payload carries `action`, `version`,
`presented_shares` and `approvals`. Secrets without a policy behave exactly
as before this feature existed.

### Distribute a share

```http
POST /secrets/prod-db-root/shares
Idempotency-Key: demo-share-alice
Content-Type: application/json

{"holder": "alice"}
```

Returns HTTP 201 with that holder's share of the current version:

```json
{"secret_id":"prod-db-root","version":1,"threshold":3,"share":{"share_id":"prod-db-root.v1.alice","holder":"alice","value":"014616bba91316318ab4915dc21a4597e823f5cbef1c54cbe85123e513d11177dc5c0125114e7c633a255562cab09fec3254ffbba4c95bc83ba558464e1d898999dc","distributed_at":"2026-10-02T05:54:21.163068Z"}}
```

`value` is the polynomial evaluation `f(x)` as 132 lowercase hex characters
(66 bytes); the coordinate `x` stays in the share record. A holder outside the
current roster is a `validation_error`; distributing the same holder and
version twice (with a new idempotency key) is `share_already_distributed`.
Shares created by `POST /secrets` stay undistributed until this endpoint
accepts them.

### Record an approval

```http
POST /secrets/prod-db-root/approvals
Idempotency-Key: demo-approve-alice
Content-Type: application/json

{"approver": "alice"}
```

Returns HTTP 201:

```json
{"secret_id":"prod-db-root","approver":"alice","version":1,"approvals":1,"required":2,"satisfied":false,"recorded_at":"2026-10-02T05:53:59.239701Z"}
```

The approver must belong to the current version's approver roster: the
holders in `legacy` mode, the explicit `approvers` in `separated` mode; any
other identifier is a `400 validation_error`. An approval belongs to one
version and is consumed by any successful reconstruction or rotation of that
version; afterwards the same approver may approve again. Approving twice
without an intervening consumption is `duplicate_approval`.

### Reconstruct a secret

```http
POST /secrets/prod-db-root/reconstruct
Idempotency-Key: demo-reconstruct
Content-Type: application/json

{
  "shares": [
    {"share_id": "prod-db-root.v1.carol", "value": "01ec...74f8"},
    {"share_id": "prod-db-root.v1.alice", "value": "01d8...2d52"},
    {"share_id": "prod-db-root.v1.bob", "value": "01d1...87d2"}
  ]
}
```

Returns HTTP 200 with the recovered secret:

```json
{"id":"prod-db-root","version":1,"secret":"demo-root-key","threshold":3,"used_shares":["prod-db-root.v1.alice","prod-db-root.v1.bob","prod-db-root.v1.carol"],"holders":["alice","bob","carol"],"reconstructed_at":"2026-10-02T05:53:59.302506Z"}
```

The body must contain exactly `shares`, a non-empty array of
`{"share_id","value"}` objects with unique share identifiers. Checks run in
this order and the first failure is returned:

1. the `Idempotency-Key` header is present (400 `validation_error`);
2. body shape and share identifiers (400 `validation_error`);
3. the secret exists (404 `not_found`);
4. the secret is not frozen (409 `secret_frozen`);
5. every submitted share exists and belongs to this secret (404 `not_found`);
6. every share belongs to the current version (409 `stale_share`);
7. every share was distributed to its holder (409 `share_not_distributed`);
8. every value matches the commitment stored at issuance (400 `share_mismatch`);
9. at least `threshold` shares were submitted (409 `insufficient_shares`);
10. at least `approvals_required` approvals exist for the version
    (409 `insufficient_approvals`);
11. the persistent authorization policy, when one is attached, holds for
    this attempt (409 `policy_denied`);
12. the recovered integer matches the stored commitment and byte length
    (409 `integrity_failure`).

More than `threshold` shares is allowed; extras only add redundancy. Shares
and holders are reported sorted, so the same set of shares always yields the
same response whatever the submit order. A successful reconstruction consumes
the version's approvals and appends `approvals_consumed` and
`secret_reconstructed` to the audit stream. Fewer than `threshold` shares can
never produce the secret:

```json
{"error":{"code":"insufficient_shares","message":"reconstruction requires 3 shares but 2 were provided"}}
```

Every mutating endpoint validates the `Idempotency-Key` header first and the
body second; the exception is `POST /secrets`, which parses the body first
because the idempotency scope contains the secret `id`.

### Rotate a secret

```http
POST /secrets/prod-db-root/rotate
Idempotency-Key: demo-rotate
Content-Type: application/json

{
  "secret": "rotated-root-key",
  "threshold": 2,
  "holders": ["frank", "grace", "heidi"],
  "approvals_required": 2
}
```

Every field is optional; omitted fields keep their current value, and `{}`
re-issues shares for the same secret value. `policy` follows the same rule
with one extension: an explicit `"policy": null` clears the authorization
policy, while omitting the field preserves it. `approvers` follows the same
tri-state pattern: omitting it continues the current approval mode (a legacy
secret's approvers follow the final holder roster, a separated secret keeps
its approver roster), an explicit array switches to or updates the separated
roster, and an explicit `null` switches back to legacy mode. The target
configuration is validated before anything changes: a separated roster
overlapping the final holders, a quorum outside `2..len(approvers)`, a
legacy quorum the final holders cannot meet, or a retained roster
invalidated by a holder change is a `400 validation_error` that leaves the
version, roster, approvals and shares untouched. Rotation must satisfy the
approvals currently required for the version it replaces — recorded by that
version's approver roster — and those approvals are consumed; the currently
stored authorization policy (not the one being installed) must also permit
the rotation. Returns HTTP 200 with
the new custody record:

```json
{"id":"prod-db-root","name":"Production database root key","version":2,"threshold":2,"holders":["frank","grace","heidi"],"approvals_required":2,"approval_mode":"legacy","approvers":["frank","grace","heidi"],"share_count":3,"distributed_shares":0,"approvals":{"recorded":0,"required":2,"satisfied":false},"secret_length":16,"status":"active","status_reason":null,"status_changed_at":"2026-10-02T05:54:08.150075Z","created_at":"2026-10-02T05:54:08.150075Z","updated_at":"2026-10-02T05:54:08.384263Z"}
```

Rotation increments the version, invalidates every share of the previous
version, and issues a fresh set of undistributed shares for the new roster, so
a previous share now fails with `stale_share`:

```json
{"error":{"code":"stale_share","message":"share prod-db-root.v1.alice belongs to version 1 and was invalidated by rotation to version 2"}}
```

### Audit stream

```http
GET /secrets/prod-db-root/audit
```

Returns the ordered append-only event stream of one secret plus a verdict on
its integrity:

```json
{"secret_id":"prod-db-root","version":1,"chain_valid":true,"head_hash":"dbbab719935acb7ab8fdc1d45f8ae904bff7eb2ffef6fee154f70956d3400c44","events":[{"sequence":1,"type":"secret_created","payload":{"approvals_required":2,"deterministic":false,"holders":["alice","bob","carol","dave","erin"],"name":"Production database root key","secret_length":13,"share_count":5,"threshold":3,"version":1},"occurred_at":"2026-10-02T05:54:21.162864Z","previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"dbbab719935acb7ab8fdc1d45f8ae904bff7eb2ffef6fee154f70956d3400c44"}]}
```

Event types are `secret_created`, `share_distributed`, `approval_recorded`,
`approvals_consumed`, `secret_reconstructed`, `secret_rotated`,
`secret_frozen`, `secret_unfrozen`, `operation_blocked`,
`authorization_denied`, `reconstruction_failed` and `audit_receipt_issued`. The `secret_created`,
`approval_recorded` and `secret_rotated` payloads carry the version's role
information (`approval_mode` and the effective `approvers` roster) alongside
their other fields. Sequences start at 1 and have no gaps. Each event
carries `previous_hash` and
`hash = sha256("<previous_hash>|<sequence>|<type>|<canonical payload>|<occurred_at>")`,
where the canonical payload is the JSON text with sorted keys and compact
`,`/`:` separators. `chain_valid` recomputes the whole chain on every read, so
an edited event is detectable. A failed reconstruction is recorded when the
failure is a custody decision (`insufficient_shares`, `insufficient_approvals`,
`stale_share`, `share_not_distributed`, `share_mismatch`,
`integrity_failure`); malformed bodies are not audited. A custody write
rejected because the secret is frozen is recorded as `operation_blocked`; a
reconstruction or rotation rejected by the persistent authorization policy
is recorded as `authorization_denied`.

### Receipt signing key

```http
GET /audit/receipt-key
```

Returns the public half of the service's Ed25519 receipt-signing key:

```json
{"algorithm":"Ed25519","key_id":"93984123e92b506065875392671400c06ec49a3d4293b8091635a9f5e8b0c83a","public_key":"PpGREZtD1Y_nXMlx6zHbVFS4dRhZeQCwDm3hjIIebFI"}
```

`key_id` is the lowercase hexadecimal SHA-256 digest of the raw public key;
`public_key` (and every signature) is URL-safe Base64 without padding. The
key is generated once, persisted in the database, and shared by every
process serving that database — including databases created before receipts
existed, which gain the key on first open. Reading the key is read-only: no
audit event or idempotency record is written. The private key never appears
in any response or backup.

### Issue an audit receipt

```http
POST /secrets/prod-db-root/audit-receipts
Idempotency-Key: demo-receipt
Content-Type: application/json

{"sequence": 1, "nonce": "order-4711"}
```

Signs a receipt certifying one existing audit event of one secret. The body
must contain exactly `sequence` (a positive integer identifying an event of
this secret) and `nonce` (a non-empty string of at most 128 UTF-8 bytes,
kept exactly as sent). The whole audit chain is re-verified first: a broken
chain is `409 audit_integrity`, an unknown secret or event is
`404 not_found`, a malformed body is `400 validation_error`, and every
failure writes nothing. A frozen secret is served exactly like an active
one.

On success the service appends an `audit_receipt_issued` event — payload
`{"key_id", "nonce", "target_sequence"}` — in the same transaction and
returns HTTP 201:

```json
{"algorithm":"Ed25519","key_id":"9398...b0c83a","secret_id":"prod-db-root","event":{"sequence":1,"type":"secret_created","payload":{...},"occurred_at":"2026-10-02T05:54:21.162864Z","previous_hash":"0000...0000","hash":"dbba...0c44"},"nonce":"order-4711","head_sequence":2,"head_hash":"9ad6...22d5","signature":"xvEp...5oAg"}
```

`event` is the certified event in the audit-stream shape; `head_sequence`
and `head_hash` point at the `audit_receipt_issued` event this call
appended, so the receipt also pins the chain head at issuance time.
`signature` signs the UTF-8 canonical JSON (sorted keys, compact separators)
of every other field. Repeating the same request with the same
`Idempotency-Key` replays the stored response and appends no further event;
reusing the key with a different secret, `sequence` or `nonce` is
`409 conflict`. Concurrent issuances linearize exactly like a serial
execution and produce at most one issuance event per idempotency key.

### Verify an audit receipt

```http
POST /audit/receipts/verify
Content-Type: application/json

{"receipt": { ...issued receipt... }, "public_key": "PpGREZtD1Y_nXMlx6zHbVFS4dRhZeQCwDm3hjIIebFI"}
```

Independently verifies a receipt against a public key. The body must contain
exactly `receipt` and `public_key`; no `Idempotency-Key` is required, and
the service neither reads nor modifies any custody state. A malformed
document (missing, extra or wrongly typed fields, bad digests or bad Base64)
is `400 validation_error`. A well-formed document whose event hash, head
position or public-key digest does not match answers
`{"valid":false,"reason":"receipt_integrity"}`; a well-formed document whose
Ed25519 signature does not verify answers
`{"valid":false,"reason":"signature_mismatch"}`; both come with HTTP 200. A
fully consistent receipt answers:

```json
{"valid":true}
```

### Export a backup

```http
GET /secrets/prod-db-root/backup
```

Returns a self-contained JSON backup of one secret, intended for offline
custody and independent verification. Exporting is read-only: it needs no
`Idempotency-Key`, appends no audit event, and works while the secret is
frozen. Unknown secrets return 404 `not_found`.

The top level carries exactly `backup_version` (always
`thresholdsafe-backup-v3` for new exports), `generated_at` (the usual UTC
timestamp), `authorization_policy` (the persistent authorization policy
expression, or `null`), `secret`, `versions`, `shares`, `approvals`,
`audit_events` and
`checksum`. `secret` is
the stored record — including `secret_length` and `secret_digest`, never the
plaintext. `versions` is a snapshot of the holder and approver rosters of
every version from 1 to the current one, each entry carrying `version`,
`approval_mode`, `holders` and the effective `approvers`, so the role
attribution of every share and approval can be checked against the version
it belongs to. `shares` covers every version, each entry keeping `share_id`,
`secret_id`, `version`, `holder`, `coordinate`, `value`, `commitment`,
`distributed_at` and `invalidated_at`, so issued, distributed and invalidated
shares stay distinguishable. `approvals` and `audit_events` are the complete
tables for the secret. `checksum` is the lowercase hex SHA-256 of the other
top-level values encoded as canonical JSON (sorted keys, compact separators),
so field order and whitespace are irrelevant.

> **Warning.** Share values are part of the backup, so the document is
> sensitive material: anyone holding it can recover the secret with
> `threshold` shares. Store it like the secret itself.

### Verify a backup

```http
POST /backups/verify
Content-Type: application/json

{"backup": { ...exported document... }}
```

Independently verifies a backup document. The body must contain exactly
`backup`; no `Idempotency-Key` is required, and the service neither reads nor
modifies any state — nothing is audited and no idempotency record is stored.
A malformed document (missing, extra or wrongly typed fields, an unsupported
`backup_version`, or a syntactically invalid `authorization_policy` in a v2
or v3 document) is `400 validation_error`. `thresholdsafe-backup-v1` (the
original layout, without `authorization_policy`), `thresholdsafe-backup-v2`
(without `versions`) and `thresholdsafe-backup-v3` documents are accepted;
v1 and v2 documents carry no role snapshots and are read in legacy mode,
where a version's approvers are its holders. A well-formed document
whose checksum does not match, or whose secret ownership, version
continuity (of the shares and, in v3, of the `versions` snapshots),
`share_id` ownership, share value/commitment pairs, approver-to-version role
attribution or
audit ordering and chain hashes are inconsistent, is `409 backup_integrity`;
verification never partially accepts. A valid backup returns HTTP 200:

```json
{"valid":true,"secret_id":"prod-db-root","version":1,"share_count":5,"approval_count":2,"event_count":8}
```

### Restore a backup

```http
POST /backups/restore
Idempotency-Key: demo-restore
Content-Type: application/json

{"backup": { ...exported document... }}
```

Rebuilds the custody state of one secret from a backup document. The body
must contain exactly `backup` and an `Idempotency-Key` is required. The
document is first checked against the same contract `POST /backups/verify`
applies: a malformed document or an unsupported `backup_version` is
`400 validation_error`, and a well-formed document whose checksum, secret
ownership, version continuity, role attribution, share commitments or audit
chain is inconsistent is `409 backup_integrity`. A secret with the same id
already present in the target database is `409 conflict`.

On success the secret record, every share of every version, all approvals
and the original audit chain are written in one transaction — preserving
the current version, threshold, holders, approval mode, authorization
policy, frozen status, status reason, every timestamp, the distribution and
invalidation marks of each share and the consumption state of each
approval — and a `backup_restored` event is appended to the imported chain.
Its payload carries `backup_version`, the backup `checksum`, the
`previous_head_hash` of the imported chain and the imported counts, so
later audit reads and re-exported backups cover the restore. v1 and v2
documents restore in the legacy approval mode (a version's approvers are
its holders), with a `null` policy for v1; v3 documents restore the
per-version role snapshots they carry. A secret restored in the frozen
state is frozen immediately. A backup contains no receipt-signing key, so
the restore never replaces the target database's own key: receipts issued
afterwards are signed with the target key. The response is HTTP 201:

```json
{"restored":true,"secret":{"id":"prod-db-root", ...standard custody record... },"imported":{"shares":5,"approvals":2,"audit_events":8}}
```

Every failure is atomic: a rejected restore leaves no partial data, no
`backup_restored` event and no idempotency record. Repeating the same
request with the same `Idempotency-Key` replays the first successful
response without importing again; reusing the key with a different backup
is `409 conflict`. Concurrent restores of the same secret linearize, so
exactly one of them succeeds.

## Data model

| Table | Key | Contents |
| --- | --- | --- |
| `secrets` | `id` | JSON document: name, current version, threshold, holders, approvals_required, approval mode and approver roster, per-version role snapshots, secret digest, secret length, authorization policy, status (`active`/`frozen`), status reason and change timestamp, timestamps |
| `shares` | `share_id` | secret, version, holder, coordinate `x`, value `f(x)`, commitment, `distributed_at`, `invalidated_at` |
| `approvals` | `(secret_id, version, approver)` | `created_at`, `consumed_at` |
| `audit_events` | `(secret_id, sequence)` | type, canonical payload, `occurred_at`, `previous_hash`, `hash` |
| `idempotency` | `key` | operation name, stored response |
| `receipt_keys` | singleton row | the Ed25519 receipt-signing key (private half included — it never leaves the database), public key, `key_id`, creation timestamp |

Issuance, distribution, approval, reconstruction, rotation, freeze or
unfreeze and backup restore each run inside one `BEGIN IMMEDIATE`
transaction, so a rejected
request leaves no partial state and every request observes a complete
pre- or post-transition snapshot. A write rejected because the secret is
frozen commits in that same transaction only its `operation_blocked` event,
with no idempotency record; a policy denial likewise commits only its
`authorization_denied` event. The single case with a separate transaction is a
rejected reconstruction, whose audit event is committed on its own after the
attempt rolls back.

## Determinism

Issuance is reproducible when the request carries `seed`: the polynomial
coefficients are then drawn from a seeded generator, so the same request body
produces byte-identical shares. Without `seed` the service draws coefficients
from its configured randomness source, which defaults to `secrets.randbelow`
(operating-system entropy) and can be replaced by passing any object with
`randbelow(bound)` to `ThresholdSafe(database, source=...)`. Seeded issuance is
a reproducibility aid for tests and demos, not an unpredictability guarantee.

## Errors

Errors use this shape:

```json
{"error":{"code":"validation_error","message":"human readable detail"}}
```

| Code | Status | Meaning |
| --- | --- | --- |
| `validation_error` | 400 | missing or unknown field, malformed body, bad identifier, policy violation, invalid approver roster or quorum, unregistered holder or approver |
| `share_mismatch` | 400 | a submitted share value does not match the commitment stored at issuance |
| `not_found` | 404 | unknown secret, unknown share, share of another secret, unknown route |
| `conflict` | 409 | duplicate secret id, or an idempotency key reused for another operation |
| `insufficient_shares` | 409 | fewer than `threshold` shares were submitted |
| `insufficient_approvals` | 409 | the approval policy for the current version is not satisfied |
| `stale_share` | 409 | the share belongs to a version invalidated by rotation |
| `share_not_distributed` | 409 | the share exists but was never handed to its holder |
| `share_already_distributed` | 409 | that holder already received the share for this version |
| `duplicate_approval` | 409 | that approver already approved this version |
| `integrity_failure` | 409 | the recovered value does not match the stored commitment |
| `policy_denied` | 409 | the persistent authorization policy denies the attempted reconstruction or rotation |
| `secret_frozen` | 409 | the secret is frozen, or a freeze was requested while already frozen |
| `secret_not_frozen` | 409 | an unfreeze was requested while the secret was active |
| `backup_integrity` | 409 | a structurally valid backup fails checksum or internal consistency checks |
| `audit_integrity` | 409 | a receipt was requested for a secret whose audit chain does not re-verify |
| `internal_error` | 500 | unexpected server failure |

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```
