# Managed host contract

Available in PassBook 1.7.1. Host applications must implement this contract
to expose managed setup, approvals, and automatic peer updates.
This optional layer leaves the standalone Python/JavaScript store contract intact.

## Trust boundary

The host is trusted to authenticate its agents, verify owner authentication, and
keep its installation signing key out of agent processes. PassBook verifies the
installation signature and enforces its bound workspace and operation grants.
MCP client display names are never authentication.

`service-values`, `service-write`, and `service-remove` are privileged host
operations. They are not agent tools. The first deliberately returns values to
trusted server-side connectors. A host must never expose these operations through
an agent-accessible passthrough or allow callers to set `ownerVerified`.

This protocol is not an OS sandbox. An unrestricted process running under the
owner's OS account may be able to read host authentication files, modify policy,
or use the account's device keystore. Environment filtering and response redaction
do not close those paths. A malicious provider may also transform an echoed
credential beyond recognizable redaction. Use trusted providers and connectors;
do not describe an arbitrary HTTPS proxy as an extraction-proof sandbox.

## Enrollment and startup

An installer invokes `passbook connect --app <id> --identity-env <variable-name>`.
It supplies the installation secret in its protected process environment, never
as an argument. `--workspace` and `--name` customize the owner-facing name.
Interactive setup asks for the password privately and offers existing or
dedicated workspaces. The first workspace adopts and encrypts the original store
in place. Later connections preserve the owner's selected workspace.

`--non-interactive --json` resumes a valid binding or returns `needs-owner`; it
does not invent a password or claim incomplete setup succeeded. The host's setup
screen completes enrollment in the same flow. `disconnect --app ...
--identity-env ... --yes` revokes only that installation and preserves saved keys.

Device-backed background use is part of explicit connection consent. Supported
keystores are reported as `auth.backgroundAvailable`; an unsupported keystore
requires an explicit non-background connection. A locked session then needs an
owner again after broker restart. No plaintext key-file fallback is created.

Successful background enrollment installs the `com.rizzma.passbook.integrations`
login service on macOS, a systemd user service on Linux, or a logon scheduled task
on Windows. It pins the store root and preserves a running broker. Status reports
service installation separately from vault readiness. Explicit pause and
disconnect survive reconnection attempts. A legacy running broker without the
protocol returns `broker-update-required`; it is not forcibly killed while work
may still be running.

## Transport and signatures

`passbook integration --json` accepts one bounded JSON document on stdin and
returns one JSON document on stdout. Passwords and credential values must not
appear in argv, stderr, logs, or exception messages. The current wire limit is
64 KiB; the authenticated `bodyJson` limit is 48,000 UTF-8 bytes.

A protected local host adapter can instead invoke `passbook integration
--identity-env <variable-name> --json` with `{action, body}`. The CLI derives its
own identity and signs the request; caller-supplied installation IDs, public keys,
and signatures cannot replace it. The variable's value never enters argv or the
reply. For `peer-refresh-proof`, the adapter returns a signed public proof without
starting a broker. Its body accepts only a lease ID, public pairing token, and
requested key names.

The host's Ed25519 seed is SHA-256 of UTF-8 `passbook-integration-v1`, one NUL
byte, and its protected installation secret. `installationId` is the hex SHA-256
of the raw 32-byte public key. Signatures and public keys use unpadded base64url.

Each signed envelope contains `op: "managed"`, `action`, `installationId`,
integer-millisecond `issuedAt`, random `nonce`, `bodyJson`, and `signature`.
Sign UTF-8 JSON for `[1, action, installationId, issuedAt, nonce, bodyJson]`;
the last element is the original JSON **string**, not an object. This avoids
cross-language number reserialization differences. Only that authenticated text
is executed. A separate unsigned `body` is ignored on signed requests.

Proofs expire after two minutes and used nonces are recorded. A names-only
unsigned `state`/`begin` is available before enrollment. Unsigned `connect`
requires the public key, matching installation ID, app/name/workspace, explicit
consent, owner password, and background preference. Existing workspaces require
their own password. Foreign ciphertext without a recoverable profile is preserved
and reported as `workspace-recovery-required`.

## Operations and approvals

Signed `request` and `use` carry `agentId`, key names, operation, exact HTTPS
destination, account, task ID, reason, idempotency key, and optional HTTP
parameters. The host supplies authenticated identity and device context; supplied
task/reason text is explanation rather than authority. Explicit existing key,
project, workspace, and destination restrictions still apply.

Keys are substituted into authentication headers inside the broker. They cannot
be substituted into a URL or request body. Redirects and ambient HTTP proxies are
disabled. The broker redacts recognizable credential echoes from returned
response data, including response header names and short values.

`challenge` binds a random two-minute challenge to the complete request digest,
decision, and selected scope. `decision` consumes it once and requires the vault
password or a host-verified, user-verified WebAuthn assertion bound to that same
challenge and scope. Ordinary dashboard authentication alone does not authorize
a decision. `supply-key` requires the workspace password and stores ciphertext;
overwriting an existing key requires explicit owner editing outside a pending
missing-key request.

Scopes are `once`, `task`, `remember`, and `all-keys`. Task grants expire within
24 hours; once grants expire within two minutes. Persistent grants remain bound
to the agent, workspace, operation/method, destination, account, and project.
All-keys covers current and future key names in that same bound operation scope.
It does not grant arbitrary destinations, export, or process injection.

Requests persist for 24 hours. Identical pending requests are deduplicated and
each retry identifier is bound to the full operation digest. Changing an
operation under the same identifier fails. The broker reserves execution before
contacting a provider, stores the redacted result, and returns it on retries.
After a crash in the uncertain interval it reports `outcome-unknown` instead of
repeating a possible side effect. At most 50 unresolved requests per installation
and agent are accepted. Managed access also writes the existing names-only,
hash-chained access ledger.

## MCP adapter

A host can use its own MCP server or configure `passbook mcp` with:

- `PASSBOOK_AGENT_URL`: HTTPS endpoint root, or HTTP loopback for a local host.
- `PASSBOOK_AGENT_TOKEN`: a scoped agent token, never the host signing secret.
- `PASSBOOK_AGENT_HEADER`: defaults to `Authorization` with a Bearer value;
  adapters with a dedicated agent header may name it explicitly.

The endpoint implements `POST /use` and `GET /requests` with the state shapes
above. `credential_use` waits briefly for approval; if the owner answers later,
the caller resumes with the same idempotency key. Persistent resumption across
agent-runtime termination is the host scheduler's responsibility.

Managed MCP advertises safe tools and refuses direct calls to plaintext or
arbitrary-process tools. A persistent managed-store marker keeps this refusal in
force when the broker is unavailable or the host has disconnected.

## Device transfer

`peer-pair`, `peer-grant`, and `peer-accept` provide an owner-approved encrypted
snapshot between already-connected workspaces. Grant and acceptance require the
owner password and the selected device fingerprint. The existing signed
X25519/AES-GCM envelope verifies issuer, recipient, expiry, and replay. Only
approved names transfer; local-only keys stay on their device. Acceptance seals
values under the receiving workspace's key and preserves existing entries. An
entered owner password opens the selected locked workspace in the same request.
Each batch contains at most 64 names and a 40,000-character envelope; an oversized
batch returns `peer-transfer-too-large` so the host can split it.

Optional `idempotencyKey` on `peer-accept` binds its safe receipt to the receiving
installation, workspace, and exact envelope digest. A fresh authenticated retry
returns the committed receipt; changing the envelope returns
`idempotency-conflict`. Calls without a retry key retain strict envelope replay
refusal. The receipt and credential file are separate durable writes: a hard
crash between them can require reconciliation rather than silently assuming a
snapshot completed. A conflict before writing leaves the envelope unused.

## Recovering a workspace without its local profile

`recovery-pair` accepts the receiving installation's public identity and selected
workspace. It requires orphaned v2 encrypted entries and no existing local vault
profile; an empty, plaintext, or already configured workspace uses ordinary
enrollment instead. Pairing creates no binding, vault profile, or access grant.
The response contains `recoveryId`, exact orphaned key names, a public pairing
token and fingerprint, and `storeDigest`/`vaultDigest`.

The owner authorizes `peer-grant` on the source. The receiver submits each
encrypted envelope through signed `recovery-part` requests containing
`recoveryId`, `envelope`, and `issuerFingerprint`. Proofs use the saved receiving
installation key even before it has a binding. Staging holds only ciphertext and
public metadata, lasts ten minutes, and allows at most 64 disjoint parts totaling
2 MiB. Repeated identical parts are harmless; overlapping key sets are refused.

Final owner-approved `connect` includes the recovery ID, original digests,
selected issuer fingerprint, and a new local password. Every orphaned name must
be covered, the source envelopes must verify, and the original store, vault
metadata, and workspace manifest must still match. The replacement is decrypted
and compared in staging before commit. Original file bytes are retained under
`.passbook-recovery/<recoveryId>.passbook` in the existing password-encrypted
backup format. Existing configuration and local metadata are preserved. Device
decryption keys are not copied into shared files or sent between hosts.

Recovery verifies the selected source's replacement and the new local encryption.
Without the original decryption key it cannot prove that the source value equals
the unreadable old value; the private original-byte archive preserves rollback
evidence. If the replacement committed before app enrollment finished, retry
verifies the archived planned bytes and finishes the replay records and binding.
After a completed response was lost, `recoveryRetry: true` requires the correct
local password, same installation/profile/workspace, and original context before
returning a safe completion receipt. An ordinary replay remains refused.

## Owner-approved automatic updates

Ongoing imports are separate from a one-time snapshot. `peer-authorize` requires
the source password once and pins the source installation/workspace, receiving
installation public key, receiving device DID/fingerprint, and approved names.
The returned lease lasts **30 days**; it does not renew itself. Review the device
permission again after expiry. An exact scope may contain up to 2,048 names;
individual transfer batches still contain at most 64. `allowFutureKeys: true`
requires separate explicit consent on both the source and receiver.

`peer-trust` requires the receiving owner's password and the public lease. Its
`idempotencyKeys` or `recoveryId` identify completed, verified initial imports.
Only entries those imports added or replaced become owned by the lease. Existing
local entries that a snapshot kept never become automatic overwrite authority.
When the owners renew a permission, the receiver also retains recorded
ciphertext versions from the same receiving installation/workspace and exact
source device/workspace. A repeated additive import therefore does not erase
existing ownership. It never adopts an independently changed value merely
because that value is present, and the newly approved key scope still limits it.
Fresh approval replaces prior receiving permissions for that exact source
device/workspace and receiving installation/workspace, including keys omitted
from the new selection. A retry of the same permission changes nothing; a
stopped permission cannot be revived by retrying its ID. Start a new reviewed
connection to resume updates.
The optional transport descriptor identifies a host for rediscovery; it confers
no permission and contains no password, access token, or credential value.

For each refresh, the receiver signs `peer-refresh-proof` with
`{leaseId, pairingToken, keys}`. The source host forwards that proof through its
own signed `peer-refresh` request. The source checks the pinned receiver key,
nonce, clock, device identity, workspace, expiry, and current policy before
producing a normal encrypted envelope. An empty key list returns currently
allowed names and missing initial names, for discovery only. Membership in a
network or a transport header alone never authorizes this operation.

The receiver uses `peer-accept` with `leaseId`, envelope, issuer fingerprint, and
an idempotency key. A valid trusted lease replaces the per-transfer password
prompt. The device-backed workspace must still be ready. Source and receiver
pause, disconnect, expiry, and policy refusal remain effective; disconnect
revokes leases so reconnecting cannot resurrect them. `peer-revoke` stops future
refresh authority. `peer-leases` returns safe metadata including `direction`,
`active`, `keys`, `ownedKeys`, `expiresMs`, and an optional transport locator.

Automatic updates are one-way from the approved source. They replace only absent
entries or ciphertext still matching the lease's last imported version, checked
under the cooperating store-writer lock. Local edits return `peer-sync-conflict`
and are preserved; a host may split a batch to update unrelated keys. Source
removals return `source-missing` and retain the receiving copy. This does not
implement deletion propagation, bidirectional conflict resolution, or immediate
revocation of already imported values. Uncooperative direct file editors remain
outside the writer lock. Authenticated fleet transport, polling, owner UI, and
OS containment remain host delivery gates in
[the integration design](MANAGED_INTEGRATIONS.md).

## Authorizing HivemindOS in the desktop app

The desktop handoff currently supports the `hivemindos` application label.
Other host integrations can use the existing owner-password `connect` protocol;
they do not acquire a desktop handoff by inventing another link name.

`authorize-begin` is signed before enrollment, with exactly `publicKey` and
`app: "hivemindos"` in its body. PassBook verifies possession of that key and
stores a random request ID for ten minutes. There is at most one pending request
per installation and 32 retained requests per store. The link is exactly
`passbook://authorize?requestId=<32 lowercase hex characters>` and carries no
password, signing secret, workspace choice, or grant.

The PassBook desktop retrieves names-only details through `authorize-inspect`,
shows the same eight-character code as HivemindOS, and asks the owner to choose
the workspace and background access. The code identifies the requesting
installation, not a verified publisher or signed executable. Owners should
continue only after starting the request themselves and comparing both codes.

The desktop submits `authorize-decide` with the exact request ID, owner password,
workspace, explicit consent and background choice through CLI stdin. Approval
uses the existing password-verified connection path; a link cannot bypass it.
Approval is single use. Failed password attempts are bounded to five per request
with a one-second retry interval. Declining needs no password because it grants
nothing. Expired, cancelled, and answered requests cannot be approved.

Only the installation that created the request can sign `authorize-status` or
`authorize-cancel`. A successful status permits HivemindOS to read its normal
connection state and resume only when it is actually ready. Credential values
and the owner's password never travel back to HivemindOS in this flow. Background
service installation still reports its actual result. Closing a pending Hive
dialog first cancels that request; closing PassBook alone leaves it to expire.

HivemindOS offers this handoff for a local browser or its desktop shell and opens
the app only on an explicit click. Its password form remains available for a
headless installation, a remote dashboard, or a missing/outdated desktop app.
The real CLI/broker and both UI surfaces are tested with isolated dummy data;
those tests simulate native IPC and operating-system protocol activation. They
do not establish that an installed app, OS key store, or login service works on
a particular owner device.
