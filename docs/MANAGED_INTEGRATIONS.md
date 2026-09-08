# Managed integrations and agent access

Status: PassBook 1.7.1 implements the managed protocol described below. The
full host experience remains an acceptance target, not a claim that every
capability below has shipped in every host application. The implemented
wire contract and its limits are recorded in [MANAGED_PROTOCOL.md](MANAGED_PROTOCOL.md).
It supplements the optional broker layer; it does not change the dependency-free
store contract in `SPEC.md`.

The PassBook implementation includes password-based setup, managed
operation approval, encrypted multipart recovery of an existing workspace without
its local profile, and owner-approved automatic peer updates. Peer permissions
last 30 days, default to exact key names, preserve local edits, and retain the
receiving copy when a key is removed at the source. They are one-way update
permissions, not full bidirectional file sync.
Future-key scope needs separate explicit consent on both devices. The source
password and receiving local password are submitted once during enrollment and
are not saved by the transport. Source and receiving background capabilities
remain separate from permission to transfer keys.

These implementation details do not mark every delivery target below complete.
In particular, native/passkey vault setup, every external runtime adapter,
platform cold-start verification, and isolation from unrestricted same-user code
must be assessed separately. A modern running broker that lacks the protocol
reports an update-required state; it is not automatically restarted while work
may be active. The protocol document records the exact retry and crash limits.

## Product promise

Connect a host application once. Save a credential once. Approved tasks can use
it across supported runtimes without putting its value into model context.
Ask the owner only when new permission or recovery is needed, then resume the
waiting task automatically.

PassBook remains usable independently of any host application or cloud account.
HivemindOS is a reference integration of this generic contract.

## Three separate decisions

1. **Connect an application:** bind a verified installation to a chosen workspace
   and permitted services. This is durable, revocable authorization.
2. **Allow background operation:** enroll protected device access so the broker
   can serve the approved integration while the owner is away. This does not
   authorize every process running on that device.
3. **Allow an agent operation:** authorize a verified agent to use a credential
   through specified operations. It never inherits the host's administrative
   powers merely because the host launches it.

The first two belong in one understandable installation screen. Individual
agent grants are shown only when existing permissions do not cover the request.
Human authentication, vault decryption, and authorization have different jobs;
a successful sign-in must not silently mean unrestricted credential access.

## First installation

The installer detects the actual state: absent installation, installed but
uninitialized, existing local workspace, or existing linked workspace on another
device. A missing local profile does not prove that the owner has no workspace.

For a genuinely new store:

1. Install the supported PassBook runtime and its managed background service.
2. Show **Set up secure keys**, integrated into the host's setup. Explain that
   the host can use its keys for connected services and keep approved tasks
   running in the background. Offer **Set up** and **Later**.
3. Create the first workspace with the host's name, such as **HivemindOS**.
   Workspace and vault-profile mechanics stay out of the ordinary flow.
4. Establish an owner authentication and recovery method in the same flow.
   Prefer a supported passkey; provide a PassBook password fallback. Reusing
   an existing owner identity requires an explicit trust relationship, not a
   display-name match. Do not invent and save a hidden vault password.
5. Bind the verified installation to this workspace, enroll the explicitly
   approved background capability, and start the service automatically.
6. Register runtime adapters and safe credential-use tools automatically.
7. Verify the binding, workspace, background capability, and usable broker path
   before showing **Keys ready**. Resume the host setup.

If a legacy store already exists, adopt its entries in place through a staged,
recoverable migration. Preserve values, metadata, scope, and project overrides;
do not leave plaintext mirrors after a successful managed migration. Do not
seal someone else's existing workspace or expand its grants without consent.
An interrupted setup resumes rather than creating duplicate workspaces or keys.

Choosing **Later** leaves unrelated host features usable. A feature that needs
a credential reopens the same setup in context and resumes when completed.

## Existing PassBook installation

1. Show **Connect PassBook** in host setup.
2. Open a PassBook-owned authorization surface: the installed app when it can
   verify the requesting installation, otherwise the system browser.
3. Offer **Create a HivemindOS workspace** or **Use an existing workspace**.
   Reuse an existing HivemindOS binding automatically when it is still valid.
   A dedicated workspace has no implicit inheritance from personal workspaces.
4. Show the selected workspace, device, requested service access, and background
   operation in one consent screen. Authenticate once with the owner's supported
   passkey, native authentication, or PassBook password.
5. Return the authorized binding to the installation, start/reconnect the service,
   verify access, and resume setup. The owner's active desktop workspace does
   not change.

Adding a machine to an already connected fleet enrolls that machine into the
existing binding. Device authorization can be included in the authenticated fleet
join screen; joining a network alone is not credential authorization. Display the
machine and workspace being enrolled. Transfer only the approved material over
the authenticated enrollment path; never sync an unopenable ciphertext file and
report the device ready.

For a truly headless installation, approve from an existing trusted host UI or
from a verification URL and short matching code on another device. A QR code is
an optional convenience. The installer waits and continues automatically.
Interactive CLI consent is a fallback, not a required extra step after browser
approval. No desktop app is required on the headless machine.

Browser authorization should use established native-app authorization with PKCE
where applicable; device authorization is for installations without a usable
browser. Local-only operation must not acquire a mandatory hosted dependency.
See [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) and
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

## Normal use and permission defaults

| Situation | Behavior |
| --- | --- |
| Host's previously connected service | Use its standing, scoped authorization silently. |
| Agent operation covered by an existing grant | Run without another prompt. |
| New permission needed | Create one request, show it to the owner, and pause the relevant operation. |
| Credential absent | Offer a secure **Add key** form in that request; save once and continue. |
| Broker stopped or connection stale | Repair automatically without expanding authorization. |
| Owner revoked access or explicitly locked background access | Respect that decision; do not auto-unlock around it. |
| Human recovery/unlock required | Offer **Unlock** in the app or trusted browser, then resume. |
| Policy forbids the operation | Explain the restriction; do not call the key missing or suggest signing in. |

Connecting a provider should establish the expected permission for the host's
trusted connector. Agents using that already approved connector do not need to
repeat provider setup, but each still needs an operation grant under its own
authenticated identity. An existing agent permission can cover that operation
without a new prompt. Actions with their own consent requirements, such as
spending or publishing, still use those action controls. Credential permission
alone does not authorize every action the provider API supports.

Custom agent tools request additional authority only when needed. The ordinary
choice is **Allow for this task**, which covers the described operation and its
safe retries until task completion or a bounded expiry. It does not approve
arbitrary new instructions added to the task. Offer **Allow once** when the owner
wants narrower access, plus an unchecked **Remember for this agent and key**.

An advanced **Allow this agent to use all keys in this workspace** control stays
off by default. Its confirmation explicitly says whether future keys are covered;
the proposed control covers current and future keys in that workspace. It still
respects provider/action restrictions, never enables plaintext export, and does
not include other workspaces. New agents do not inherit it automatically.

## One request, several surfaces

Example review card (illustrative task and agent):

> **Hermes needs access to Relay**
>
> To finish the task you started in hivemindos-mobile.
>
> HivemindOS workspace · MacBook Pro
>
> Connection: RELAY_API_KEY · Requested action and destination shown here
>
> **Allow for this task** · **Deny**
>
> [ ] Remember for Hermes and this key
>
> More access options

Use familiar connection names first, with the environment variable available for
clarity. Show the authenticated agent, workspace, device, requested operation,
destination/account, and bounded purpose. An agent-supplied reason is explanatory
text, not proof that the request is legitimate.

PassBook holds the authoritative request. The host projects its safe metadata
into the top **Needs your approval** area of Inbox, a foreground approval popup,
and a high-priority push alert. These are three views of the same request.

- Pending credential approvals remain above ordinary Inbox items until resolved;
  marking one read does not grant access or hide an unresolved decision.
- Open the popup when the user is in the app; notify in the background. Do not
  interrupt unrelated typing with repeated dialogs or notify again on every retry.
- A push opens the authenticated review screen. It never contains a key, password,
  approval capability, or sensitive task text on the lock screen. OS notification
  permissions and delivery limits still apply.
- Authenticate the decision against the exact request and selected grant scope.
  The broker must verify and consume a short-lived, single-use proof. A button
  click, generic dashboard session, or claimed approver name is insufficient.
- Authenticate **Add key** submissions through the trusted PassBook surface.
  Values go directly to encrypted storage, never into chat or notification data.
- Approving resolves every surface and resumes the waiting operation. A retry
  must not execute a side effect twice. Denial, cancellation, expiry, and an
  already-resolved request each have explicit outcomes.

Pending requests survive broker/app restarts and ordinary phone response delays.
Use a durable waiting state instead of relying on a 60-second open socket.
Deduplicate only identical authenticated requests and scopes; a broader request
must not piggyback on approval of a narrower one.

## Required enforcement boundaries

Every managed request carries a verified installation, stable agent principal,
workspace, credential identity, operation, destination/account, task reference,
and expiry. The effective permission is the intersection of installation,
workspace, agent, credential, and action restrictions. A runtime/model label is
not identity; changing models does not erase or broaden the agent's permissions.
External runtimes enroll through the same adapter contract. Unknown callers do
not borrow a trusted agent's grants.

Resolve the credential and its decryption context using the authenticated binding
on every operation. Do not rely on the desktop's current selection or a
caller-supplied workspace string. UI hiding is not authorization enforcement.

For the managed no-plaintext path, keep keys inside PassBook or trusted connector
processes outside agent-controlled execution. Return operation results, not
values. Constrain requests by account and operation as well as destination;
an allowed hostname can still host an attacker-controlled account or resource.
Disable secret-returning tools for managed agents, and remove raw keys from their
inherited environments, readable runtime files, and logs.

Arbitrary code that receives a credential can transform, write, or transmit it.
Consequently, `run` plus output redaction is a trusted-process compatibility mode,
not a strong no-extraction guarantee. Preserving that guarantee requires a broker
and OS/process boundary that agent-controlled code cannot modify or bypass.
Automatic redaction remains defense in depth; see
[GitHub's documented redaction limits](https://docs.github.com/en/actions/reference/security/secure-use).

Passkeys authenticate a human decision; they do not by themselves provide
unattended vault decryption. Background access needs appropriately protected
device key material or an authenticated remote broker. Broker-only access must
be enforced against agent processes; an ordinary same-user keystore item is not
sufficient isolation by itself. Verify each platform's service and keystore
behavior, including cold restart and a locked desktop. If the platform cannot
provide the selected behavior, expose the specific recovery step instead of
silently falling back to a plaintext key file. WebAuthn approval verification
must require and validate user verification; see
[WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).

## Settings, revocation, and recovery

Keep ordinary controls in **PassBook → Connected apps → HivemindOS**: workspace,
connected devices, background access, agent permissions, recent use, and
**Disconnect**. Put broker diagnostics behind an advanced view.

Disconnect revokes future operations and grant renewal. Revoke an individual
agent/key without disconnecting the host. Explicitly identify running trusted
processes that already received values: stop them where supported, and explain
that copied or externally issued credentials may require provider rotation.
Offline devices cannot receive instantaneous revocation; use expiring device
leases and report the effective offline limit.

Closing the desktop window does not cancel authorized background work. An
explicit **Pause background access** or device revocation stops new managed
operations and ends running jobs where supported, subject to the documented
offline lease limit. Make these distinct from locking the owner's management UI.

Recovery restores access to the existing workspace. It never silently replaces
keys, creates an unrelated profile, or treats encrypted entries as absent.

## Delivery sequence and acceptance

1. Complete verified workspace binding, agent identity, authenticated approval,
   and broker/process isolation for the managed path.
2. Deliver installation/enrollment and durable service access on each supported
   platform. Refresh existing installs without losing grants or interrupting
   credential-bearing jobs unsafely.
3. Connect durable requests to Inbox, push, popup, secure key entry, and task
   resumption. Reuse host notification and authentication presentation where
   suitable; PassBook remains the authority for credential decisions.
4. Update MCP/CLI guidance and runtime adapters together. Agents receive
   machine-readable states such as ready, awaiting approval, absent, locked,
   denied, and reconnecting, with a request reference when action is pending.

Validate through real installer, app, CLI, and managed agent paths with dummy
credentials before using existing stores:

- Fresh install, installed-but-uninitialized, existing workspace, and second
  device enrollment all end in usable credentials with no broker/signin commands.
- Desktop workspace changes cannot redirect the host's credential lookup; a
  dedicated workspace cannot inherit personal keys accidentally.
- Approved operations still work after app restart, broker recovery, and the
  supported cold-restart/locked-screen conditions without new human approval.
- Spoofed agent names, different workspace IDs, broader destinations, reused
  proofs, and direct approval calls cannot acquire another grant.
- Agents cannot retrieve keys through plaintext tools, inherited env, runtime
  files, transformed output, or a permitted provider's unintended destination.
- Concurrent identical requests make one approval; one decision resolves all
  surfaces and resumes once. Denial, timeout, and revocation remain enforced.
- A missing key is added securely in context; a locked key is recovered without
  duplication. Permission failures never become misleading sign-in instructions.
- Installation and migration failures preserve the previous usable state;
  reinstalling neither duplicates stores nor silently broadens authorization.

The integration work belongs in host adapters. PassBook's public package owns
the reusable enrollment, binding, policy, approval, and credential-use contract;
it must not depend on a particular host's private routes or source code.
