# Signing, distribution, and what it actually buys

Rizzma Inc., Apple Team **L7XLLTV3X7**.

> These are the maintainer's own release credentials, and a Team ID is public
> — it appears in the signature of every signed macOS binary. If you are
> building your own copy, substitute your team throughout; nothing here depends
> on this particular one.

## Where this stands

Both certificates are now in the login keychain:

```
Apple Development: Abdel Nabut (B3MTX9DN8X)          builds for your own devices
Developer ID Application: Rizzma, Inc. (L7XLLTV3X7)  distribution to other Macs
```

`Apple Development` cannot sign anything for distribution — Gatekeeper will not
accept it on someone else's Mac — so it is the second one that matters here.
Check yours with:

```bash
security find-identity -v -p codesigning | grep "Developer ID Application"
```

If that prints nothing, create the certificate at developer.apple.com →
Certificates → **+** → **Developer ID Application**, download the `.cer`, and
double-click it. It needs a signed-in session on the portal, so it is not
something a script can do for you.

One warning from experience: an earlier `dev-codesign-runner.sh` hardcoded a
signing identity and piped `codesign` errors to `/dev/null`. Every signing
silently failed, the app fell back to an ad-hoc signature, and macOS re-prompted
for folder access on every rebuild because an ad-hoc identity changes with the
binary. The cause took a day to find. **Do not add a fallback that hides the
error** — a build that cannot sign should stop and say so.

## What signing buys PassBook

Two separate things, and only the second is a security boundary.

### 1. Distribution without a Gatekeeper wall

Notarized builds install without the "unidentified developer" refusal. This is
the whole story for the Tauri app and for any packaged CLI.

### 2. Caller verification — the thing the broker cannot do today

The broker's headline limit is that anything running as you can connect to its
socket and claim to be any app. On macOS that is fixable, but only with a signed
binary:

- `getsockopt(LOCAL_PEERPID)` gives the connecting process's pid
- `SecCodeCopyGuestWithAttributes` turns that pid into a code object
- `SecCodeCheckValidity` against a requirement such as
  `anchor apple generic and certificate leaf[subject.OU] = "L7XLLTV3X7"`
  proves the caller is genuinely one of ours

Then "I am the Content Studio" stops being a claim in a JSON field and becomes
something the kernel vouches for.

Paired with a keychain ACL that names only the signed broker, the store can be
sealed with a key nothing else can read silently — which closes the other limit,
that the file is still there to be read directly.

## The part that does not work, and will not

**A signed interpreter does not identify a script.** Python scripts, CLI tools
and agents are all run by the same `python`, so they all present the same code
signature. The broker can prove *an* interpreter is Apple-signed; it can never
tell `content-studio.py` from `steal-everything.py` when both are run by it.

So signing splits PassBook's population in two, and the product should say so:

| Caller | With signing |
|---|---|
| A bundled app (Tauri PassBook, HivemindOS desktop, a packaged studio) | Identity is **enforced**. The broker refuses an impostor. |
| A script, CLI or agent under a shared interpreter | Identity stays a **claim**. Audit and blast-radius only, exactly as today. |

That is not a shortcoming to engineer around — it is what process identity means
on a shared-interpreter runtime. The honest product shape is: bundled apps get
enforcement, everything else gets the record. Anything that blurred the two
would be selling the weaker half as the stronger one.

## Order of work

1. Get the Developer ID Application certificate (above) — blocks everything else
2. `notarytool store-credentials` for a keychain profile, so CI can notarize
3. Ship the Tauri app signed and notarized; it is a bundle, so it gets enforced
   identity on day one
4. Add peer verification to the broker, applied **only** to callers that present
   a verifiable code identity; unsigned callers keep today's semantics and are
   labelled as such in the record
5. Move the sealing key to a keychain item whose ACL names the signed broker

Steps 4 and 5 are what turn `denied` in the record from "an app asked for
something it is not set up to need" into "an intruder was turned away" — but
only for the rows where the caller was a signed bundle. The record should carry
that distinction per row rather than in a footnote.
