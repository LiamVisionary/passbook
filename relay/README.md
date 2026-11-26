# The PassBook relay

The small server PassBook uses when two things cannot talk to each other directly: a computer
joining another, a backup kept off the machine, a phone answering a request, a member reporting to
the owner who shares with it. It is a Cloudflare Worker with a D1 database, about a thousand lines,
and this folder is all of it.

PassBook uses `https://hivemindos-passbook-relay.hivemindos.workers.dev` unless you tell it
otherwise. That relay runs this code. The one thing it adds is a lookup of whether the PassBook
asking has a paid plan, which decides the numbers in `src/plan.ts`. A relay you run has no plans
and no billing: everybody it serves gets everything the code can do.

## What a relay can and cannot see

It is built so that running one is not a position of trust over anybody's keys.

| It carries | What it can read | What it cannot do |
|---|---|---|
| Envelopes of keys for a linked computer or a member | Who lends to whom, and when | Open an envelope: each is sealed to the machine it is for |
| An invite | Its id | Join it: the secret in `pbj1.<id>.<secret>.…` never arrives, and the owner checks the joiner's HMAC |
| A backup | Its size, its label, when it was made | Open it: it is encrypted with a passphrase that never arrives |
| A question for a phone | Which phone, and when | Read it (encrypted to the phone) or answer it (PassBook checks the phone's signature) |
| A member's report of key use | Which member reported, and when | Read it: it is sealed to the owner |

One limit, said plainly. The page a phone opens (`/phone`) is served by the relay. Everything in
the fourth row holds against a relay that stores and forwards. It does not hold against a relay
changed to serve a different page, because the page is what holds the phone's key. Every answer a
phone gives is written to Activity on the machine that asked, so a wrong one can be seen, and a
phone can only answer a request to *use* a key, never one to add, change or delete.

Every request from a machine is signed with that machine's own key, so there are no accounts and no
passwords here:

```
X-PassBook-Proof: <did:key> <unix seconds> <Ed25519 signature, base64url>
signed text:      passbook-relay:v1\n<METHOD>\n<path and query>\n<seconds>\n<sha256 hex of the body>
```

## Run your own

You need a Cloudflare account and Node 23.6 or newer.

```bash
cd relay
npm install
npx wrangler d1 create passbook_relay
```

Put the id it prints into `wrangler.jsonc`, then:

```bash
npx wrangler d1 execute passbook_relay --remote --file=./schema.sql
npx wrangler deploy
```

On every machine that should use it, both ends of a link included:

```bash
export PASSBOOK_WEB_RELAYS=https://passbook-relay.<your-subdomain>.workers.dev
export PASSBOOK_MACHINE_RELAY=https://passbook-relay.<your-subdomain>.workers.dev
```

PassBook only ever talks to relays on that list, so a link cannot send an envelope anywhere else.
`MAX_MACHINES` in `wrangler.jsonc` is how many computers one PassBook may lend to through your relay.

## Routes

| Route | Who signs | What it does |
|---|---|---|
| `GET /api/passbook/plan` | owner | What this relay carries for this PassBook, and how much is used |
| `POST /api/passbook/machine-invites` | owner | Open an invite (`kind`: `machine` or `member`) |
| `POST /api/passbook/machine-invites/:id/join` | joiner | Join it with a pairing token and an HMAC |
| `GET /api/passbook/machine-invites/:id` | owner | Read who joined |
| `POST /api/passbook/machine-invites/:id/answer` | owner | Answer with a sealed envelope, or decline |
| `GET /api/passbook/machine-invites/:id/result` | joiner | Collect the envelope |
| `GET /api/passbook/machines` | owner | Everything this PassBook lends to |
| `POST /api/passbook/machines/:did/envelope` | owner | Send a linked machine fresh keys |
| `GET /api/passbook/machines/:did/envelope?issuer=` | machine | Collect them |
| `DELETE /api/passbook/machines/:did` | either | Unlink |
| `POST /api/passbook/backups` | owner | Keep an encrypted export (the newest five are kept) |
| `GET /api/passbook/backups`, `GET`/`DELETE /api/passbook/backups/:id` | owner | List, read back, remove |
| `POST /api/passbook/backups/:id/recover` | any machine | Read one back with its recovery secret |
| `POST /api/passbook/phones` | owner | Open a link for a phone |
| `POST /api/passbook/phones/:id/join` | nobody (the link's id) | The phone's public keys and HMAC |
| `GET /api/passbook/phones/:id`, `POST …/confirm`, `DELETE` | owner | Check what joined, accept it, unlink it |
| `POST /api/passbook/approvals`, `GET`/`DELETE /api/passbook/approvals/:id` | owner | Ask a phone, read its answer, withdraw |
| `GET /api/passbook/phones/:id/requests` | phone | What is waiting |
| `POST /api/passbook/approvals/:id/decision` | phone | Its signed answer |
| `POST /api/passbook/team/events` | member | Report uses of an owner's keys, sealed to the owner |
| `GET /api/passbook/team/events?after=&afterId=` | owner | Read them |
| `GET /phone` | nobody | The page a phone opens |

Limits are in the source next to what they limit: 15 minutes for an invite or a phone link, 256 KB
for an envelope, 1 MB for a backup, 90 days and 5,000 rows of member reports per owner.

## Test

```bash
npm test          # node --test, against node:sqlite standing in for D1
npm run typecheck
```
