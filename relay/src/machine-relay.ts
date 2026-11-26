// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// PassBook machine relay: how a second computer (a bot, a server, another laptop) joins PassBook.
//
// A computer has an identity of its own: PassBook gives every machine an Ed25519 key, so every call
// here is signed by the machine making it and no account is needed. The flow:
//
//   1. the owner's PassBook opens an invite                     POST /api/passbook/machine-invites
//   2. the new machine joins it with its pairing token          POST /api/passbook/machine-invites/:id/join
//   3. the owner's PassBook reads who joined                    GET  /api/passbook/machine-invites/:id
//   4. …and answers with an envelope sealed to that machine     POST /api/passbook/machine-invites/:id/answer
//   5. the new machine collects it                              GET  /api/passbook/machine-invites/:id/result
//   6. the owner keeps it current                               POST /api/passbook/machines/:did/envelope
//      and the machine reads that on its schedule               GET  /api/passbook/machines/:did/envelope?issuer=
//   7. either end unlinks                                       DELETE /api/passbook/machines/:did?issuer=
//
// What the relay never has: a credential (envelopes are sealed to the receiving machine), or the
// invite's secret. The invite the owner copies to the new machine is `pbj1.<id>.<secret>.<code>`;
// the relay sees only the id. The joining machine proves it holds the secret with an HMAC the owner
// checks, so a relay, or anyone who learned the id, cannot slip its own machine in.
//
// Every request carries `X-PassBook-Proof: <did> <unix seconds> <signature>`, an Ed25519 signature
// by that did over `passbook-relay:v1\n<METHOD>\n<path>\n<seconds>\n<sha256 hex of the body>`.
//
// How many machines an owner may lend to is the relay operator's decision, not this file's: the
// caller passes `planFor`, and a relay you run yourself uses OPEN_PLAN (see plan.ts).

import { json, readSigned, DID_SHAPE, ID_SHAPE, DID_IN_PATH, unb64, randomId, label } from "./proof.ts";
import { planOf, notIncluded, type RelayOptions } from "./plan.ts";

export { publicKeyOf, provenDid } from "./proof.ts";

const PAIR_PREFIX = "passbook-pair:v1:";
const ENVELOPE_PREFIX = "passbook-env:v1:";
const INVITE_TTL_MS = 15 * 60 * 1000;
const PAIRING_TTL_MS = 10 * 60 * 1000;
const MAX_ENVELOPE = 262_144;
const MAX_OPEN_INVITES = 10;
const MAC_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/** The public half of a pairing token, checked the way PassBook's read_pairing_token checks it. */
export function readMachinePairingToken(token: string, now = Date.now()): { did: string; expires: number } | null {
  if (typeof token !== "string" || !token.startsWith(PAIR_PREFIX) || token.length > 1024) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(unb64(token.slice(PAIR_PREFIX.length)))) as { v?: number; did?: string; seal?: string; exp?: string };
    const expires = Date.parse(String(payload.exp));
    if (payload.v !== 1 || !DID_SHAPE.test(String(payload.did)) || unb64(String(payload.seal)).length !== 32) return null;
    if (!Number.isFinite(expires) || expires <= now || expires > now + PAIRING_TTL_MS + 60_000) return null;
    return { did: String(payload.did), expires };
  } catch {
    return null;
  }
}

/** Who an envelope is from and to. The body is sealed; the grant beside it is not, by design. */
export function envelopeParties(envelope: string): { iss: string; aud: string } | null {
  if (typeof envelope !== "string" || !envelope.startsWith(ENVELOPE_PREFIX) || envelope.length > MAX_ENVELOPE) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(unb64(envelope.slice(ENVELOPE_PREFIX.length)))) as { grant?: { aud?: string; iss?: string; kind?: string } };
    const grant = parsed.grant;
    if (grant?.kind !== "passbook-grant" || !DID_SHAPE.test(String(grant.aud)) || !DID_SHAPE.test(String(grant.iss))) return null;
    return { iss: String(grant.iss), aud: String(grant.aud) };
  } catch {
    return null;
  }
}

type InviteRow = {
  id: string; issuer_did: string; label: string; status: string; kind: string; device_did: string | null; pairing_token: string | null;
  join_mac: string | null; device_label: string | null; envelope: string | null; expires_at: string;
};
type MailboxRow = { device_did: string; issuer_did: string; label: string; envelope: string | null; envelope_at: string | null; revoked_at: string | null };

export async function handleMachineRelayRoute(request: Request, database: D1Database, now = new Date(), options?: RelayOptions): Promise<Response | null> {
  const read = await readSigned(request, ["/api/passbook/machine-invites", "/api/passbook/machines"], MAX_ENVELOPE + 4096, now);
  if (!read || read instanceof Response) return read;
  const { signer, path, url, body, nowIso } = read;

  if (path === "/api/passbook/machine-invites" && request.method === "POST") {
    await database.prepare("DELETE FROM passbook_machine_invites WHERE expires_at <= ?1").bind(nowIso).run();
    const open = await database.prepare("SELECT COUNT(*) AS n FROM passbook_machine_invites WHERE issuer_did = ?1").bind(signer).first<{ n: number }>();
    if (Number(open?.n ?? 0) >= MAX_OPEN_INVITES) return json({ ok: false, error: "This machine has too many open invites. Let one expire or finish first." }, 429);
    const kind = body.kind === "member" ? "member" : "machine";
    if (kind === "member") {
      // Refused here, before an invite exists, so nobody is sent a line that cannot work.
      const plan = await planOf(signer, options);
      if (plan.seats < 1) return json({ ok: false, code: "seat_limit", limit: 0, plan: plan.plan,
                                        error: notIncluded("Sharing keys with another person is not included for this PassBook on this relay.", plan) }, 409);
    }
    const id = randomId();
    const expiresAt = new Date(now.getTime() + INVITE_TTL_MS).toISOString();
    await database.prepare(
      `INSERT INTO passbook_machine_invites (id, issuer_did, label, status, kind, created_at, expires_at) VALUES (?1, ?2, ?3, 'open', ?4, ?5, ?6)`,
    ).bind(id, signer, label(body.label, "PassBook"), kind, nowIso, expiresAt).run();
    return json({ ok: true, inviteId: id, kind, expiresAt, relay: url.origin });
  }

  const inviteMatch = path.match(/^\/api\/passbook\/machine-invites\/([A-Za-z0-9_-]+)(?:\/(join|answer|result))?$/);
  if (inviteMatch) {
    const [, id, action] = inviteMatch;
    if (!ID_SHAPE.test(id)) return json({ ok: false, error: "That invite was not found." }, 404);
    const row = await database.prepare("SELECT * FROM passbook_machine_invites WHERE id = ?1 LIMIT 1").bind(id).first<InviteRow>();
    const live = !!row && row.expires_at > nowIso;
    const gone = json({ ok: false, error: "This invite has expired. Make a new one in PassBook." }, 404);

    if (action === "join" && request.method === "POST") {
      if (!row || !live || row.status !== "open") return gone;
      const token = String(body.pairingToken ?? "");
      const pairing = readMachinePairingToken(token, now.getTime());
      if (!pairing || pairing.did !== signer) return json({ ok: false, error: "That pairing token is not this machine's." }, 400);
      if (pairing.did === row.issuer_did) return json({ ok: false, error: "A machine cannot join its own invite." }, 400);
      const mac = String(body.proof ?? "");
      if (!MAC_SHAPE.test(mac)) return json({ ok: false, error: "That join could not be read." }, 400);
      const changed = await database.prepare(
        `UPDATE passbook_machine_invites SET status = 'joined', device_did = ?2, pairing_token = ?3, join_mac = ?4, device_label = ?5
          WHERE id = ?1 AND status = 'open'`,
      ).bind(id, signer, token, mac, label(body.label, "A computer")).run();
      if (!Number(changed.meta?.changes ?? 0)) return gone;
      return json({ ok: true, status: "joined" });
    }
    if (!action && request.method === "GET") {
      if (!row || signer !== row.issuer_did) return json({ ok: false, error: "That invite was not found." }, 404);
      if (!live && row.status !== "answered") return json({ ok: true, status: "expired" });
      return json({ ok: true, status: row.status, kind: row.kind, pairingToken: row.pairing_token, proof: row.join_mac,
                    label: row.device_label, expiresAt: row.expires_at });
    }
    if (action === "answer" && request.method === "POST") {
      if (!row || signer !== row.issuer_did) return json({ ok: false, error: "That invite was not found." }, 404);
      if (!live || row.status !== "joined" || !row.device_did) return gone;
      if (body.declined === true) {
        await database.prepare("UPDATE passbook_machine_invites SET status = 'declined', answered_at = ?2 WHERE id = ?1").bind(id, nowIso).run();
        return json({ ok: true, status: "declined" });
      }
      const envelope = String(body.envelope ?? "");
      const parties = envelopeParties(envelope);
      if (!parties || parties.aud !== row.device_did || parties.iss !== signer) return json({ ok: false, error: "That answer is not for this invite." }, 400);
      const member = row.kind === "member";
      const machines = await database.prepare("SELECT COUNT(*) AS n FROM passbook_machine_mailboxes WHERE issuer_did = ?1 AND kind = ?3 AND revoked_at IS NULL AND device_did != ?2")
        .bind(signer, row.device_did, member ? "member" : "machine").first<{ n: number }>();
      // The limit is checked only when a machine is added. One already linked keeps receiving its
      // keys whatever the owner's plan becomes, so a lapsed payment never takes a working machine away.
      const plan = await planOf(signer, options);
      const limit = member ? plan.seats : plan.machines;
      if (Number(machines?.n ?? 0) >= limit) {
        const what = member
          ? `This PassBook already shares with ${limit} ${limit === 1 ? "person" : "people"}, the most this relay carries for it. Remove one first.`
          : `This PassBook already lends to ${limit} ${limit === 1 ? "computer" : "computers"}, the most this relay carries for it. Unlink one first.`;
        return json({ ok: false, code: member ? "seat_limit" : "machine_limit", limit, plan: plan.plan, error: notIncluded(what, plan) }, 409);
      }
      await database.batch([
        database.prepare("UPDATE passbook_machine_invites SET status = 'answered', envelope = ?2, answered_at = ?3 WHERE id = ?1 AND status = 'joined'").bind(id, envelope, nowIso),
        database.prepare(
          `INSERT INTO passbook_machine_mailboxes (device_did, issuer_did, label, kind, envelope, envelope_at, linked_at, revoked_at)
            VALUES (?1, ?2, ?3, ?6, ?4, ?5, ?5, NULL)
            ON CONFLICT(device_did, issuer_did) DO UPDATE SET label = excluded.label, kind = excluded.kind, envelope = excluded.envelope,
              envelope_at = excluded.envelope_at, linked_at = excluded.linked_at, revoked_at = NULL`,
        ).bind(row.device_did, signer, row.device_label || "A computer", envelope, nowIso, member ? "member" : "machine"),
      ]);
      return json({ ok: true, status: "answered" });
    }
    if (action === "result" && request.method === "GET") {
      if (!row || signer !== row.device_did) return json({ ok: false, error: "That invite was not found." }, 404);
      if (row.status === "joined" && !live) return json({ ok: true, status: "expired" });
      return json({ ok: true, status: row.status, envelope: row.status === "answered" ? row.envelope : null });
    }
    return json({ ok: false, error: "Not found." }, 404);
  }

  if (path === "/api/passbook/machines" && request.method === "GET") {
    const rows = await database.prepare(
      "SELECT device_did, label, kind, envelope_at, linked_at, revoked_at FROM passbook_machine_mailboxes WHERE issuer_did = ?1 ORDER BY linked_at",
    ).bind(signer).all<{ device_did: string; label: string; kind: string; envelope_at: string | null; linked_at: string; revoked_at: string | null }>();
    return json({ ok: true, machines: (rows.results ?? []).map(r => ({
      did: r.device_did, label: r.label, kind: r.kind, sentAt: r.envelope_at, linkedAt: r.linked_at, unlinkedAt: r.revoked_at })) });
  }

  const machineMatch = path.match(new RegExp(`^/api/passbook/machines/(${DID_IN_PATH})(?:/(envelope))?$`));
  if (machineMatch) {
    const [, did, part] = machineMatch;
    // The issuer is the signer when the owner calls, and named in the query when the machine does.
    const issuer = signer === did ? String(url.searchParams.get("issuer") || "") : signer;
    if (!DID_SHAPE.test(issuer)) return json({ ok: false, error: "Which PassBook is this for?" }, 400);
    if (signer !== did && signer !== issuer) return json({ ok: false, error: "This machine is not linked." }, 404);
    const box = await database.prepare("SELECT * FROM passbook_machine_mailboxes WHERE device_did = ?1 AND issuer_did = ?2 LIMIT 1")
      .bind(did, issuer).first<MailboxRow>();
    if (part === "envelope" && request.method === "POST") {
      if (signer !== issuer) return json({ ok: false, error: "Only the lending PassBook can send this machine keys." }, 403);
      if (!box || box.revoked_at) return json({ ok: false, error: "This machine is no longer linked.", unlinked: true }, 410);
      const envelope = String(body.envelope ?? "");
      const parties = envelopeParties(envelope);
      if (!parties || parties.aud !== did || parties.iss !== issuer) return json({ ok: false, error: "That envelope is not for this machine." }, 400);
      await database.prepare("UPDATE passbook_machine_mailboxes SET envelope = ?3, envelope_at = ?4 WHERE device_did = ?1 AND issuer_did = ?2")
        .bind(did, issuer, envelope, nowIso).run();
      return json({ ok: true });
    }
    if (part === "envelope" && request.method === "GET") {
      if (signer !== did) return json({ ok: false, error: "Only that machine can collect its keys." }, 403);
      if (!box) return json({ ok: false, error: "This machine is not linked." }, 404);
      if (box.revoked_at) return json({ ok: true, unlinked: true, envelope: null });
      return json({ ok: true, envelope: box.envelope, envelopeAt: box.envelope_at });
    }
    if (!part && request.method === "DELETE") {
      if (box) {
        await database.prepare("UPDATE passbook_machine_mailboxes SET revoked_at = ?3, envelope = NULL WHERE device_did = ?1 AND issuer_did = ?2")
          .bind(did, issuer, nowIso).run();
      }
      return json({ ok: true });
    }
  }
  return json({ ok: false, error: "Not found." }, 404);
}
