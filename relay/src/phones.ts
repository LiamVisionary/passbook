// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// Answering a request for a credential from a phone, without the relay being able to answer for you.
//
// PassBook asks its owner before an agent or app is given a key. Until now the question appeared on
// the machine that was asked, and waited for somebody sitting at it. These routes carry the question
// to a phone and the answer back. The relay is a mailbox between the two and nothing more:
//
//   * It cannot read the question. PassBook encrypts it to a key that exists only in the phone's
//     browser (ECDH P-256, HKDF-SHA256, AES-256-GCM).
//   * It cannot make the answer. The phone signs "allow" or "deny" together with the SHA-256 of the
//     exact question it was shown (ECDSA P-256), and PassBook checks that signature against the key
//     it accepted when the phone was linked. A relay that invents, replays or swaps an answer
//     produces one PassBook throws away.
//   * It cannot link a phone of its own. Linking starts from a code PassBook shows on screen,
//     `pbp1.<id>.<secret>.…`; the relay is told only the id. The phone proves it holds the secret
//     with an HMAC over its public keys, which PassBook checks before it will send that phone
//     anything. This is the same trade the machine invite makes, for the same reason.
//
// All three hold against a relay that stores and forwards, which is what a stolen database or a
// curious operator amounts to. They do not hold against a relay changed to serve a different page
// to the phone, because the page is what holds the phone's key: see phone-page.ts, which says so.
//
// Owner routes, signed by the machine like every other route here:
//
//   POST   /api/passbook/phones                  open a link for a phone       (needs plan.approvals)
//   GET    /api/passbook/phones                  the phones this PassBook has linked
//   GET    /api/passbook/phones/:id              what joined, for PassBook to check
//   POST   /api/passbook/phones/:id/confirm      PassBook checked it: this phone may be asked
//   DELETE /api/passbook/phones/:id              unlink it
//   POST   /api/passbook/approvals               ask the phone something       (needs plan.approvals)
//   GET    /api/passbook/approvals/:id           has it answered
//   DELETE /api/passbook/approvals/:id           never mind (answered at the desk, or too late)
//
// Phone routes. A phone has no machine key, so the first is open to whoever holds the link's id,
// and the rest are signed with the key the phone joined with
// (`X-PassBook-Phone: <phone id> <unix seconds> <signature>`, ECDSA P-256 over
// `passbook-phone:v1\n<METHOD>\n<path>\n<seconds>\n<sha256 hex of the body>`):
//
//   POST   /api/passbook/phones/:id/join         the phone's two public keys and its HMAC
//   GET    /api/passbook/phones/:id/requests     what is waiting for this phone
//   POST   /api/passbook/approvals/:id/decision  the phone's signed answer

import { json, readSigned, randomId, label, sha256hex, unb64, ID_SHAPE, PROOF_SKEW_S } from "./proof.ts";
import { planOf, notIncluded, type RelayOptions } from "./plan.ts";

const LINK_TTL_MS = 15 * 60 * 1000;
const MAX_ASK_MS = 15 * 60 * 1000;
const MAX_PHONES = 5;
const MAX_WAITING = 20;
const MAX_SEALED = 16_384;
const MAX_DECISION = 2_048;
const P256_PUBLIC = 65;           // an uncompressed point: 0x04, x, y
const MAC_SHAPE = /^[A-Za-z0-9_-]{43}$/;

type PhoneRow = {
  id: string; owner_did: string; label: string; status: string; sign_key: string | null; seal_key: string | null;
  join_mac: string | null; created_at: string; expires_at: string; linked_at: string | null; seen_at: string | null;
};
type ApprovalRow = {
  id: string; phone_id: string; owner_did: string; sealed: string; status: string; decision: string | null;
  created_at: string; expires_at: string; decided_at: string | null;
};

function p256(text: unknown): string | null {
  if (typeof text !== "string" || text.length > 100) return null;
  try { const raw = unb64(text); return raw.length === P256_PUBLIC && raw[0] === 4 ? text : null; } catch { return null; }
}

/** True when `signature` is the ECDSA P-256 / SHA-256 signature (r||s, as WebCrypto makes it) of `message`. */
export async function signedByPhone(signKey: string, message: string, signature: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", unb64(signKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, unb64(signature), new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

/** The linked or joined phone that signed this request, or null. */
async function provenPhone(request: Request, database: D1Database, pathAndQuery: string, raw: string, now: Date): Promise<PhoneRow | null> {
  const parts = (request.headers.get("x-passbook-phone") || "").trim().split(/\s+/);
  if (parts.length !== 3) return null;
  const [id, seconds, signature] = parts;
  if (!ID_SHAPE.test(id) || !/^\d{9,11}$/.test(seconds) || Math.abs(now.getTime() / 1000 - Number(seconds)) > PROOF_SKEW_S) return null;
  const phone = await database.prepare("SELECT * FROM passbook_phones WHERE id = ?1 LIMIT 1").bind(id).first<PhoneRow>();
  if (!phone || !phone.sign_key || (phone.status !== "joined" && phone.status !== "linked")) return null;
  const message = `passbook-phone:v1\n${request.method}\n${pathAndQuery}\n${seconds}\n${await sha256hex(raw)}`;
  return await signedByPhone(phone.sign_key, message, signature) ? phone : null;
}

/** The three routes a phone calls. They run before the machine-signed ones, which would refuse them. */
export async function handlePhoneSideRoute(request: Request, database: D1Database, now = new Date()): Promise<Response | null> {
  const url = new URL(request.url);
  let path: string;
  try { path = decodeURIComponent(url.pathname).replace(/\/+$/, ""); } catch { return null; }
  const join = path.match(/^\/api\/passbook\/phones\/([A-Za-z0-9_-]+)\/join$/);
  const requests = path.match(/^\/api\/passbook\/phones\/([A-Za-z0-9_-]+)\/requests$/);
  const decision = path.match(/^\/api\/passbook\/approvals\/([A-Za-z0-9_-]+)\/decision$/);
  if (!join && !requests && !decision) return null;
  const nowIso = now.toISOString();
  const raw = request.method === "GET" ? "" : await request.text();
  if (raw.length > MAX_DECISION + 1024) return json({ ok: false, error: "That request is too large." }, 413);
  let body: Record<string, unknown> = {};
  if (raw) { try { body = JSON.parse(raw) ?? {}; } catch { return json({ ok: false, error: "That request could not be read." }, 400); } }

  if (join && request.method === "POST") {
    const gone = json({ ok: false, error: "This link has expired. Make a new one in PassBook." }, 404);
    if (!ID_SHAPE.test(join[1])) return gone;
    const signKey = p256(body.signKey), sealKey = p256(body.sealKey), mac = String(body.mac ?? "");
    if (!signKey || !sealKey || !MAC_SHAPE.test(mac)) return json({ ok: false, error: "That phone could not be read." }, 400);
    const changed = await database.prepare(
      `UPDATE passbook_phones SET status = 'joined', sign_key = ?2, seal_key = ?3, join_mac = ?4, label = ?5
        WHERE id = ?1 AND status = 'open' AND expires_at > ?6`,
    ).bind(join[1], signKey, sealKey, mac, label(body.label, "A phone", 40), nowIso).run();
    return Number(changed.meta?.changes ?? 0) ? json({ ok: true, status: "joined" }) : gone;
  }

  const phone = await provenPhone(request, database, url.pathname + url.search, raw, now);
  if (!phone) return json({ ok: false, error: "This phone is not linked to a PassBook." }, 401);

  if (requests && request.method === "GET") {
    if (requests[1] !== phone.id) return json({ ok: false, error: "This phone is not linked to a PassBook." }, 401);
    await database.prepare("UPDATE passbook_phones SET seen_at = ?2 WHERE id = ?1").bind(phone.id, nowIso).run();
    // Until PassBook has checked the phone's HMAC, nothing is sent to it. The page shows that it is waiting.
    if (phone.status !== "linked") return json({ ok: true, status: phone.status, requests: [] });
    const rows = await database.prepare(
      "SELECT id, sealed, expires_at FROM passbook_approvals WHERE phone_id = ?1 AND status = 'waiting' AND expires_at > ?2 ORDER BY created_at",
    ).bind(phone.id, nowIso).all<{ id: string; sealed: string; expires_at: string }>();
    return json({ ok: true, status: "linked", requests: (rows.results ?? []).map(r => ({ id: r.id, sealed: r.sealed, expiresAt: r.expires_at })) });
  }

  if (decision && request.method === "POST") {
    const gone = json({ ok: false, error: "That request is no longer waiting." }, 404);
    if (!ID_SHAPE.test(decision[1]) || phone.status !== "linked") return gone;
    // Stored exactly as sent. PassBook reads and verifies it; the relay only carries it.
    const answer = typeof body.answer === "string" ? body.answer : "";
    if (!answer || answer.length > MAX_DECISION) return json({ ok: false, error: "That answer could not be read." }, 400);
    const changed = await database.prepare(
      `UPDATE passbook_approvals SET status = 'decided', decision = ?3, decided_at = ?4
        WHERE id = ?1 AND phone_id = ?2 AND status = 'waiting' AND expires_at > ?4`,
    ).bind(decision[1], phone.id, answer, nowIso).run();
    return Number(changed.meta?.changes ?? 0) ? json({ ok: true }) : gone;
  }
  return json({ ok: false, error: "Not found." }, 404);
}

/** The routes the owner's PassBook calls. */
export async function handlePhoneRoute(request: Request, database: D1Database, now = new Date(), options?: RelayOptions): Promise<Response | null> {
  const read = await readSigned(request, ["/api/passbook/phones", "/api/passbook/approvals"], MAX_SEALED + 4096, now);
  if (!read || read instanceof Response) return read;
  const { signer, path, body, nowIso } = read;
  const notHere = json({ ok: false, error: "Not found." }, 404);

  const refused = async () => {
    const plan = await planOf(signer, options);
    return plan.approvals ? null : json({ ok: false, code: "not_included", plan: plan.plan,
                                          error: notIncluded("Answering requests from a phone is not included for this PassBook.", plan) }, 403);
  };

  if (path === "/api/passbook/phones" && request.method === "POST") {
    const no = await refused();
    if (no) return no;
    await database.prepare("DELETE FROM passbook_phones WHERE owner_did = ?1 AND status IN ('open', 'joined') AND expires_at <= ?2").bind(signer, nowIso).run();
    const held = await database.prepare("SELECT COUNT(*) AS n FROM passbook_phones WHERE owner_did = ?1 AND status != 'revoked'").bind(signer).first<{ n: number }>();
    if (Number(held?.n ?? 0) >= MAX_PHONES) return json({ ok: false, error: `This PassBook already has ${MAX_PHONES} phones. Unlink one first.` }, 409);
    const id = randomId();
    const expiresAt = new Date(now.getTime() + LINK_TTL_MS).toISOString();
    await database.prepare(
      "INSERT INTO passbook_phones (id, owner_did, label, status, created_at, expires_at) VALUES (?1, ?2, ?3, 'open', ?4, ?5)",
    ).bind(id, signer, label(body.label, "A phone", 40), nowIso, expiresAt).run();
    return json({ ok: true, phoneId: id, expiresAt });
  }

  if (path === "/api/passbook/phones" && request.method === "GET") {
    const rows = await database.prepare("SELECT * FROM passbook_phones WHERE owner_did = ?1 AND status = 'linked' ORDER BY linked_at").bind(signer).all<PhoneRow>();
    return json({ ok: true, phones: (rows.results ?? []).map(r => ({ id: r.id, label: r.label, linkedAt: r.linked_at, seenAt: r.seen_at })) });
  }

  const phoneMatch = path.match(/^\/api\/passbook\/phones\/([A-Za-z0-9_-]+)(?:\/(confirm))?$/);
  if (phoneMatch) {
    const [, id, action] = phoneMatch;
    const phone = ID_SHAPE.test(id) ? await database.prepare("SELECT * FROM passbook_phones WHERE id = ?1 LIMIT 1").bind(id).first<PhoneRow>() : null;
    if (!phone || phone.owner_did !== signer) return json({ ok: false, error: "That phone was not found." }, 404);
    if (!action && request.method === "GET") {
      const status = phone.status === "open" && phone.expires_at <= nowIso ? "expired" : phone.status;
      return json({ ok: true, status, label: phone.label, signKey: phone.sign_key, sealKey: phone.seal_key, mac: phone.join_mac, expiresAt: phone.expires_at });
    }
    if (action === "confirm" && request.method === "POST") {
      const changed = await database.prepare("UPDATE passbook_phones SET status = 'linked', linked_at = ?2 WHERE id = ?1 AND status = 'joined'").bind(id, nowIso).run();
      return Number(changed.meta?.changes ?? 0) ? json({ ok: true, status: "linked" }) : json({ ok: false, error: "That phone has not joined, or was already confirmed." }, 409);
    }
    if (!action && request.method === "DELETE") {
      await database.batch([
        database.prepare("UPDATE passbook_phones SET status = 'revoked', sign_key = NULL, seal_key = NULL, join_mac = NULL WHERE id = ?1").bind(id),
        database.prepare("DELETE FROM passbook_approvals WHERE phone_id = ?1").bind(id),
      ]);
      return json({ ok: true });
    }
    return notHere;
  }

  if (path === "/api/passbook/approvals" && request.method === "POST") {
    const no = await refused();
    if (no) return no;
    const phoneId = String(body.phone ?? "");
    const phone = ID_SHAPE.test(phoneId) ? await database.prepare("SELECT * FROM passbook_phones WHERE id = ?1 LIMIT 1").bind(phoneId).first<PhoneRow>() : null;
    if (!phone || phone.owner_did !== signer || phone.status !== "linked") return json({ ok: false, error: "That phone is not linked to this PassBook." }, 404);
    const sealed = typeof body.sealed === "string" ? body.sealed : "";
    if (!sealed.startsWith("pbps1.") || sealed.length > MAX_SEALED) return json({ ok: false, error: "That request could not be read." }, 400);
    const seconds = Number(body.seconds);
    const lasts = Math.min(MAX_ASK_MS, Math.max(30_000, Number.isFinite(seconds) ? seconds * 1000 : 120_000));
    await database.prepare("DELETE FROM passbook_approvals WHERE owner_did = ?1 AND expires_at <= ?2").bind(signer, new Date(now.getTime() - 24 * 3600 * 1000).toISOString()).run();
    const waiting = await database.prepare("SELECT COUNT(*) AS n FROM passbook_approvals WHERE owner_did = ?1 AND status = 'waiting' AND expires_at > ?2").bind(signer, nowIso).first<{ n: number }>();
    if (Number(waiting?.n ?? 0) >= MAX_WAITING) return json({ ok: false, error: "Too many requests are already waiting on a phone." }, 429);
    const id = randomId();
    const expiresAt = new Date(now.getTime() + lasts).toISOString();
    await database.prepare(
      "INSERT INTO passbook_approvals (id, phone_id, owner_did, sealed, status, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, 'waiting', ?5, ?6)",
    ).bind(id, phoneId, signer, sealed, nowIso, expiresAt).run();
    return json({ ok: true, approvalId: id, expiresAt });
  }

  const approvalMatch = path.match(/^\/api\/passbook\/approvals\/([A-Za-z0-9_-]+)$/);
  if (approvalMatch) {
    const id = approvalMatch[1];
    const row = ID_SHAPE.test(id) ? await database.prepare("SELECT * FROM passbook_approvals WHERE id = ?1 LIMIT 1").bind(id).first<ApprovalRow>() : null;
    if (!row || row.owner_did !== signer) return json({ ok: false, error: "That request was not found." }, 404);
    if (request.method === "GET") {
      const status = row.status === "waiting" && row.expires_at <= nowIso ? "expired" : row.status;
      return json({ ok: true, status, answer: row.status === "decided" ? row.decision : null, expiresAt: row.expires_at });
    }
    if (request.method === "DELETE") {
      await database.prepare("DELETE FROM passbook_approvals WHERE id = ?1").bind(id).run();
      return json({ ok: true });
    }
  }
  return notHere;
}
