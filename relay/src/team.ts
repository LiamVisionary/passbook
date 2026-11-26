// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// One record of who used a shared key, kept where the owner can read it and the relay cannot.
//
// A member is another person's PassBook that an owner lends named keys to (an invite of kind
// "member", machine-relay.ts). The owner's own Activity record stops at the owner's machine: once a
// key is on a member's machine, nothing told the owner it was used. These routes carry that back.
//
//   POST /api/passbook/team/events          a member reports uses of the owner's keys
//   GET  /api/passbook/team/events?after=   the owner reads what members reported
//
// Each event is sealed by the member's PassBook to the owner's key before it leaves (the same
// X25519 sealing an envelope uses), so the relay stores who reported and when, and nothing about
// which key, which app or why. Only a member the owner still shares with may report, and only to
// that owner.
//
// What this is: a record members' machines volunteer. A member who has changed their PassBook can
// leave things out. It tells an owner what honest machines did, which is what an audit of people
// you chose to share with is for. It is not a control, and removing a member still means rotating
// what they held (`passbook team remove` lists it).

import { json, readSigned, randomId, DID_SHAPE } from "./proof.ts";
import type { RelayOptions } from "./plan.ts";

const MAX_EVENT = 8_192;
const MAX_BATCH = 50;
const KEPT_DAYS = 90;
const KEPT_PER_OWNER = 5_000;
const PAGE = 200;

export async function handleTeamRoute(request: Request, database: D1Database, now = new Date(), _options?: RelayOptions): Promise<Response | null> {
  const read = await readSigned(request, ["/api/passbook/team"], MAX_EVENT * MAX_BATCH + 4096, now);
  if (!read || read instanceof Response) return read;
  const { signer, path, url, body, nowIso } = read;

  if (path === "/api/passbook/team/events" && request.method === "POST") {
    const owner = String(body.owner ?? "");
    const events = Array.isArray(body.events) ? body.events : [];
    if (!DID_SHAPE.test(owner) || !events.length || events.length > MAX_BATCH
        || events.some(event => typeof event !== "string" || !event.startsWith("pbts1.") || event.length > MAX_EVENT)) {
      return json({ ok: false, error: "That report could not be read." }, 400);
    }
    const member = await database.prepare(
      "SELECT 1 AS yes FROM passbook_machine_mailboxes WHERE device_did = ?1 AND issuer_did = ?2 AND kind = 'member' AND revoked_at IS NULL LIMIT 1",
    ).bind(signer, owner).first<{ yes: number }>();
    if (!member) return json({ ok: false, code: "not_member", error: "This PassBook is not shared with by that one." }, 403);
    await database.batch((events as string[]).map(sealed => database.prepare(
      "INSERT INTO passbook_team_events (id, owner_did, member_did, sealed, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
    ).bind(randomId(), owner, signer, sealed, nowIso)));
    // Kept for a stated time and a stated number, so the record cannot grow without end.
    await database.prepare("DELETE FROM passbook_team_events WHERE owner_did = ?1 AND created_at < ?2")
      .bind(owner, new Date(now.getTime() - KEPT_DAYS * 86_400_000).toISOString()).run();
    await database.prepare(
      `DELETE FROM passbook_team_events WHERE owner_did = ?1 AND id NOT IN
        (SELECT id FROM passbook_team_events WHERE owner_did = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2)`,
    ).bind(owner, KEPT_PER_OWNER).run();
    return json({ ok: true, stored: events.length, keptDays: KEPT_DAYS });
  }

  if (path === "/api/passbook/team/events" && request.method === "GET") {
    // The place to carry on from is the last event read: its time and its id, because one report
    // stores many events at the same instant and a time alone would skip the rest of them.
    const after = String(url.searchParams.get("after") || "");
    const afterId = String(url.searchParams.get("afterId") || "");
    const from = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(after) ? after : "";
    const rows = await database.prepare(
      `SELECT id, member_did, sealed, created_at FROM passbook_team_events
        WHERE owner_did = ?1 AND (created_at > ?2 OR (created_at = ?2 AND id > ?3)) ORDER BY created_at, id LIMIT ?4`,
    ).bind(signer, from, /^[A-Za-z0-9_-]{22}$/.test(afterId) ? afterId : "", PAGE + 1)
      .all<{ id: string; member_did: string; sealed: string; created_at: string }>();
    const found = rows.results ?? [];
    return json({ ok: true, more: found.length > PAGE, keptDays: KEPT_DAYS,
                  events: found.slice(0, PAGE).map(r => ({ id: r.id, member: r.member_did, at: r.created_at, sealed: r.sealed })) });
  }
  return json({ ok: false, error: "Not found." }, 404);
}
