// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// Keeping an encrypted backup of a store here, and getting it back on a machine that has nothing.
//
// What arrives is the text `passbook export` writes: a `passbook-export:v1` envelope, scrypt over a
// passphrase the owner chose and AES-256-GCM over the body. The relay never sees the passphrase,
// so it holds ciphertext it cannot open. It is still worth guessing at, which is why the passphrase
// rule (eight characters at least) is PassBook's and not this file's to weaken.
//
//   POST   /api/passbook/backups               the owner stores one          (needs plan.backup)
//   GET    /api/passbook/backups               the owner lists its own
//   GET    /api/passbook/backups/:id           the owner reads one back
//   DELETE /api/passbook/backups/:id           the owner removes one
//   POST   /api/passbook/backups/:id/recover   any machine, with the recovery secret
//
// The last route is the point of a backup: the machine that made it may be gone, and its key with
// it. So when PassBook stores a backup it also makes a recovery code, `pbb1.<id>.<secret>`, shows
// it once, and sends only the secret's SHA-256 here. A new machine presents the secret and is
// given the ciphertext, which it still cannot open without the passphrase. Two things a person
// keeps, in two places: the code and the passphrase.
//
// A plan is asked for only when a backup is written. Reading, recovering and deleting what is
// already here never depend on it, so a lapsed payment cannot hold a backup hostage.

import { json, readSigned, randomId, label, sha256hex, ID_SHAPE } from "./proof.ts";
import { planOf, notIncluded, type RelayOptions } from "./plan.ts";

export const BACKUP_PREFIX = "passbook-export:v1\n";
export const MAX_BACKUP = 1_000_000;
const KEPT_PER_OWNER = 5;
const MISSES_BEFORE_WAIT = 5;
const WAIT_MS = 15 * 60 * 1000;
const HEX64 = /^[0-9a-f]{64}$/;

type BackupRow = {
  id: string; owner_did: string; label: string; blob: string; bytes: number; digest: string;
  recovery_hash: string; misses: number; missed_at: string | null; created_at: string;
};

/** Equal-time comparison of two hex digests of the same length. */
function sameDigest(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const described = (row: BackupRow) => ({ id: row.id, label: row.label, bytes: row.bytes, digest: row.digest, at: row.created_at });

export async function handleBackupRoute(request: Request, database: D1Database, now = new Date(), options?: RelayOptions): Promise<Response | null> {
  const read = await readSigned(request, ["/api/passbook/backups"], MAX_BACKUP + 4096, now);
  if (!read || read instanceof Response) return read;
  const { signer, path, body, nowIso } = read;

  if (path === "/api/passbook/backups" && request.method === "POST") {
    const plan = await planOf(signer, options);
    if (!plan.backup) return json({ ok: false, code: "not_included", plan: plan.plan,
                                    error: notIncluded("Keeping a backup here is not included for this PassBook.", plan) }, 403);
    const blob = typeof body.blob === "string" ? body.blob : "";
    if (!blob.startsWith(BACKUP_PREFIX) || blob.length > MAX_BACKUP) {
      return json({ ok: false, error: blob.length > MAX_BACKUP ? "That backup is too large to keep here." : "That is not an encrypted PassBook export." }, 400);
    }
    const recovery = String(body.recovery ?? "");
    if (!HEX64.test(recovery)) return json({ ok: false, error: "That backup came without a recovery code." }, 400);
    const id = randomId();
    await database.prepare(
      `INSERT INTO passbook_backups (id, owner_did, label, blob, bytes, digest, recovery_hash, misses, missed_at, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, ?8)`,
    ).bind(id, signer, label(body.label, "PassBook"), blob, blob.length, await sha256hex(blob), recovery, nowIso).run();
    // The newest few are kept. An older one goes when a newer one arrives, never before.
    await database.prepare(
      `DELETE FROM passbook_backups WHERE owner_did = ?1 AND id NOT IN
        (SELECT id FROM passbook_backups WHERE owner_did = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2)`,
    ).bind(signer, KEPT_PER_OWNER).run();
    return json({ ok: true, id, at: nowIso, bytes: blob.length, kept: KEPT_PER_OWNER });
  }

  if (path === "/api/passbook/backups" && request.method === "GET") {
    const rows = await database.prepare("SELECT * FROM passbook_backups WHERE owner_did = ?1 ORDER BY created_at DESC, id DESC").bind(signer).all<BackupRow>();
    return json({ ok: true, backups: (rows.results ?? []).map(described) });
  }

  const match = path.match(/^\/api\/passbook\/backups\/([A-Za-z0-9_-]+)(?:\/(recover))?$/);
  if (!match) return json({ ok: false, error: "Not found." }, 404);
  const [, id, action] = match;
  const missing = json({ ok: false, error: "That backup was not found." }, 404);
  if (!ID_SHAPE.test(id)) return missing;
  const row = await database.prepare("SELECT * FROM passbook_backups WHERE id = ?1 LIMIT 1").bind(id).first<BackupRow>();

  if (action === "recover" && request.method === "POST") {
    if (!row) return missing;
    // A wrong secret is counted, and after a few the backup stops answering for a while. The secret
    // is 256 random bits, so this is not what keeps it safe; it is what keeps a guesser from being
    // answered at the speed they ask.
    const waiting = row.misses >= MISSES_BEFORE_WAIT && row.missed_at && Date.parse(row.missed_at) + WAIT_MS > now.getTime();
    if (waiting) return json({ ok: false, error: "That recovery code was wrong too many times. Try again in fifteen minutes." }, 429);
    const offered = await sha256hex(String(body.secret ?? ""));
    if (!sameDigest(offered, row.recovery_hash)) {
      await database.prepare("UPDATE passbook_backups SET misses = CASE WHEN misses >= ?3 THEN 1 ELSE misses + 1 END, missed_at = ?2 WHERE id = ?1")
        .bind(id, nowIso, MISSES_BEFORE_WAIT).run();
      return missing;
    }
    if (row.misses) await database.prepare("UPDATE passbook_backups SET misses = 0, missed_at = NULL WHERE id = ?1").bind(id).run();
    return json({ ok: true, ...described(row), blob: row.blob });
  }

  // Everything else about one backup is its owner's alone, and a stranger learns nothing from asking.
  if (!row || row.owner_did !== signer) return missing;
  if (!action && request.method === "GET") return json({ ok: true, ...described(row), blob: row.blob });
  if (!action && request.method === "DELETE") {
    await database.prepare("DELETE FROM passbook_backups WHERE id = ?1 AND owner_did = ?2").bind(id, signer).run();
    return json({ ok: true });
  }
  return json({ ok: false, error: "Not found." }, 404);
}
