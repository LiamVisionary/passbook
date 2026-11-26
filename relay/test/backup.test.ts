// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { handleBackupRoute, BACKUP_PREFIX, MAX_BACKUP } from "../src/backup.ts";
import { OPEN_PLAN, type RelayOptions } from "../src/plan.ts";
import { fixture as base, machine } from "./helpers.ts";

const fixture = (options?: RelayOptions) => base((request, database) => handleBackupRoute(request, database, new Date(), options));
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const blob = (body = "{}") => BACKUP_PREFIX + body;

test("an owner stores a backup, reads it back, and nobody else can", async () => {
  const { call } = fixture();
  const owner = machine(), stranger = machine();
  const stored = await call("POST", "/api/passbook/backups", { as: owner, body: { blob: blob('{"a":1}'), label: "Studio Mac", recovery: sha("s3cret") } });
  assert.equal(stored.status, 200);
  const id = stored.body.id;

  const listed = await call("GET", "/api/passbook/backups", { as: owner });
  assert.deepEqual(listed.body.backups.map((b: any) => [b.id, b.label, b.bytes]), [[id, "Studio Mac", blob('{"a":1}').length]]);
  assert.ok(!("blob" in listed.body.backups[0]), "a list never carries the ciphertext");
  assert.deepEqual((await call("GET", "/api/passbook/backups", { as: stranger })).body.backups, []);

  assert.equal((await call("GET", `/api/passbook/backups/${id}`, { as: owner })).body.blob, blob('{"a":1}'));
  assert.equal((await call("GET", `/api/passbook/backups/${id}`, { as: stranger })).status, 404);
  assert.equal((await call("DELETE", `/api/passbook/backups/${id}`, { as: stranger })).status, 404);
  assert.equal((await call("DELETE", `/api/passbook/backups/${id}`, { as: owner })).status, 200);
  assert.equal((await call("GET", `/api/passbook/backups/${id}`, { as: owner })).status, 404);
});

test("a machine that has nothing gets the ciphertext back with the recovery secret, and only with it", async () => {
  const { call } = fixture();
  const owner = machine(), fresh = machine();
  const id = (await call("POST", "/api/passbook/backups", { as: owner, body: { blob: blob("x"), recovery: sha("the-secret") } })).body.id;
  assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { as: fresh, body: { secret: "wrong" } })).status, 404);
  const back = await call("POST", `/api/passbook/backups/${id}/recover`, { as: fresh, body: { secret: "the-secret" } });
  assert.deepEqual([back.status, back.body.blob], [200, blob("x")]);
  assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { body: { secret: "the-secret" } })).status, 401, "still a signed request");
});

test("wrong recovery secrets stop being answered for a while, then are again", async () => {
  const { call, database } = fixture();
  const owner = machine(), guesser = machine();
  const id = (await call("POST", "/api/passbook/backups", { as: owner, body: { blob: blob("x"), recovery: sha("right") } })).body.id;
  for (let n = 0; n < 5; n++) assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { as: guesser, body: { secret: `guess-${n}` } })).status, 404);
  assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { as: guesser, body: { secret: "right" } })).status, 429, "even the right one waits");
  database.db.prepare("UPDATE passbook_backups SET missed_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(id);
  assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { as: guesser, body: { secret: "right" } })).status, 200);
  assert.equal(database.db.prepare("SELECT misses FROM passbook_backups WHERE id = ?").get(id)!.misses, 0);
});

test("only an encrypted export of a sane size is kept, and only the newest five", async () => {
  const { call } = fixture();
  const owner = machine();
  const put = (body: unknown) => call("POST", "/api/passbook/backups", { as: owner, body });
  assert.equal((await put({ blob: "OPENAI_API_KEY=sk-plain", recovery: sha("r") })).status, 400, "a plain export is refused");
  assert.equal((await put({ blob: blob("x"), recovery: "not-a-digest" })).status, 400);
  assert.equal((await put({ blob: BACKUP_PREFIX + "x".repeat(MAX_BACKUP), recovery: sha("r") })).status, 400, "too large");
  const ids: string[] = [];
  for (let n = 0; n < 7; n++) ids.push((await put({ blob: blob(String(n)), label: `b${n}`, recovery: sha("r") })).body.id);
  const kept = (await call("GET", "/api/passbook/backups", { as: owner })).body.backups;
  assert.equal(kept.length, 5);
  assert.ok(kept.some((b: any) => b.id === ids[6]), "the newest is always kept");
});

test("a plan without backup refuses a new one and still returns the old", async () => {
  let backup = true;
  const { call } = fixture({ planFor: () => ({ ...OPEN_PLAN, plan: "free", backup, more: "PassBook Sync includes it." }) });
  const owner = machine(), fresh = machine();
  const id = (await call("POST", "/api/passbook/backups", { as: owner, body: { blob: blob("x"), recovery: sha("r") } })).body.id;
  backup = false;
  const refused = await call("POST", "/api/passbook/backups", { as: owner, body: { blob: blob("y"), recovery: sha("r") } });
  assert.deepEqual([refused.status, refused.body.code, refused.body.plan], [403, "not_included", "free"]);
  assert.match(refused.body.error, /not included.*PassBook Sync includes it\./);
  assert.equal((await call("GET", `/api/passbook/backups/${id}`, { as: owner })).status, 200);
  assert.equal((await call("POST", `/api/passbook/backups/${id}/recover`, { as: fresh, body: { secret: "r" } })).status, 200);
  assert.equal((await call("DELETE", `/api/passbook/backups/${id}`, { as: owner })).status, 200);
});
