// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";

import { handleMachineRelayRoute, publicKeyOf } from "../src/machine-relay.ts";
import { OPEN_PLAN, type RelayOptions } from "../src/plan.ts";
import { MAC, envelope, fixture as base, link, machine, proof } from "./helpers.ts";

const fixture = (options?: RelayOptions) => base((request, database) => handleMachineRelayRoute(request, database, new Date(), options));

test("a did:key names the Ed25519 key it was made from", () => {
  const one = machine();
  assert.deepEqual(Buffer.from(publicKeyOf(one.did)!), Buffer.from(one.signPublic));
  assert.equal(publicKeyOf("did:key:znot-base58-0OIl"), null);
});

test("a computer joins through an invite and collects an envelope only it can ask for", async () => {
  const { call } = fixture();
  const owner = machine(), bot = machine(), stranger = machine();

  assert.equal((await call("POST", "/api/passbook/machine-invites", { body: { label: "Studio Mac" } })).status, 401, "an unsigned invite is refused");
  const opened = await call("POST", "/api/passbook/machine-invites", { as: owner, body: { label: "Studio Mac" } });
  assert.equal(opened.status, 200);
  const id = opened.body.inviteId;
  assert.match(id, /^[A-Za-z0-9_-]{22}$/);

  // The joining machine signs with the key its pairing token names; a token that is not its own is refused.
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: stranger, body: { pairingToken: bot.token(), proof: MAC, label: "bot" } })).status, 400);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: owner, body: { pairingToken: owner.token(), proof: MAC } })).status, 400, "not your own invite");
  const botToken = bot.token();
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: bot, body: { pairingToken: botToken, proof: MAC, label: "build-bot" } })).status, 200);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: stranger, body: { pairingToken: stranger.token(), proof: MAC } })).status, 404, "an invite is joined once");

  // Only the owner reads who joined.
  assert.equal((await call("GET", `/api/passbook/machine-invites/${id}`, { as: bot })).status, 404);
  const seen = await call("GET", `/api/passbook/machine-invites/${id}`, { as: owner });
  assert.equal(seen.body.status, "joined");
  assert.equal(seen.body.label, "build-bot");
  assert.equal(seen.body.proof, MAC);
  assert.equal(seen.body.pairingToken, botToken);

  // The answer must come from the owner, be addressed to the bot, and be signed as the owner.
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: stranger, body: { envelope: envelope(stranger.did, bot.did) } })).status, 404);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, stranger.did) } })).status, 400);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(stranger.did, bot.did) } })).status, 400);
  const sealed = envelope(owner.did, bot.did);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: sealed } })).status, 200);

  assert.equal((await call("GET", `/api/passbook/machine-invites/${id}/result`, { as: stranger })).status, 404);
  const result = await call("GET", `/api/passbook/machine-invites/${id}/result`, { as: bot });
  assert.deepEqual([result.body.status, result.body.envelope], ["answered", sealed]);
});

test("the owner keeps a linked computer current, and either end can unlink it", async () => {
  const { call } = fixture();
  const owner = machine(), bot = machine(), stranger = machine();
  const id = (await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).body.inviteId;
  await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: bot, body: { pairingToken: bot.token(), proof: MAC } });
  await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, bot.did) } });

  const box = `/api/passbook/machines/${bot.did}`;
  const fresh = envelope(owner.did, bot.did, "sealed again");
  assert.equal((await call("POST", `${box}/envelope`, { as: stranger, body: { envelope: envelope(stranger.did, bot.did) } })).status, 410, "a stranger has no mailbox to write to");
  assert.equal((await call("POST", `${box}/envelope?issuer=${owner.did}`, { as: bot, body: { envelope: envelope(owner.did, bot.did) } })).status, 403, "the machine cannot write its own keys");
  assert.equal((await call("POST", `${box}/envelope`, { as: owner, body: { envelope: fresh } })).status, 200);

  const mine = `${box}/envelope?issuer=${owner.did}`;
  assert.equal((await call("GET", mine, { as: stranger })).status, 403, "only the machine collects its own mailbox");
  assert.equal((await call("GET", mine, { as: bot })).body.envelope, fresh);

  assert.equal((await call("DELETE", box, { as: owner })).status, 200);
  assert.deepEqual((await call("GET", mine, { as: bot })).body, { ok: true, unlinked: true, envelope: null });
  const after = await call("POST", `${box}/envelope`, { as: owner, body: { envelope: fresh } });
  assert.deepEqual([after.status, after.body.unlinked], [410, true], "an unlinked machine is sent nothing more");
});

test("a proof is bound to its method, path, body and time", async () => {
  const { call } = fixture();
  const owner = machine();
  const body = JSON.stringify({ label: "x" });
  const stale = proof(owner, "POST", "/api/passbook/machine-invites", body, Math.floor(Date.now() / 1000) - 3600);
  assert.equal((await call("POST", "/api/passbook/machine-invites", { header: stale, body: { label: "x" } })).status, 401, "an old proof is refused");
  const otherBody = proof(owner, "POST", "/api/passbook/machine-invites", JSON.stringify({ label: "y" }));
  assert.equal((await call("POST", "/api/passbook/machine-invites", { header: otherBody, body: { label: "x" } })).status, 401, "a proof for another body is refused");
  const otherPath = proof(owner, "POST", "/api/passbook/machine-invites/zzz", body);
  assert.equal((await call("POST", "/api/passbook/machine-invites", { header: otherPath, body: { label: "x" } })).status, 401);
});

test("an invite expires, and a machine cannot hold more than ten open", async () => {
  const { call, database } = fixture();
  const owner = machine(), bot = machine();
  const id = (await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).body.inviteId;
  database.db.prepare("UPDATE passbook_machine_invites SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(id);
  assert.equal((await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: bot, body: { pairingToken: bot.token(), proof: MAC } })).status, 404);
  assert.equal((await call("GET", `/api/passbook/machine-invites/${id}`, { as: owner })).body.status, "expired");
  for (let n = 0; n < 10; n++) assert.equal((await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).status, 200);
  assert.equal((await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).status, 429);
});

test("the operator's plan decides how many computers an owner lends to, and only when one is added", async () => {
  let machines = 2;
  const { call } = fixture({ planFor: () => ({ ...OPEN_PLAN, plan: "free", machines, more: "PassBook Sync carries up to 50." }) });
  const owner = machine(), one = machine(), two = machine(), three = machine();
  assert.equal((await link(call, owner, one)).status, 200);
  assert.equal((await link(call, owner, two)).status, 200);
  const refused = await link(call, owner, three);
  assert.equal(refused.status, 409);
  assert.deepEqual([refused.body.code, refused.body.limit, refused.body.plan], ["machine_limit", 2, "free"]);
  assert.match(refused.body.error, /already lends to 2 computers.*PassBook Sync carries up to 50\./);

  // Linking a machine that is already linked is not adding one.
  assert.equal((await link(call, owner, two)).status, 200);

  // A smaller plan later takes nothing away: both machines are still sent their keys.
  machines = 1;
  assert.equal((await call("POST", `/api/passbook/machines/${one.did}/envelope`, { as: owner, body: { envelope: envelope(owner.did, one.did, "again") } })).status, 200);
  assert.equal((await call("GET", `/api/passbook/machines/${two.did}/envelope?issuer=${owner.did}`, { as: two })).status, 200);

  // Unlinking one frees its place under a plan that has room.
  machines = 2;
  assert.equal((await call("DELETE", `/api/passbook/machines/${one.did}`, { as: owner })).status, 200);
  assert.equal((await link(call, owner, three)).status, 200);
});

test("with no plan passed, a relay serves the open plan", async () => {
  const { call } = fixture();
  const owner = machine();
  for (let n = 0; n < 3; n++) assert.equal((await link(call, owner, machine())).status, 200);
});
