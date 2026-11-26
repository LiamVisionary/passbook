// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";

import { handleMachineRelayRoute } from "../src/machine-relay.ts";
import { handleTeamRoute } from "../src/team.ts";
import { handlePlanRoute } from "../src/plan-route.ts";
import { handleRelay } from "../src/index.ts";
import { OPEN_PLAN, type RelayOptions } from "../src/plan.ts";
import { MAC, envelope, fixture as base, machine, type Machine } from "./helpers.ts";

const fixture = (options?: RelayOptions) => base((request, database) => handleRelay(request, database, options));

async function share(call: ReturnType<typeof fixture>["call"], owner: Machine, member: Machine, label = "Ada") {
  const opened = await call("POST", "/api/passbook/machine-invites", { as: owner, body: { kind: "member" } });
  if (opened.status !== 200) return opened;
  const id = opened.body.inviteId;
  await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: member, body: { pairingToken: member.token(), proof: MAC, label } });
  return call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, member.did) } });
}

test("people are counted against seats, computers against machines, and neither against the other", async () => {
  const { call } = fixture({ planFor: () => ({ ...OPEN_PLAN, plan: "teams", machines: 1, seats: 2, more: "Add a seat for another." }) });
  const owner = machine(), ada = machine(), bo = machine(), cy = machine(), laptop = machine(), server = machine();
  assert.equal((await share(call, owner, ada, "Ada")).status, 200);
  assert.equal((await share(call, owner, bo, "Bo")).status, 200);
  const third = await share(call, owner, cy, "Cy");
  assert.deepEqual([third.status, third.body.code, third.body.limit], [409, "seat_limit", 2]);
  assert.match(third.body.error, /already shares with 2 people.*Add a seat for another\./);

  // Two members do not use up the one computer, and the one computer does not use up a seat.
  const link = async (bot: Machine) => {
    const id = (await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).body.inviteId;
    await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: bot, body: { pairingToken: bot.token(), proof: MAC } });
    return call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, bot.did) } });
  };
  assert.equal((await link(laptop)).status, 200);
  assert.equal((await link(server)).body.code, "machine_limit");

  const listed = (await call("GET", "/api/passbook/machines", { as: owner })).body.machines;
  assert.deepEqual(listed.map((m: any) => [m.label, m.kind]).sort(), [["A computer", "machine"], ["Ada", "member"], ["Bo", "member"]]);

  const plan = await call("GET", "/api/passbook/plan", { as: owner });
  assert.deepEqual([plan.body.plan, plan.body.limits.seats, plan.body.used.members, plan.body.used.machines], ["teams", 2, 2, 1]);
});

test("a plan with no seats refuses a member invite before anyone is sent a line", async () => {
  const { call } = fixture({ planFor: () => ({ ...OPEN_PLAN, plan: "sync", seats: 0, more: "PassBook Teams adds people." }) });
  const refused = await call("POST", "/api/passbook/machine-invites", { as: machine(), body: { kind: "member" } });
  assert.deepEqual([refused.status, refused.body.code], [409, "seat_limit"]);
  assert.match(refused.body.error, /another person is not included.*PassBook Teams adds people\./);
});

test("a member reports to the owner who shares with it, and only that owner reads it", async () => {
  const { call } = fixture();
  const owner = machine(), ada = machine(), outsider = machine(), laptop = machine();
  await share(call, owner, ada);
  const events = ["pbts1.one", "pbts1.two"];
  assert.equal((await call("POST", "/api/passbook/team/events", { as: outsider, body: { owner: owner.did, events } })).status, 403, "not a member");
  assert.equal((await call("POST", "/api/passbook/team/events", { as: ada, body: { owner: outsider.did, events } })).status, 403, "not that owner's member");
  assert.equal((await call("POST", "/api/passbook/team/events", { as: ada, body: { owner: owner.did, events: ["plain text"] } })).status, 400);
  const stored = await call("POST", "/api/passbook/team/events", { as: ada, body: { owner: owner.did, events } });
  assert.deepEqual([stored.status, stored.body.stored], [200, 2]);

  // The owner's own computer is linked, not shared with: it reports nothing here.
  const id = (await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).body.inviteId;
  await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: laptop, body: { pairingToken: laptop.token(), proof: MAC } });
  await call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, laptop.did) } });
  assert.equal((await call("POST", "/api/passbook/team/events", { as: laptop, body: { owner: owner.did, events } })).status, 403);

  const read = await call("GET", "/api/passbook/team/events", { as: owner });
  assert.deepEqual(read.body.events.map((e: any) => [e.member, e.sealed]).sort(), [[ada.did, "pbts1.one"], [ada.did, "pbts1.two"]]);
  assert.deepEqual((await call("GET", "/api/passbook/team/events", { as: ada })).body.events, [], "a member reads nobody's record");

  // Carrying on from the last event read skips nothing stored at the same instant.
  const first = read.body.events[0];
  const rest = await call("GET", `/api/passbook/team/events?after=${first.at}&afterId=${first.id}`, { as: owner });
  assert.deepEqual(rest.body.events.map((e: any) => e.id), [read.body.events[1].id]);

  // Removed: nothing more is accepted from that member.
  assert.equal((await call("DELETE", `/api/passbook/machines/${ada.did}`, { as: owner })).status, 200);
  assert.equal((await call("POST", "/api/passbook/team/events", { as: ada, body: { owner: owner.did, events } })).status, 403);
});

test("every route is reachable through the one entry point, and nothing else is", async () => {
  const { call } = fixture();
  const owner = machine();
  assert.equal((await call("GET", "/api/passbook/plan", { as: owner })).body.plan, "self-hosted");
  assert.equal((await call("GET", "/api/passbook/backups", { as: owner })).status, 200);
  assert.equal((await call("GET", "/api/passbook/phones", { as: owner })).status, 200);
  assert.equal((await call("GET", "/api/passbook/machines", { as: owner })).status, 200);
  assert.equal((await call("GET", "/api/passbook/team/events", { as: owner })).status, 200);
  const billing = await call("POST", "/api/passbook/plan/checkout", { as: owner, body: { plan: "sync" } });
  assert.deepEqual([billing.status, billing.body.code], [404, "no_billing"], "a relay you run sells nothing");
  const page = await handleRelay(new Request("https://relay.test/phone"), {} as D1Database);
  assert.match(page!.headers.get("content-type") || "", /text\/html/);
  assert.equal(await handleRelay(new Request("https://relay.test/somewhere-else"), {} as D1Database), null);
});
