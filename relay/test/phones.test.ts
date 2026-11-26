// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash, createHmac, webcrypto } from "node:crypto";
import test from "node:test";

import { handlePhoneRoute, handlePhoneSideRoute } from "../src/phones.ts";
import { phonePage } from "../src/phone-page.ts";
import { OPEN_PLAN, type RelayOptions } from "../src/plan.ts";
import { Database, b64, fixture as base, machine } from "./helpers.ts";

const subtle = webcrypto.subtle;
const fixture = (options?: RelayOptions) => base(async (request, database) =>
  (await handlePhoneSideRoute(request, database, new Date())) ?? handlePhoneRoute(request, database, new Date(), options));

/** A phone as the page makes one: an ECDSA pair to sign with, an ECDH pair to be encrypted to. */
async function phone() {
  const sign = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const seal = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const signKey = b64(new Uint8Array(await subtle.exportKey("raw", sign.publicKey)));
  const sealKey = b64(new Uint8Array(await subtle.exportKey("raw", seal.publicKey)));
  const header = async (id: string, method: string, path: string, body = "", at = Math.floor(Date.now() / 1000)) => {
    const message = `passbook-phone:v1\n${method}\n${path}\n${at}\n${createHash("sha256").update(body).digest("hex")}`;
    return `${id} ${at} ${b64(new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, sign.privateKey, Buffer.from(message))))}`;
  };
  return { signKey, sealKey, header };
}

/** What a phone route is called with: no machine proof, the phone's own header. */
function phoneCaller(database: Database) {
  return async (method: string, path: string, { header, body }: { header?: string; body?: unknown } = {}) => {
    const text = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (header) headers["x-passbook-phone"] = header;
    const response = await handlePhoneSideRoute(new Request(`https://relay.test${path}`, { method, headers, body: body === undefined ? undefined : text }),
      database as unknown as D1Database, new Date());
    assert.ok(response, `${method} ${path} is a phone route`);
    return { status: response.status, body: await response.json() as Record<string, any>, text };
  };
}

async function linked(options?: RelayOptions) {
  const { call, database } = fixture(options);
  const owner = machine(), mobile = await phone(), asPhone = phoneCaller(database);
  const id = (await call("POST", "/api/passbook/phones", { as: owner, body: { label: "My phone" } })).body.phoneId;
  const secret = Buffer.alloc(32, 9);
  const mac = createHmac("sha256", secret).update(`passbook-phone-join:v1\n${id}\n${mobile.signKey}\n${mobile.sealKey}`).digest("base64url");
  await asPhone("POST", `/api/passbook/phones/${id}/join`, { body: { signKey: mobile.signKey, sealKey: mobile.sealKey, mac, label: "iPhone" } });
  await call("POST", `/api/passbook/phones/${id}/confirm`, { as: owner });
  return { call, database, owner, mobile, asPhone, id, mac };
}

test("a phone joins with its keys, and is sent nothing until PassBook has confirmed it", async () => {
  const { call, database } = fixture();
  const owner = machine(), stranger = machine(), mobile = await phone(), asPhone = phoneCaller(database);
  const opened = await call("POST", "/api/passbook/phones", { as: owner, body: { label: "My phone" } });
  assert.equal(opened.status, 200);
  const id = opened.body.phoneId;

  assert.equal((await asPhone("POST", `/api/passbook/phones/${id}/join`, { body: { signKey: "short", sealKey: mobile.sealKey, mac: b64(Buffer.alloc(32)) } })).status, 400);
  const mac = b64(Buffer.alloc(32, 3));
  assert.equal((await asPhone("POST", `/api/passbook/phones/${id}/join`, { body: { signKey: mobile.signKey, sealKey: mobile.sealKey, mac, label: "iPhone" } })).status, 200);
  assert.equal((await asPhone("POST", `/api/passbook/phones/${id}/join`, { body: { signKey: mobile.signKey, sealKey: mobile.sealKey, mac } })).status, 404, "a link is joined once");

  // PassBook reads what joined: the keys and the HMAC it will check. Only the owner may.
  assert.equal((await call("GET", `/api/passbook/phones/${id}`, { as: stranger })).status, 404);
  const seen = await call("GET", `/api/passbook/phones/${id}`, { as: owner });
  assert.deepEqual([seen.body.status, seen.body.signKey, seen.body.sealKey, seen.body.mac, seen.body.label], ["joined", mobile.signKey, mobile.sealKey, mac, "iPhone"]);

  // Before the confirm, an ask is refused and the phone is told only that it is waiting.
  assert.equal((await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.a.b.c" } })).status, 404);
  const path = `/api/passbook/phones/${id}/requests`;
  assert.deepEqual((await asPhone("GET", path, { header: await mobile.header(id, "GET", path) })).body, { ok: true, status: "joined", requests: [] });

  assert.equal((await call("POST", `/api/passbook/phones/${id}/confirm`, { as: stranger })).status, 404);
  assert.equal((await call("POST", `/api/passbook/phones/${id}/confirm`, { as: owner })).status, 200);
  assert.deepEqual((await call("GET", "/api/passbook/phones", { as: owner })).body.phones.map((p: any) => [p.id, p.label]), [[id, "iPhone"]]);
});

test("a question reaches only its phone, and the answer comes back exactly as the phone sent it", async () => {
  const { call, owner, mobile, asPhone, id } = await linked();
  const other = await phone(), stranger = machine();
  const asked = await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.eph.nonce.box", seconds: 120 } });
  assert.equal(asked.status, 200);
  const approval = asked.body.approvalId;

  const path = `/api/passbook/phones/${id}/requests`;
  assert.equal((await asPhone("GET", path)).status, 401, "an unsigned read is refused");
  assert.equal((await asPhone("GET", path, { header: await other.header(id, "GET", path) })).status, 401, "another phone's key is refused");
  assert.equal((await asPhone("GET", path, { header: await mobile.header(id, "GET", path, "", Math.floor(Date.now() / 1000) - 3600) })).status, 401, "an old signature is refused");
  const waiting = await asPhone("GET", path, { header: await mobile.header(id, "GET", path) });
  assert.deepEqual(waiting.body.requests.map((r: any) => [r.id, r.sealed]), [[approval, "pbps1.eph.nonce.box"]]);

  assert.equal((await call("GET", `/api/passbook/approvals/${approval}`, { as: stranger })).status, 404);
  assert.deepEqual((await call("GET", `/api/passbook/approvals/${approval}`, { as: owner })).body.status, "waiting");

  const answer = JSON.stringify({ v: 1, rid: "r1", decision: "allow", signature: "sig" });
  const body = JSON.stringify({ answer });
  const decide = `/api/passbook/approvals/${approval}/decision`;
  assert.equal((await asPhone("POST", decide, { header: await other.header(id, "POST", decide, body), body: { answer } })).status, 401);
  assert.equal((await asPhone("POST", decide, { header: await mobile.header(id, "POST", decide, JSON.stringify({ answer: "other" })), body: { answer } })).status, 401, "a signature for another body is refused");
  assert.equal((await asPhone("POST", decide, { header: await mobile.header(id, "POST", decide, body), body: { answer } })).status, 200);
  assert.equal((await asPhone("POST", decide, { header: await mobile.header(id, "POST", decide, body), body: { answer } })).status, 404, "answered once");

  const read = await call("GET", `/api/passbook/approvals/${approval}`, { as: owner });
  assert.deepEqual([read.body.status, read.body.answer], ["decided", answer]);
  assert.deepEqual((await asPhone("GET", path, { header: await mobile.header(id, "GET", path) })).body.requests, []);
  assert.equal((await call("DELETE", `/api/passbook/approvals/${approval}`, { as: owner })).status, 200);
});

test("a question expires, and an unlinked phone is told nothing and can answer nothing", async () => {
  const { call, database, owner, mobile, asPhone, id } = await linked();
  const first = (await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.a.b.c" } })).body.approvalId;
  database.db.prepare("UPDATE passbook_approvals SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(first);
  assert.equal((await call("GET", `/api/passbook/approvals/${first}`, { as: owner })).body.status, "expired");
  const decide = `/api/passbook/approvals/${first}/decision`, body = JSON.stringify({ answer: "{}" });
  assert.equal((await asPhone("POST", decide, { header: await mobile.header(id, "POST", decide, body), body: { answer: "{}" } })).status, 404, "too late to answer");

  const second = (await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.a.b.c" } })).body.approvalId;
  assert.equal((await call("DELETE", `/api/passbook/phones/${id}`, { as: owner })).status, 200);
  const path = `/api/passbook/phones/${id}/requests`;
  assert.equal((await asPhone("GET", path, { header: await mobile.header(id, "GET", path) })).status, 401);
  assert.equal((await call("GET", `/api/passbook/approvals/${second}`, { as: owner })).status, 404, "its questions went with it");
  assert.deepEqual((await call("GET", "/api/passbook/phones", { as: owner })).body.phones, []);
  assert.equal((await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.a.b.c" } })).status, 404);
});

test("a plan without phone approvals refuses a new link and a new question", async () => {
  let approvals = true;
  const { call, owner, id } = await linked({ planFor: () => ({ ...OPEN_PLAN, plan: "free", approvals, more: "PassBook Sync includes it." }) });
  approvals = false;
  const link = await call("POST", "/api/passbook/phones", { as: owner, body: {} });
  assert.deepEqual([link.status, link.body.code], [403, "not_included"]);
  const ask = await call("POST", "/api/passbook/approvals", { as: owner, body: { phone: id, sealed: "pbps1.a.b.c" } });
  assert.deepEqual([ask.status, ask.body.code], [403, "not_included"]);
  assert.match(ask.body.error, /PassBook Sync includes it\./);
});

test("the page a phone opens allows only its own script and talks only to its own relay", async () => {
  const page = phonePage();
  const policy = page.headers.get("content-security-policy") || "";
  const nonce = policy.match(/script-src 'nonce-([0-9a-f]+)'/)?.[1];
  assert.ok(nonce, "the script is allowed by nonce, not by 'unsafe-inline'");
  assert.match(policy, /default-src 'none'/);
  assert.match(policy, /connect-src 'self'/);
  assert.match(policy, /frame-ancestors 'none'/);
  const html = await page.text();
  assert.ok(html.includes(`<script nonce="${nonce}">`));
  assert.equal((html.match(/<script/g) || []).length, 1, "one script, inline, nothing fetched from elsewhere");
  assert.ok(!/https?:\/\//.test(html.replace(/http:\/\/www\.w3\.org[^"']*/g, "")), "the page names no other origin");
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.notEqual(phonePage().headers.get("content-security-policy"), policy, "a new nonce each time");
});
