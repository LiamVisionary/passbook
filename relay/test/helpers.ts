// SPDX-License-Identifier: Apache-2.0
// What the relay's tests share: a D1 stand-in over node:sqlite, a machine with real keys, and a
// caller that signs requests the way PassBook does.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

class Statement {
  private values: unknown[] = [];
  private readonly db: DatabaseSync;
  private readonly sql: string;
  constructor(db: DatabaseSync, sql: string) { this.db = db; this.sql = sql; }
  bind(...values: unknown[]) { this.values = values; return this; }
  async first<T>() { return (this.db.prepare(this.sql).get(...(this.values as never[])) as T | undefined) ?? null; }
  async all<T>() { return { results: this.db.prepare(this.sql).all(...(this.values as never[])) as T[] }; }
  async run() { return this.execute(); }
  execute() { const r = this.db.prepare(this.sql).run(...(this.values as never[])); return { success: true, meta: { changes: Number(r.changes) } }; }
}

export class Database {
  readonly db = new DatabaseSync(":memory:");
  prepare(sql: string) { return new Statement(this.db, sql); }
  async batch(statements: Statement[]) {
    this.db.exec("BEGIN");
    try { const out = statements.map(s => s.execute()); this.db.exec("COMMIT"); return out; } catch (e) { this.db.exec("ROLLBACK"); throw e; }
  }
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (raw: Uint8Array) => { let n = BigInt("0x" + Buffer.from(raw).toString("hex")); let out = ""; while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; } return out; };
export const b64 = (raw: Uint8Array | string) => Buffer.from(raw).toString("base64url");

export function machine() {
  const pair = generateKeyPairSync("ed25519");
  const signPublic = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const seal = generateKeyPairSync("x25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const did = "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), signPublic]));
  const token = (expMs = Date.now() + 9 * 60_000) => "passbook-pair:v1:" + b64(JSON.stringify({ v: 1, did, seal: b64(seal), exp: new Date(expMs).toISOString() }));
  const sign = (message: string) => b64(edSign(null, Buffer.from(message), pair.privateKey));
  return { did, key: pair.privateKey, signPublic, token, sign };
}
export type Machine = ReturnType<typeof machine>;

export const envelope = (iss: string, aud: string, ct = "sealed") =>
  "passbook-env:v1:" + b64(JSON.stringify({ v: 1, grant: { kind: "passbook-grant", iss, aud }, ct }));

export function proof(signer: { did: string; key: KeyObject }, method: string, path: string, body: string, at = Math.floor(Date.now() / 1000)) {
  const message = `passbook-relay:v1\n${method}\n${path}\n${at}\n${createHash("sha256").update(body).digest("hex")}`;
  return `${signer.did} ${at} ${b64(edSign(null, Buffer.from(message), signer.key))}`;
}

export const MAC = b64(Buffer.alloc(32, 7));

type Handler = (request: Request, database: D1Database) => Promise<Response | null>;

export function fixture(handler: Handler) {
  const database = new Database();
  database.db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  const call = async (method: string, path: string, { as, body, header }: { as?: Machine; body?: unknown; header?: string } = {}) => {
    const text = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (header !== undefined) headers["x-passbook-proof"] = header;
    else if (as) headers["x-passbook-proof"] = proof(as, method, path, text);
    const response = await handler(new Request(`https://relay.test${path}`, { method, headers, body: body === undefined ? undefined : text }),
      database as unknown as D1Database);
    assert.ok(response, `${method} ${path} is a relay route`);
    return { status: response.status, body: await response.json() as Record<string, any> };
  };
  return { database, call };
}

/** Link `bot` to `owner` through an invite, the way the first three calls of a join go. */
export async function link(call: ReturnType<typeof fixture>["call"], owner: Machine, bot: Machine, label = "bot") {
  const id = (await call("POST", "/api/passbook/machine-invites", { as: owner, body: {} })).body.inviteId;
  await call("POST", `/api/passbook/machine-invites/${id}/join`, { as: bot, body: { pairingToken: bot.token(), proof: MAC, label } });
  return call("POST", `/api/passbook/machine-invites/${id}/answer`, { as: owner, body: { envelope: envelope(owner.did, bot.did) } });
}
