// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// What every relay route shares: reading a request once, and checking who signed it.
//
// A PassBook machine is named by a `did:key` that is its Ed25519 public key, so a signature is all
// the identity a route needs. Every request carries
//
//   X-PassBook-Proof: <did> <unix seconds> <signature>
//
// an Ed25519 signature by that did over
//
//   passbook-relay:v1\n<METHOD>\n<path and query>\n<seconds>\n<sha256 hex of the body>
//
// so a proof cannot be replayed against another route, another body, or five minutes later.

export const PROOF_SKEW_S = 300;
export const DID_SHAPE = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/;
export const DID_IN_PATH = "did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}";
export const ID_SHAPE = /^[A-Za-z0-9_-]{22}$/;
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

export function unb64(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

export function b64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** 22 characters of base64url: 128 random bits. */
export function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return b64(bytes);
}

function b58decode(text: string): Uint8Array<ArrayBuffer> | null {
  let value = 0n;
  for (const character of text) {
    const digit = B58.indexOf(character);
    if (digit < 0) return null;
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) { bytes.unshift(Number(value & 0xffn)); value >>= 8n; }
  for (const character of text) { if (character !== "1") break; bytes.unshift(0); }
  return Uint8Array.from(bytes);
}

/** The Ed25519 public key a `did:key` names, or null for anything else. */
export function publicKeyOf(did: string): Uint8Array<ArrayBuffer> | null {
  if (!DID_SHAPE.test(did)) return null;
  const raw = b58decode(did.slice("did:key:z".length));
  if (!raw || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) return null;
  return raw.slice(2);
}

export async function sha256hex(text: string) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** True when `signature` (base64url) is `did`'s Ed25519 signature over `message`. */
export async function signedBy(did: string, message: string, signature: string): Promise<boolean> {
  const key = publicKeyOf(did);
  if (!key) return false;
  try {
    const imported = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, imported, unb64(signature), new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

/** Which machine signed this request, or null when the proof is missing, stale or wrong. */
export async function provenDid(request: Request, path: string, body: string, now = Date.now()): Promise<string | null> {
  const parts = (request.headers.get("x-passbook-proof") || "").trim().split(/\s+/);
  if (parts.length !== 3) return null;
  const [did, seconds, signature] = parts;
  const at = Number(seconds);
  if (!/^\d{9,11}$/.test(seconds) || Math.abs(now / 1000 - at) > PROOF_SKEW_S) return null;
  const message = `passbook-relay:v1\n${request.method}\n${path}\n${seconds}\n${await sha256hex(body)}`;
  return await signedBy(did, message, signature) ? did : null;
}

/** A short name a person typed, with control characters removed. */
export function label(value: unknown, fallback: string, max = 60) {
  return typeof value === "string" && value.trim() ? value.trim().replace(/[\u0000-\u001f]/g, "").slice(0, max) : fallback;
}

export type Signed = { signer: string; path: string; url: URL; raw: string; body: Record<string, unknown>; nowIso: string; now: Date };

/**
 * Read a request once and check its proof. Returns the pieces a route needs, a Response when the
 * request is refused, or null when the path is not under any of `prefixes` (not this handler's).
 */
export async function readSigned(request: Request, prefixes: string[], maxBody: number, now: Date): Promise<Signed | Response | null> {
  const url = new URL(request.url);
  let path: string;
  try { path = decodeURIComponent(url.pathname).replace(/\/+$/, ""); } catch { return null; }
  if (!prefixes.some(prefix => path === prefix || path.startsWith(prefix + "/"))) return null;
  const raw = request.method === "GET" || request.method === "DELETE" ? "" : await request.text();
  if (raw.length > maxBody) return json({ ok: false, error: "That request is too large." }, 413);
  let body: Record<string, unknown> = {};
  if (raw) {
    try { body = JSON.parse(raw); } catch { return json({ ok: false, error: "That request could not be read." }, 400); }
    if (!body || typeof body !== "object" || Array.isArray(body)) return json({ ok: false, error: "That request could not be read." }, 400);
  }
  const signer = await provenDid(request, url.pathname + url.search, raw, now.getTime());
  if (!signer) return json({ ok: false, error: "This request is not signed by a PassBook machine." }, 401);
  return { signer, path, url, raw, body, nowIso: now.toISOString(), now };
}
