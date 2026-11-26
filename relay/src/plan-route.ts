// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
//   GET /api/passbook/plan     what this relay carries for the PassBook asking, and how much is used
//
// PassBook asks before it offers something, so a person is never shown a button that will be
// refused. A relay with billing answers its own richer version of this route first (who pays, until
// when); this one is the whole answer on a relay without any.

import { json, readSigned } from "./proof.ts";
import { planOf, type RelayOptions, type RelayPlan } from "./plan.ts";

export type Usage = { machines: number; members: number; backups: number; phones: number };

export async function usageOf(ownerDid: string, database: D1Database): Promise<Usage> {
  const count = async (sql: string) => Number((await database.prepare(sql).bind(ownerDid).first<{ n: number }>())?.n ?? 0);
  return {
    machines: await count("SELECT COUNT(*) AS n FROM passbook_machine_mailboxes WHERE issuer_did = ?1 AND kind = 'machine' AND revoked_at IS NULL"),
    members: await count("SELECT COUNT(*) AS n FROM passbook_machine_mailboxes WHERE issuer_did = ?1 AND kind = 'member' AND revoked_at IS NULL"),
    backups: await count("SELECT COUNT(*) AS n FROM passbook_backups WHERE owner_did = ?1"),
    phones: await count("SELECT COUNT(*) AS n FROM passbook_phones WHERE owner_did = ?1 AND status = 'linked'"),
  };
}

export function planAnswer(plan: RelayPlan, used: Usage, extra: Record<string, unknown> = {}) {
  return { ok: true, plan: plan.plan, limits: { machines: plan.machines, seats: plan.seats, backup: plan.backup, approvals: plan.approvals },
           used, more: plan.more ?? null, ...extra };
}

export async function handlePlanRoute(request: Request, database: D1Database, now = new Date(), options?: RelayOptions): Promise<Response | null> {
  const read = await readSigned(request, ["/api/passbook/plan"], 4096, now);
  if (!read || read instanceof Response) return read;
  if (read.path !== "/api/passbook/plan" || request.method !== "GET") return json({ ok: false, code: "no_billing", error: "This relay has no paid plans." }, 404);
  return json(planAnswer(await planOf(read.signer, options), await usageOf(read.signer, database)));
}
