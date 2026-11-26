// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// A PassBook relay you run yourself: every route, no accounts, no billing.
//
// The relay PassBook uses by default is this same code with one difference: it passes a `planFor`
// that looks up whether the PassBook asking has a paid plan. Here everyone gets OPEN_PLAN, with
// the number of computers set by MAX_MACHINES in wrangler.jsonc.

import { handleMachineRelayRoute } from "./machine-relay.ts";
import { handleBackupRoute } from "./backup.ts";
import { handlePhoneRoute, handlePhoneSideRoute } from "./phones.ts";
import { handleTeamRoute } from "./team.ts";
import { handlePlanRoute } from "./plan-route.ts";
import { phonePage } from "./phone-page.ts";
import { OPEN_PLAN, type RelayOptions } from "./plan.ts";

export type Env = { DB: D1Database; MAX_MACHINES?: string };

/** Every relay route, in the order they must be tried. Shared with the hosted relay. */
export async function handleRelay(request: Request, database: D1Database, options?: RelayOptions, now = new Date()): Promise<Response | null> {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/phone") return phonePage();
  return (await handlePhoneSideRoute(request, database, now))
    ?? (await handlePlanRoute(request, database, now, options))
    ?? (await handleMachineRelayRoute(request, database, now, options))
    ?? (await handleBackupRoute(request, database, now, options))
    ?? (await handlePhoneRoute(request, database, now, options))
    ?? (await handleTeamRoute(request, database, now, options));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === "/health") return Response.json({ ok: true });
    const machines = Math.max(1, Math.min(10_000, Number(env.MAX_MACHINES) || OPEN_PLAN.machines));
    const options: RelayOptions = { planFor: () => ({ ...OPEN_PLAN, machines }) };
    try {
      return (await handleRelay(request, env.DB, options)) ?? Response.json({ ok: false, error: "Not found." }, { status: 404 });
    } catch (error) {
      console.error("relay error", error instanceof Error ? error.message : "unknown");
      return Response.json({ ok: false, error: "Something went wrong on the relay. Try again in a moment." }, { status: 500 });
    }
  },
};
