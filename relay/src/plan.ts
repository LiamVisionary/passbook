// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// What an owner's PassBook may ask of this relay. The routes enforce a plan; they never decide one.
//
// A relay you run yourself has one plan for everybody, OPEN_PLAN, and no notion of payment. The
// hosted relay passes its own `planFor`, which looks up whether the owner's PassBook is tied to an
// account with PassBook Sync or Teams. That lookup is the only part of the hosted relay that is not
// in this folder, and it can only ever return one of these shapes.

export type RelayPlan = {
  /** A short name PassBook shows: "self-hosted", "free", "sync", "teams". */
  plan: string;
  /** How many computers this owner may lend keys to. */
  machines: number;
  /** May this owner keep an encrypted backup here? */
  backup: boolean;
  /** May this owner be asked for approval on a phone through here? */
  approvals: boolean;
  /** How many other people this owner may share with (team members). 0 means none. */
  seats: number;
  /** One sentence added to a refusal when a limit is reached, saying what would lift it. */
  more?: string;
};

export type RelayOptions = {
  planFor?: (ownerDid: string) => Promise<RelayPlan> | RelayPlan;
};

/** The plan of a relay with no billing: everything the code can do, for everyone it serves. */
export const OPEN_PLAN: RelayPlan = { plan: "self-hosted", machines: 50, backup: true, approvals: true, seats: 50 };

export async function planOf(ownerDid: string, options: RelayOptions | undefined): Promise<RelayPlan> {
  return options?.planFor ? await options.planFor(ownerDid) : OPEN_PLAN;
}

/** "This is not included." plus what would include it, when the operator says. */
export function notIncluded(what: string, plan: RelayPlan) {
  return `${what}${plan.more ? " " + plan.more : ""}`;
}
