# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What the relay carries for this PassBook, and buying more of it.

Everything PassBook does on one machine is free and stays free: the store, encryption, the broker,
scoping, the record. This module is about the one part that runs on somebody else's computer, the
relay (`relay/` in this repository), which carries keys to a linked machine, keeps an encrypted
backup, and carries a question to a phone.

A relay decides how much of that it does for each PassBook, and says so when asked:

    GET /api/passbook/plan   ->   plan, limits, what is used, and who pays if anyone does

A relay somebody runs themselves has one plan, "self-hosted", with no billing: everything the code
can do, for everyone it serves. The relay PassBook uses by default has three:

    free    3 linked computers. No account, nothing to pay.
    sync    50 computers, a backup kept on the relay, answers from a phone.
    teams   everything in sync, and sharing keys with other people. Priced by the person.

A plan belongs to this PassBook's own key (its `did:key`), not to an account. PassBook never had an
account and buying something is not a reason to make one: the relay starts a Stripe Checkout for
this machine's key, the person pays in their browser, and the relay asks Stripe whether it was paid.

**What a plan cannot do** is take anything away. The relay checks a limit when something is added
(a computer, a person, a backup, a phone). A machine already linked keeps receiving its keys and a
backup already stored can always be read back, whatever happens to the plan.

**What this module never does** is open a web page by itself. It returns the address the relay
gave, after checking that it is Stripe's, and the caller (the command line) opens it. The window
asks the command line, so a page is only ever opened with an address this file accepted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import passbook_join as join
import passbook_link as link

CHECKOUT_ORIGIN = "https://checkout.stripe.com/"
BILLING_ORIGIN = "https://billing.stripe.com/"
PLANS = ("sync", "teams")
MIN_SEATS, MAX_SEATS = 2, 50

# The refusals a relay marks with a `code`, so the window can put the way out beside the sentence.
LIMIT_CODES = ("machine_limit", "seat_limit", "not_included")


class PlanError(join.JoinError):
    """Something about the plan could not be done. The message is safe to show a person.

    `code` is the relay's own word for why (`not_on_sale`, `no_billing`, `already`, …) or "".
    """

    def __init__(self, message: str, code: str = "") -> None:
        super().__init__(message)
        self.code = code


def _ask(method: str, path: str, body: Mapping[str, Any] | None = None, *, relay: str = "",
         root: Path | None = None, opener: join.Opener | None = None) -> tuple[str, int, dict[str, Any]]:
    chosen = join.relay_url(relay)
    status, answer = join._call(chosen, method, path, body, link.identity(root=root), opener=opener)
    return chosen, status, answer if isinstance(answer, dict) else {}


def _refuse(status: int, answer: Mapping[str, Any], fallback: str) -> PlanError:
    code = str(answer.get("code") or "")
    if code == "no_billing" or (status == 404 and not code):
        return PlanError("This relay has no paid plans. Everything it can do is already on.", "no_billing")
    return PlanError(str(answer.get("error") or fallback), code)


def _shape(answer: Mapping[str, Any], relay: str) -> dict[str, Any]:
    """The relay's answer, with every field the window reads present and of the right kind."""
    limits = answer.get("limits") if isinstance(answer.get("limits"), Mapping) else {}
    used = answer.get("used") if isinstance(answer.get("used"), Mapping) else {}
    billing = answer.get("billing") if isinstance(answer.get("billing"), Mapping) else None
    count = lambda source, name: max(0, int(source.get(name) or 0))  # noqa: E731
    return {
        "ok": True,
        "relay": relay,
        "plan": str(answer.get("plan") or "free"),
        "limits": {"machines": count(limits, "machines"), "seats": count(limits, "seats"),
                   "backup": bool(limits.get("backup")), "approvals": bool(limits.get("approvals"))},
        "used": {name: count(used, name) for name in ("machines", "members", "backups", "phones")},
        "more": str(answer["more"]) if answer.get("more") else None,
        "billing": dict(billing) if billing is not None else None,
    }


def status(*, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """What the relay carries for this PassBook right now."""
    chosen, code, answer = _ask("GET", "/api/passbook/plan", relay=relay, root=root, opener=opener)
    if code == 404:
        # A relay from before plans existed. It has no limits to report and nothing to sell.
        return _shape({"plan": "self-hosted", "limits": {"machines": 50}}, chosen)
    if code != 200 or not answer.get("ok"):
        raise _refuse(code, answer, "The relay did not say what plan this PassBook has. Try again in a moment.")
    return _shape(answer, chosen)


def describe(plan: Mapping[str, Any]) -> str:
    """One line a person can read: the plan and how much of it is used."""
    name = {"free": "Free", "sync": "PassBook Sync", "teams": "PassBook Teams",
            "self-hosted": "Your own relay"}.get(str(plan.get("plan")), str(plan.get("plan")))
    limits, used = plan["limits"], plan["used"]
    parts = [f"{used['machines']} of {limits['machines']} computers"]
    if limits["seats"]:
        parts.append(f"{used['members']} of {limits['seats']} people")
    return f"{name}: {', '.join(parts)}"


def subscribe(plan: str, *, yearly: bool = False, seats: int = 0, relay: str = "", root: Path | None = None,
              opener: join.Opener | None = None) -> dict[str, Any]:
    """Start buying a plan. Returns `{"url": …}` to pay at, or `{"changed": True, …}`.

    A PassBook that already pays for a plan is moved to the new one on the same subscription, with
    the difference prorated, so nothing opens and there is nothing to pay twice.
    """
    if plan not in PLANS:
        raise PlanError("Choose sync or teams.")
    body: dict[str, Any] = {"plan": plan, "interval": "year" if yearly else "month"}
    if plan == "teams":
        if not MIN_SEATS <= int(seats or MIN_SEATS) <= MAX_SEATS:
            raise PlanError(f"A team has between {MIN_SEATS} and {MAX_SEATS} people, you included.")
        body["seats"] = int(seats or MIN_SEATS)
    chosen, code, answer = _ask("POST", "/api/passbook/plan/checkout", body, relay=relay, root=root, opener=opener)
    if code != 200 or not answer.get("ok"):
        raise _refuse(code, answer, "The relay could not start a checkout. Nothing was charged.")
    if answer.get("changed"):
        return {**_shape(answer, chosen), "changed": True}
    url = str(answer.get("url") or "")
    if not url.startswith(CHECKOUT_ORIGIN):
        raise PlanError("The relay answered with a page that is not Stripe's checkout, so it was not opened.")
    return {"ok": True, "url": url, "plan": plan, "interval": body["interval"], "seats": body.get("seats")}


def _change(path: str, body: Mapping[str, Any] | None, fallback: str, *, relay: str, root: Path | None,
            opener: join.Opener | None) -> dict[str, Any]:
    chosen, code, answer = _ask("POST", path, body, relay=relay, root=root, opener=opener)
    if code != 200 or not answer.get("ok"):
        raise _refuse(code, answer, fallback)
    return _shape(answer, chosen)


def cancel(*, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Stop the plan renewing. What was paid for runs to its end."""
    return _change("/api/passbook/plan/cancel", {}, "The plan could not be canceled just now. Try again in a moment.",
                   relay=relay, root=root, opener=opener)


def resume(*, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Undo a cancel that has not taken effect yet."""
    return _change("/api/passbook/plan/resume", {}, "The plan could not be resumed just now. Try again in a moment.",
                   relay=relay, root=root, opener=opener)


def set_seats(seats: int, *, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> dict[str, Any]:
    """Change how many people a team has seats for."""
    if not MIN_SEATS <= int(seats) <= MAX_SEATS:
        raise PlanError(f"A team has between {MIN_SEATS} and {MAX_SEATS} people, you included.")
    return _change("/api/passbook/plan/change", {"plan": "teams", "seats": int(seats)},
                   "The seats could not be changed just now. Try again in a moment.", relay=relay, root=root, opener=opener)


def billing_page(*, relay: str = "", root: Path | None = None, opener: join.Opener | None = None) -> str:
    """The address of Stripe's page for this plan's card and invoices."""
    _, code, answer = _ask("POST", "/api/passbook/plan/portal", {}, relay=relay, root=root, opener=opener)
    if code != 200 or not answer.get("ok"):
        raise _refuse(code, answer, "The billing page could not be opened just now. Try again in a moment.")
    url = str(answer.get("url") or "")
    if not url.startswith(BILLING_ORIGIN):
        raise PlanError("The relay answered with a page that is not Stripe's, so it was not opened.")
    return url
