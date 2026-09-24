# SPDX-License-Identifier: Apache-2.0
"""Installed CLI transport for application integrations. JSON on stdin only."""
from __future__ import annotations

import json
import sys
from typing import Any

import passbook
import passbook_broker as broker


def exchange(envelope: dict[str, Any], *, install_service: bool = True) -> dict[str, Any]:
    root = passbook.root()
    if not broker.running(root=root):
        started = broker.start(root=root)
        if not started.get("ok"):
            return {"ok": False, "error": "Your key connection could not start. Please try again.", "code": "broker-unavailable"}
    features = broker._ask({"op": "ping"}, root=root) or {}
    if features.get("managed_integrations") != 1:
        return {"ok": False, "error": "Finish updating PassBook to connect this app. Running work has been left intact.",
                "code": "broker-update-required"}
    # A broker started before an update keeps running the old code. One from
    # before web links answers `managed_integrations` and then refuses the link
    # as "not connected", which the app can only show as "could not be linked".
    if str(envelope.get("action") or "").startswith("web-link-") and features.get("web_links") != 1:
        return {"ok": False, "error": "PassBook's background service predates this update. Run `passbook broker restart`, "
                                      "sign in again, and try linking again.",
                "code": "broker-update-required"}
    # Recovery performs password derivation and HTTPS may take up to 30 seconds.
    # The two-second availability probe is not a deadline for completed work.
    answer = broker._ask(envelope, root=root, timeout=35) or {
        "ok": False, "error": "Your key connection stopped responding. Please try again.", "code": "broker-unavailable"}
    if envelope.get("action") in {"connect", "authorize-decide"} and answer.get("ok") and (answer.get("binding") or {}).get("background"):
        from passbook_managed_service import install_managed_service
        answer["backgroundService"] = install_managed_service(root=root, install=install_service)
    elif envelope.get("action") == "state" and answer.get("ok") and (answer.get("binding") or {}).get("background"):
        from passbook_managed_service import managed_service_state
        answer["backgroundService"] = managed_service_state(root=root)
    return answer


def integration(_args: Any) -> int:
    try:
        raw = sys.stdin.buffer.read(broker.MAX_REQUEST_BYTES + 1)
        if len(raw) > broker.MAX_REQUEST_BYTES:
            raise ValueError()
        envelope = json.loads(raw)
        if not isinstance(envelope, dict):
            raise ValueError()
        identity_env = getattr(_args, "identity_env", "")
        if identity_env:
            from passbook_connect import envelope as sign_envelope, identity
            key, public, ident = identity(identity_env)
            action, body = envelope.get("action"), envelope.get("body", {})
            if not isinstance(action, str) or not isinstance(body, dict):
                raise ValueError()
            if action == "peer-refresh-proof":
                from passbook_integrations import text
                from passbook_managed_use import keys_of
                if set(body) != {"leaseId", "pairingToken", "keys"}:
                    raise ValueError()
                text(body["leaseId"], limit=64, required=True)
                text(body["pairingToken"], limit=4096, required=True)
                if body["keys"] != []:
                    keys_of(body["keys"])
            if action == "authorize-begin":
                envelope = sign_envelope(action, {**body, "publicKey": public}, key, ident)
            elif action in {"connect", "recovery-pair"}:
                envelope = {"op": "managed", "action": action, "installationId": ident,
                            "body": {**body, "publicKey": public}}
            elif action == "begin":
                envelope = {"op": "managed", "action": action, "body": {}}
            else:
                envelope = sign_envelope(action, body, key, ident)
        elif envelope.get("op") != "managed":
            raise ValueError()
        answer = ({"ok": True, "proof": envelope} if identity_env and envelope.get("action") == "peer-refresh-proof"
                  else exchange(envelope))
        if identity_env and envelope.get("action") == "state" and answer.get("code") == "not-connected":
            answer = exchange({"op": "managed", "action": "state"})
    except (OSError, ValueError, TypeError):
        answer = {"ok": False, "error": "The connection request is invalid.", "code": "invalid-request"}
    print(json.dumps(answer, ensure_ascii=False, separators=(",", ":")))
    return 0 if answer.get("ok") else 1
