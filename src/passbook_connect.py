# SPDX-License-Identifier: Apache-2.0
"""Owner-facing enrollment; authentication is prompted, never passed in argv."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

from passbook_prompt import hidden_input
from passbook_managed_cli import exchange
from passbook_managed_store import b64, canonical, identifier, installation_id, now_ms, signed_bytes


def identity(variable: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    secret = os.environ.get(variable, "")
    if len(secret) < 32 or secret.startswith("hive-sealed:"):
        raise ValueError("Open the app to finish connecting your keys. Its installation identity is not available here.")
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        b"passbook-integration-v1\0" + secret.encode()).digest())
    public = b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return key, public, installation_id(public)


def envelope(action: str, body: dict[str, Any], key, ident: str) -> dict[str, Any]:
    at, nonce, raw = now_ms(), identifier(), canonical(body)
    return {"op": "managed", "action": action, "installationId": ident, "issuedAt": at,
            "nonce": nonce, "bodyJson": raw, "signature": b64(key.sign(signed_bytes(action, ident, at, nonce, raw)))}


def _finish(args, result: dict[str, Any]) -> int:
    if args.json:
        print(json.dumps(result, separators=(",", ":")))
    elif not result.get("ok"):
        print(result.get("error", "This connection could not be completed."), file=sys.stderr)
    elif result.get("revoked"):
        print("App disconnected. Your saved keys and other app connections are preserved.")
    else:
        binding = result.get("binding") or {}
        if result.get("state") == "paused":
            print("Background access is paused. Resume it in the app when you are ready.")
        elif result.get("state") != "ready":
            print("Your workspace is connected but locked. Open the app to unlock your keys.")
        else:
            print(f"Connected to {binding.get('name', 'PassBook')}. Your keys are ready to use.")
        service = result.get("backgroundService") or {}
        if service.get("ok") is False:
            print("Background startup could not be enabled. Reopen the connection settings to retry.", file=sys.stderr)
    return 0 if result.get("ok") else 1


def connect(args) -> int:
    try:
        workspace_label = args.workspace or args.app
        key, public, ident = identity(args.identity_env)
        current = exchange(envelope("state", {}, key, ident))
        binding = current.get("binding") if current.get("ok") else None
        if binding:
            if binding.get("app") != args.app:
                raise ValueError("This identity belongs to a different app. Its connection was preserved.")
            if binding.get("background") and current.get("state") == "ready":
                from passbook_managed_service import install_managed_service
                current["backgroundService"] = install_managed_service()
            if current.get("state") in {"ready", "paused"}:
                return _finish(args, current)
        if current.get("code") not in {"not-connected", None}:
            return _finish(args, current)
        if args.non_interactive or not sys.stdin.isatty():
            return _finish(args, {"ok": False, "code": "locked" if binding else "needs-owner",
                                  "state": "locked" if binding else "unconfigured",
                                  "error": "Open your app's key settings to unlock PassBook." if binding else
                                  "Open your app's key settings to finish connecting PassBook."})
        available = current if binding else exchange({"op": "managed", "action": "begin"})
        if not available.get("ok"):
            return _finish(args, available)
        rows = available.get("workspaces", [])
        existing = bool(binding) or any(row.get("hasProfile") for row in rows)
        workspace = workspace_label
        create = True
        if binding:
            workspace, create = binding["workspace"], False
            print("Unlock your connected workspace to continue.", file=sys.stderr)
        elif existing:
            print(f"Authorize {args.name or args.app} to use a workspace.", file=sys.stderr)
            for index, row in enumerate(rows, 1):
                print(f"  {index}. {row['name']}", file=sys.stderr)
            print(f"  {len(rows) + 1}. Create a dedicated {workspace_label} workspace", file=sys.stderr)
            choice = input(f"Workspace [new]: ").strip()
            if choice:
                if not choice.isdigit() or not 1 <= int(choice) <= len(rows) + 1:
                    raise ValueError("Choose one of the listed workspaces.")
                if int(choice) <= len(rows):
                    workspace, create = rows[int(choice) - 1]["id"], False
        else:
            # Hive setup may have already written its original store. The first
            # connection encrypts that same store and gives it the app's label.
            workspace = "main"
            print(f"Set up {args.name or workspace_label} to keep your keys encrypted and ready for this app.", file=sys.stderr)
        password = hidden_input("PassBook password: " if existing and not create else "Create a PassBook password (8+ characters): ")
        if not existing or create:
            if password != hidden_input("Confirm password: "):
                raise ValueError("The passwords did not match. No connection was created.")
        background = not args.no_background and (binding.get("background", False) if binding else True)
        if background:
            import passbook_keystore
            if not passbook_keystore.available():
                print("This device has no supported secure key store. Keys will stay available until sign-out; "
                      "background access needs a supported device key store.", file=sys.stderr)
                background = False
        result = exchange({"op": "managed", "action": "connect", "installationId": ident,
                           "body": {"publicKey": public, "app": args.app, "name": args.name or workspace_label,
                                    "workspace": workspace, "createWorkspace": create, "consent": True,
                                    "password": password, "background": background}})
        return _finish(args, result)
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        return _finish(args, {"ok": False, "code": "needs-owner", "error": str(exc) or "Connection cancelled."})


def disconnect(args) -> int:
    try:
        key, _public, ident = identity(args.identity_env)
        current = exchange(envelope("state", {}, key, ident))
        if current.get("code") == "not-connected":
            return _finish(args, {"ok": True, "revoked": True, "already": True})
        if not current.get("ok"):
            return _finish(args, current)
        if current.get("binding", {}).get("app") != args.app:
            raise ValueError("This identity belongs to a different app. Its connection was preserved.")
        if not args.yes:
            if not sys.stdin.isatty() or input(f"Disconnect {args.app} from PassBook? [y/N] ").strip().lower() != "y":
                raise ValueError("Connection preserved.")
        return _finish(args, exchange(envelope("revoke", {"disconnect": True}, key, ident)))
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        return _finish(args, {"ok": False, "code": "needs-owner", "error": str(exc) or "Connection preserved."})


def add_commands(subs) -> None:
    for name, callback in (("connect", connect), ("disconnect", disconnect)):
        parser = subs.add_parser(name, help=f"{name} an app with your encrypted workspace")
        parser.add_argument("--app", required=True, help="application identifier")
        parser.add_argument("--identity-env", required=True, help="name of the app's installation identity variable")
        parser.add_argument("--json", action="store_true")
        if name == "connect":
            parser.add_argument("--workspace", default="", help="new workspace name; defaults to the app identifier")
            parser.add_argument("--name", default="")
            parser.add_argument("--non-interactive", action="store_true")
            parser.add_argument("--no-background", action="store_true")
        else:
            parser.add_argument("--yes", action="store_true")
        parser.set_defaults(func=callback)
