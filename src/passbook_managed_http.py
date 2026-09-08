# SPDX-License-Identifier: Apache-2.0
"""Bound HTTPS operations. Never follow redirects carrying authentication."""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

import passbook_grant


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def proxy(parameters: Mapping[str, Any], values: Mapping[str, str]) -> dict[str, Any]:
    url = str(parameters["url"])
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        return {"ok": False, "error": "This connection requires a secure destination."}
    headers = {}
    for key, template in parameters.get("headers", {}).items():
        headers[key] = passbook_grant._fill(template, values)[0]
    payload = parameters.get("body")
    data = None if payload is None else (payload if isinstance(payload, str) else json.dumps(payload)).encode("utf-8")
    if data and not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, method=parameters.get("method", "GET"), headers=headers, data=data)
    try:
        # LibreSSL ignores these standard host trust settings when loading its
        # defaults. Pass them explicitly, keeping certificate/hostname checks
        # enabled and the system trust store unchanged when neither is set.
        context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None,
                                             capath=os.environ.get("SSL_CERT_DIR") or None)
        # Ignore ambient proxy variables: an agent-supplied environment must not
        # redirect an authenticated operation to an unintended intermediary.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                             urllib.request.HTTPSHandler(context=context))
        try:
            answer = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            answer = error
        with answer:
            status = answer.code
            raw = answer.read(passbook_grant.MAX_OUTPUT + 1)
            response_headers = dict(answer.headers)
        if 300 <= status < 400:
            return {"ok": False, "status": status,
                    "error": "This service requested a different destination. Review the connection before continuing."}
        def scrub(content: Any) -> str:
            cleaned = passbook_grant.redact(str(content), values)
            # The process-output scrubber skips short values to keep ordinary
            # command output legible. Managed credential responses cannot make
            # that tradeoff: a valid short credential still must not be echoed.
            for name, value in sorted(values.items(), key=lambda item: len(item[1]), reverse=True):
                if value and len(value) < passbook_grant.MIN_REDACTABLE:
                    cleaned = cleaned.replace(value, passbook_grant.REDACTION.format(name=name))
            return cleaned
        return {"ok": True, "status": status, "body": scrub(raw.decode("utf-8", errors="replace"))[:passbook_grant.MAX_OUTPUT],
                "headers": {key: scrub(value) for key, value in response_headers.items()
                            if key.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
                            and scrub(key) == key},
                "truncated": len(raw) > passbook_grant.MAX_OUTPUT, "used": sorted(values)}
    except (OSError, ValueError, urllib.error.URLError):
        return {"ok": False, "error": "The service could not be reached. Check its status before retrying this operation."}
