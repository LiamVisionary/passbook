# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rizzma, Inc.
"""What your service accounts have left, read with the keys this store already holds.

`passbook balances` asks each provider you hold a key for what is left on the account (OpenRouter credits,
a fal balance, an ElevenLabs allowance...), straight from this computer to the provider, and says where to
top up. Nothing is sent anywhere else, and only the numbers are kept, for two minutes.

The provider list and the readers came from HivemindOS's service accounts (Liam, 2026-10-12: "share the
logic so improvements affect both"); HivemindOS now reads balances through this module, so a reader added or
fixed here reaches both. The rules they carried over:

- A reading is what the provider reports, never an estimate: no balance is assumed when the answer is not
  understood, and a plan allowance or an invoice is not called a cash balance.
- A denial is only its HTTP category. The body of a 401 or 403 is never read back: it can echo the key.
- A credential never follows a redirect: each endpoint is the canonical address, and a redirect is refused.
- Some providers need a separate billing key (an inference key cannot read billing); the catalog names it.

Optional, like every module beside `passbook.py`: nothing here is needed to read a credential.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

# The directory: every provider HivemindOS knows a billing page for, and, for 13 of them, how to read the
# balance. `keys` are the credentials the provider is used with; `reading_keys`, when present, are the only
# ones that can read its billing. Generated from HivemindOS's catalog on 2026-10-12.
PROVIDERS: tuple[dict, ...] = (
    {"id": "openrouter", "name": "OpenRouter", "category": "Models", "keys": ('OPENROUTER_API_KEY',), "reading_keys": ('OPENROUTER_MANAGEMENT_KEY',), "billing": "prepaid", "console_url": "https://openrouter.ai", "billing_url": "https://openrouter.ai/settings/credits", "adapter": "openrouter", "docs_url": "https://openrouter.ai/docs/api/api-reference/credits/get-remaining-credits", "verified": "2026-10-02", "payment_note": "Buy credits on OpenRouter. Its former Coinbase Commerce top-up API is deprecated; no payment is made here."},
    {"id": "openai-api", "name": "OpenAI API", "category": "Models", "keys": ('OPENAI_API_KEY',), "billing": "mixed", "console_url": "https://platform.openai.com", "billing_url": "https://platform.openai.com/settings/organization/billing/overview", "docs_url": "https://help.openai.com/en/articles/8264644-setting-up-and-managing-prepaid-api-billing", "verified": "2026-10-02", "payment_note": "API billing is separate from ChatGPT subscriptions. Purchase credits on the OpenAI billing page."},
    {"id": "anthropic", "name": "Anthropic API", "category": "Models", "keys": ('ANTHROPIC_API_KEY',), "billing": "mixed", "console_url": "https://platform.claude.com", "billing_url": "https://platform.claude.com/settings/billing", "verified": "2026-10-02", "payment_note": "API billing is separate from Claude subscriptions. Confirm your account’s billing model on the billing page."},
    {"id": "xai", "name": "xAI API", "category": "Models", "keys": ('XAI_API_KEY',), "billing": "mixed", "console_url": "https://console.x.ai", "docs_url": "https://docs.x.ai/developers/rest-api-reference/management/billing", "verified": "2026-10-02", "payment_note": "xAI documents a top-up API requiring a management key and team. In-app charging stays unavailable until payment identity and duplicate-charge reconciliation are verified. Use the console for now."},
    {"id": "fal", "name": "fal", "category": "Media", "keys": ('FAL_KEY',), "reading_keys": ('FAL_ADMIN_KEY', 'FAL_KEY'), "billing": "prepaid", "console_url": "https://fal.ai/dashboard", "billing_url": "https://fal.ai/dashboard/usage-billing/billing", "adapter": "fal", "docs_url": "https://fal.ai/docs/platform-apis/v1/account/billing", "verified": "2026-10-02", "payment_note": "A billing read requires an Admin key. An existing FAL_KEY is tried read-only; the provider enforces its permissions. Complete purchases on fal’s billing page."},
    {"id": "meshy", "name": "Meshy", "category": "Media", "keys": ('MESHY_API_KEY',), "billing": "mixed", "console_url": "https://www.meshy.ai/workspace", "adapter": "meshy", "docs_url": "https://docs.meshy.ai/en/api/balance", "verified": "2026-10-02", "payment_note": "Meshy reports credits, not dollars. Subscription credits and API purchases must be checked on the provider’s site."},
    {"id": "vast", "name": "Vast.ai", "category": "Cloud", "keys": ('VAST_API_KEY', 'VASTAI_API_KEY'), "billing": "prepaid", "console_url": "https://console.vast.ai", "adapter": "vast", "docs_url": "https://docs.vast.ai/api-reference/accounts/show-user", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "apify", "name": "Apify", "category": "Research", "keys": ('APIFY_TOKEN', 'APIFY_API_KEY', 'APIFY_API_TOKEN'), "billing": "mixed", "console_url": "https://console.apify.com", "billing_url": "https://console.apify.com/billing", "adapter": "apify", "docs_url": "https://docs.apify.com/api/v2/users-me-usage-monthly-get", "verified": "2026-10-02", "payment_note": "The live reading is monthly usage, not a remaining credit balance. Manage the plan and spending limits on Apify."},
    {"id": "runware", "name": "Runware", "category": "Media", "keys": ('RUNWARE_API_KEY',), "billing": "prepaid", "console_url": "https://my.runware.ai", "docs_url": "https://runware.ai/docs/models-api/pricing", "verified": "2026-10-02", "payment_note": "Top up inference credits on the Runware dashboard. Serverless credit is a separate pool; no balance conversion is assumed."},
    {"id": "tripo", "name": "Tripo API", "category": "Media", "keys": ('TRIPO_API_KEY',), "billing": "prepaid", "console_url": "https://platform.tripo3d.ai", "docs_url": "https://docs.tripo3d.ai/other/wallet.html", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "ideogram", "name": "Ideogram", "category": "Media", "keys": ('IDEOGRAM_API_KEY',), "billing": "prepaid", "console_url": "https://ideogram.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "kie", "name": "KIE", "category": "Media", "keys": ('KIE_API_KEY',), "billing": "prepaid", "console_url": "https://kie.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "icypeas", "name": "Icypeas", "category": "Research", "keys": ('ICYPEAS_API_KEY',), "billing": "mixed", "console_url": "https://app.icypeas.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "kinovi", "name": "Kinovi", "category": "Media", "keys": ('KINOVI_API_KEY',), "billing": "prepaid", "console_url": "https://kinovi.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "alchemy", "name": "Alchemy", "category": "Developer tools", "keys": ('ALCHEMY_API_KEY',), "billing": "unknown", "console_url": "https://dashboard.alchemy.com", "docs_url": "https://www.alchemy.com/docs/admin-api/usage/get-usage-summary", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Usage reporting requires an Alchemy admin key with usage-read permission. Your saved RPC key alone does not establish billing access."},
    {"id": "ngrok", "name": "ngrok", "category": "Developer tools", "keys": ('NGROK_API_KEY', 'NGROK_AUTHTOKEN'), "billing": "unknown", "console_url": "https://dashboard.ngrok.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "vercel", "name": "Vercel", "category": "Cloud", "keys": ('VERCEL_TOKEN', 'VERCEL_OIDC_TOKEN'), "billing": "unknown", "console_url": "https://vercel.com/dashboard", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "vultr", "name": "Vultr", "category": "Cloud", "keys": ('VULTR_API_KEY',), "billing": "postpaid", "console_url": "https://my.vultr.com", "adapter": "vultr", "docs_url": "https://github.com/vultr/govultr/blob/master/account.go", "verified": "2026-10-02", "payment_note": "Account balance and pending charges are shown as reported. Their signs are not interpreted as spendable funds. Complete payments on Vultr."},
    {"id": "composio", "name": "Composio", "category": "Developer tools", "keys": ('COMPOSIO_API_KEY',), "billing": "unknown", "console_url": "https://platform.composio.dev", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "google-cloud", "name": "Google Cloud", "category": "Cloud", "billing": "unknown", "console_url": "https://console.cloud.google.com/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "cloudflare", "name": "Cloudflare", "category": "Cloud", "keys": ('CLOUDFLARE_API_TOKEN',), "billing": "unknown", "console_url": "https://dash.cloudflare.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "supabase", "name": "Supabase", "category": "Cloud", "keys": ('SUPABASE_ACCESS_TOKEN',), "billing": "unknown", "console_url": "https://supabase.com/dashboard", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "github", "name": "GitHub", "category": "Developer tools", "keys": ('GITHUB_TOKEN', 'GH_TOKEN'), "billing": "unknown", "console_url": "https://github.com/settings/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "resend", "name": "Resend", "category": "Developer tools", "keys": ('RESEND_API_KEY',), "billing": "mixed", "console_url": "https://resend.com", "adapter": "resend", "docs_url": "https://resend.com/docs/api-reference/usage/retrieve-usage", "verified": "2026-10-02", "payment_note": "Email and other allowances are usage limits, not cash. Review your plan and billing on Resend."},
    {"id": "hetzner", "name": "Hetzner", "category": "Cloud", "keys": ('HETZNER_API_TOKEN', 'HCLOUD_TOKEN'), "billing": "postpaid", "console_url": "https://console.hetzner.cloud", "docs_url": "https://docs.hetzner.com/cloud/billing/faq/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Resource prices can support an estimate, but they do not report your invoice or account balance. Review Hetzner billing."},
    {"id": "agentmail", "name": "AgentMail", "category": "Developer tools", "keys": ('AGENTMAIL_API_KEY',), "billing": "unknown", "console_url": "https://console.agentmail.to", "adapter": "agentmail", "docs_url": "https://docs.agentmail.to/api-reference/organizations/get", "verified": "2026-10-02", "payment_note": "The organization endpoint reports connected inboxes and domains, not a monetary balance. Review your plan and payment on AgentMail."},
    {"id": "scrapecreators", "name": "Scrape Creators", "category": "Research", "keys": ('SCRAPECREATORS_API_KEY', 'SCRAPE_CREATORS_API_KEY'), "billing": "prepaid", "console_url": "https://scrapecreators.com", "docs_url": "https://docs.scrapecreators.com/v1/account/credit-balance/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Checking this balance costs one provider credit. Automatic reads are disabled; review the balance on Scrape Creators."},
    {"id": "resemble", "name": "Resemble AI", "category": "Media", "keys": ('RESEMBLE_API_KEY',), "billing": "unknown", "console_url": "https://app.resemble.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "quiver", "name": "QuiverAI", "category": "Media", "keys": ('QUIVER_API_KEY', 'QUIVERAI_API_KEY'), "reading_keys": ('QUIVER_BILLING_ADMIN_KEY',), "billing": "prepaid", "console_url": "https://quiver.ai", "adapter": "quiver", "docs_url": "https://docs.quiver.ai/api-reference/organization/get-organization-balance", "verified": "2026-10-02", "payment_note": "Balance reporting uses a separate existing organization Admin key with billing-read permission. Your inference key stays separate. Credits cover the organization across projects. Purchase credits on QuiverAI.", "billing_key": {"key": "QUIVER_BILLING_ADMIN_KEY", "label": "QuiverAI organization billing key", "permission": "An existing organization Admin key with billing-read permission. Project keys cannot read organization billing; Admin keys cannot run inference."}},
    {"id": "nansen", "name": "Nansen", "category": "Research", "keys": ('NANSEN_API_KEY',), "billing": "unknown", "console_url": "https://app.nansen.ai", "docs_url": "https://docs.nansen.ai/getting-started/credits", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "A supported credit-balance endpoint has not been verified. Review your credit balance on the Nansen dashboard."},
    {"id": "vadoo", "name": "Vadoo", "category": "Media", "keys": ('VADOO_API_KEY',), "billing": "unknown", "console_url": "https://www.vadoo.tv", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "termly", "name": "Termly", "category": "Developer tools", "billing": "unknown", "console_url": "https://app.termly.io", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "apple-developer", "name": "Apple Developer", "category": "Developer tools", "billing": "unknown", "console_url": "https://developer.apple.com/account", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "chatgpt", "name": "ChatGPT subscription", "category": "Models", "billing": "unknown", "console_url": "https://chatgpt.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "claude-plan", "name": "Claude subscription", "category": "Models", "billing": "unknown", "console_url": "https://claude.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "elevenlabs", "name": "ElevenLabs", "category": "Media", "keys": ('ELEVENLABS_API_KEY',), "billing": "mixed", "console_url": "https://elevenlabs.io/app", "adapter": "elevenlabs", "docs_url": "https://elevenlabs.io/docs/api-reference/user/subscription/get", "verified": "2026-10-02", "payment_note": "Plan allowance, usage, overage and the next invoice are distinct from a cash balance. Review your plan or additional credits on ElevenLabs."},
    {"id": "muapi", "name": "Muapi", "category": "Media", "keys": ('MUAPI_API_KEY',), "billing": "mixed", "console_url": "https://muapi.ai", "billing_url": "https://muapi.ai/topup", "docs_url": "https://muapi.ai/topup", "verified": "2026-10-02", "payment_note": "Buy credits on Muapi’s official billing page. Check whether the selected plan includes credits before purchasing more."},
    {"id": "supergrok", "name": "SuperGrok subscription", "category": "Models", "billing": "unknown", "console_url": "https://grok.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "codex-credits", "name": "Codex / Work credits", "category": "Models", "billing": "unknown", "console_url": "https://chatgpt.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "azure", "name": "Microsoft Azure", "category": "Cloud", "billing": "unknown", "console_url": "https://portal.azure.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "render", "name": "Render", "category": "Cloud", "keys": ('RENDER_API_KEY',), "billing": "unknown", "console_url": "https://dashboard.render.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "huggingface", "name": "Hugging Face", "category": "Models", "keys": ('HF_TOKEN', 'HUGGING_FACE_HUB_TOKEN'), "billing": "unknown", "console_url": "https://huggingface.co/settings/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "colab", "name": "Google Colab", "category": "Cloud", "billing": "unknown", "console_url": "https://colab.research.google.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "aws", "name": "Amazon Web Services", "category": "Cloud", "billing": "unknown", "console_url": "https://console.aws.amazon.com/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "obsidian-sync", "name": "Obsidian Sync", "category": "Developer tools", "billing": "unknown", "console_url": "https://obsidian.md/account", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "google-one", "name": "Google One / AI plan", "category": "Models", "billing": "unknown", "console_url": "https://one.google.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "streamoji", "name": "Streamoji Avatars", "category": "Media", "billing": "unknown", "console_url": "https://streamoji.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "universal-sign-in", "name": "Universal Sign In", "category": "Developer tools", "billing": "unknown", "console_url": "https://universal-sign-in.com/auth/login", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "deepseek", "name": "DeepSeek", "category": "Models", "keys": ('DEEPSEEK_API_KEY',), "billing": "prepaid", "console_url": "https://platform.deepseek.com", "adapter": "deepseek", "docs_url": "https://api-docs.deepseek.com/api/get-user-balance/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "bankr", "name": "Bankr LLM", "category": "Models", "keys": ('BANKR_LLM_KEY',), "billing": "prepaid", "console_url": "https://bankr.bot", "billing_url": "https://bankr.bot/terminal/llm", "adapter": "bankr", "docs_url": "https://docs.bankr.bot/llm-gateway/api-reference/", "verified": "2026-10-02", "payment_note": "The available balance covers this wallet across its API keys and includes pending usage. Daily spending limits are separate. Complete purchases on Bankr."},
    {"id": "venice", "name": "Venice AI", "category": "Models", "keys": ('VENICE_API_KEY',), "billing": "mixed", "console_url": "https://venice.ai", "adapter": "venice", "docs_url": "https://docs.venice.ai/api-reference/endpoint/billing/balance", "verified": "2026-10-02", "payment_note": "USD funds and DIEM allowance are shown separately. DIEM is not added to your dollar balance. Manage payments on Venice."},
    {"id": "usepod", "name": "UsePod", "category": "Models", "keys": ('USEPOD_TOKEN',), "billing": "prepaid", "console_url": "https://usepod.com", "docs_url": "https://docs.usepod.ai/using/funding/", "verified": "2026-10-02", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding.", "reading_note": "UsePod reports balance with paid responses. This dashboard does not spend money to obtain a balance; review your funding page."},
    {"id": "groq", "name": "Groq", "category": "Models", "keys": ('GROQ_API_KEY',), "billing": "unknown", "console_url": "https://console.groq.com", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "dot", "name": "Dot", "category": "Models", "keys": ('DOT_API_KEY',), "billing": "unknown", "console_url": "https://usedot.xyz", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "engy", "name": "engy", "category": "Models", "keys": ('ENGYAI_API_KEY',), "billing": "unknown", "console_url": "https://engy.ai", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "nearai", "name": "NEAR AI", "category": "Models", "keys": ('NEAR_AI_API_KEY',), "billing": "unknown", "console_url": "https://cloud.near.ai", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "gemini", "name": "Gemini", "category": "Models", "keys": ('GEMINI_API_KEY',), "billing": "unknown", "console_url": "https://aistudio.google.com", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
)

# Where each reader asks, and how it says who it is. The documented Vast endpoint redirects to this
# trailing-slash address; asking it directly means the key never follows a redirect.
REQUESTS: dict[str, tuple[str, str]] = {
    "openrouter": ("https://openrouter.ai/api/v1/credits", "Bearer"),
    "fal": ("https://api.fal.ai/v1/account/billing?expand=credits", "Key"),
    "meshy": ("https://api.meshy.ai/openapi/v1/balance", "Bearer"),
    "vast": ("https://console.vast.ai/api/v0/users/current/", "Bearer"),
    "apify": ("https://api.apify.com/v2/users/me/usage/monthly", "Bearer"),
    "deepseek": ("https://api.deepseek.com/user/balance", "Bearer"),
    "venice": ("https://api.venice.ai/api/v1/billing/balance", "Bearer"),
    "bankr": ("https://llm.bankr.bot/v1/credits", "Bearer"),
    "elevenlabs": ("https://api.elevenlabs.io/v1/user/subscription", "xi-api-key"),
    "agentmail": ("https://api.agentmail.to/v0/organizations", "Bearer"),
    "vultr": ("https://api.vultr.com/v2/account", "Bearer"),
    "resend": ("https://api.resend.com/usage", "Bearer"),
    "quiver": ("https://api.quiver.ai/v1/organization/balance", "Bearer"),
}

# What a ready reading means, said once per kind: the reading is never more than the provider reported.
READY_NOTES = {
    "apify": "Provider-reported usage. Remaining credits are not reported here.",
    "elevenlabs": "Plan allowance and invoices are not a cash balance.",
    "resend": "Plan usage and allowances are not a cash balance. An uncapped daily allowance does not remove your monthly plan limit.",
    "agentmail": "Organization counts and limits are not a cash balance.",
    "vultr": "Accounting amounts are shown as reported, without assuming spendable funds or combining pending charges.",
}
READY_NOTE = "Provider-reported balance for the saved billing credential. Other organizations or accounts may be missing."
MANUAL_NOTE = "This provider does not report a balance to an API key. Check it on the provider's site."

CACHE_SECONDS = 120
SETTINGS_FILE = "balances.json"
CACHE_FILE = "balances-cache.json"
SALT_FILE = "balances-salt"

BILLING_LABELS = {"prepaid": "Prepaid credits", "subscription": "Subscription", "postpaid": "Billed after usage",
                  "mixed": "Plan / usage / credits", "unknown": "Billing needs review"}


class Unreadable(ValueError):
    """The provider answered, but not in a shape this reader understands. No balance is assumed."""


# ── reading one answer ──────────────────────────────────────────────────────


def _record(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if value == value and abs(value) != float("inf") else None


def _decimal(value: Any) -> float | None:
    if isinstance(value, str):
        text = value.strip()
        try:
            parsed = float(text)
        except ValueError:
            return None
        return parsed if text and text.lstrip("-").replace(".", "", 1).isdigit() else None
    return _number(value)


def _text(value: Any) -> str | None:
    return value.strip()[:100] if isinstance(value, str) and value.strip() else None


def _currency(value: Any) -> str | None:
    return value.upper() if isinstance(value, str) and len(value) == 3 and value.isalpha() else None


def _amount(label: str, value: Any, unit: str) -> list[dict]:
    # As given, written as JavaScript writes a number (10, not 10.0), so HivemindOS shows the same text.
    shown = int(value) if isinstance(value, float) and value.is_integer() and abs(value) < 2**53 else value
    return [] if _decimal(value) is None else [{"label": label, "value": f"{shown} {unit}"}]


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) >= 100:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def parse_reading(adapter: str, payload: Any) -> dict:
    """One provider's answer as a reading: balance and unit, usage, an allowance, details. Raises Unreadable."""
    body = _record(payload)
    data = _record(body.get("data"))
    if adapter == "openrouter":
        credits, usage = _number(data.get("total_credits")), _number(data.get("total_usage"))
        if credits is None or usage is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": credits - usage, "unit": "USD", "usageUsd": usage, "usagePeriod": "All time"}
    if adapter == "fal":
        credits = _record(body.get("credits"))
        balance, unit = _number(credits.get("current_balance")), credits.get("currency")
        if balance is None or not isinstance(unit, str) or len(unit) != 3 or not unit.isupper():
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": unit, "accountLabel": _text(body.get("username"))}
    if adapter == "meshy":
        balance = _number(body.get("balance"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "credits"}
    if adapter == "vast":
        balance = _number(body.get("balance"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "USD"}
    if adapter == "apify":
        usage = _number(data.get("totalUsageCreditsUsdAfterVolumeDiscount"))
        if usage is None:
            raise Unreadable("Unexpected usage response")
        return {"usageUsd": usage, "usagePeriod": "Current monthly cycle"}
    if adapter == "deepseek":
        rows = [_record(row) for row in body.get("balance_infos") or [] if isinstance(row, dict)]
        rows = [row for row in rows if row.get("currency") in ("USD", "CNY") and _decimal(row.get("total_balance")) is not None]
        if not rows:
            raise Unreadable("Unexpected balance response")
        primary = next((row for row in rows if row.get("currency") == "USD"), rows[0])
        details = [item for row in rows for item in (
            _amount("Available balance", row.get("total_balance"), str(row["currency"]))
            + _amount("Unexpired granted balance", row.get("granted_balance"), str(row["currency"]))
            + _amount("Purchased balance", row.get("topped_up_balance"), str(row["currency"])))]
        return {"balance": _decimal(primary.get("total_balance")), "unit": str(primary["currency"]), "details": details}
    if adapter == "venice":
        balances = _record(body.get("balances"))
        balance = _number(balances.get("usd"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "USD", "details": (
            _amount("DIEM allowance remaining", balances.get("diem"), "DIEM")
            + _amount("DIEM epoch allocation", body.get("diemEpochAllocation"), "DIEM")
            + _amount("Bundled credits", balances.get("bundledCredits"), "credits")
            + _amount("Earned credits", balances.get("earnedCredits"), "credits"))}
    if adapter == "bankr":
        balance = _number(body.get("effectiveBalanceUsd"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        budget = _record(body.get("dailyBudget"))
        return {"balance": balance, "unit": "USD", "details": (
            _amount("Wallet balance before pending usage", body.get("balanceUsd"), "USD")
            + _amount("Pending usage", body.get("undeductedCostUsd"), "USD")
            + _amount("Rolling 24-hour spend limit", budget.get("limitUsd"), "USD")
            + _amount("Rolling 24-hour spend", budget.get("spentUsd"), "USD")
            + _amount("Rolling 24-hour allowance remaining", budget.get("remainingUsd"), "USD"))}
    if adapter == "elevenlabs":
        used, limit = _number(body.get("character_count")), _number(body.get("character_limit"))
        if used is None or limit is None or used < 0 or limit < 0 or used != int(used) or limit != int(limit):
            raise Unreadable("Unexpected subscription response")
        reset = _number(body.get("next_character_count_reset_unix"))
        overage, invoice = _record(body.get("current_overage")), _record(body.get("next_invoice"))
        cents, invoice_currency = _number(invoice.get("amount_due_cents")), _currency(body.get("currency"))
        details = ([{"label": "Plan", "value": _text(body.get("tier"))}] if _text(body.get("tier")) else []) \
            + ([{"label": "Subscription status", "value": _text(body.get("status"))}] if _text(body.get("status")) else []) \
            + (_amount("Current overage", overage.get("amount"), _currency(overage.get("currency"))) if _currency(overage.get("currency")) else []) \
            + (_amount("Next invoice", cents / 100, invoice_currency) if cents is not None and invoice_currency else [])
        resets = _iso(reset) if reset is not None and abs(reset) <= 8.64e12 else None
        return {"allowance": {"used": int(used), "limit": int(limit), "unit": "characters", "resetsAt": resets}, "details": details}
    if adapter == "agentmail":
        inboxes, domains = _number(body.get("inbox_count")), _number(body.get("domain_count"))
        if inboxes is None or domains is None or inboxes < 0 or domains < 0 or not _text(body.get("organization_id")):
            raise Unreadable("Unexpected organization response")
        return {"accountLabel": _text(body.get("organization_id")), "details": (
            _amount("Inboxes", inboxes, "inboxes") + _amount("Inbox limit", body.get("inbox_limit"), "inboxes")
            + _amount("Domains", domains, "domains") + _amount("Domain limit", body.get("domain_limit"), "domains")
            + ([{"label": "Billing type", "value": _text(body.get("billing_type"))}] if _text(body.get("billing_type")) else []))}
    if adapter == "vultr":
        account = _record(body.get("account"))
        if _number(account.get("balance")) is None or _number(account.get("pending_charges")) is None:
            raise Unreadable("Unexpected account response")
        return {"accountLabel": _text(account.get("name")), "details": (
            _amount("Account balance as reported", account.get("balance"), "USD")
            + _amount("Pending charges", account.get("pending_charges"), "USD"))}
    if adapter == "resend":
        emails = _record(body.get("emails"))
        monthly, daily = _record(emails.get("monthly")), _record(emails.get("daily"))
        used, limit = _number(monthly.get("used")), _number(monthly.get("limit"))
        daily_used, daily_limit = _number(daily.get("used")), _number(daily.get("limit"))
        if (used is None or used < 0 or daily_used is None or daily_used < 0
                or not (monthly.get("limit") is None or (limit is not None and limit >= 0))
                or not (daily.get("limit") is None or (daily_limit is not None and daily_limit >= 0))):
            raise Unreadable("Unexpected usage response")
        ai = _record(body.get("ai_credits"))
        cap = lambda value: "No cap" if value is None else f"{value:g}"  # noqa: E731
        reading = {"details": [
            {"label": "Monthly plan email usage", "value": f"{used:g} / {cap(limit)} emails"},
            {"label": "Rolling 24-hour email usage", "value": f"{daily_used:g} / {cap(daily_limit)} emails"},
        ] + _amount("AI credits used", ai.get("used"), "credits") + _amount("AI credit limit", ai.get("limit"), "credits")}
        if limit is not None:
            reading["allowance"] = {"used": used, "limit": limit, "unit": "emails", "resetsAt": _timestamp(monthly.get("resets_at"))}
        return reading
    if adapter == "quiver":
        balance, observed = _decimal(body.get("available_credits")), _number(body.get("observed_at"))
        if (balance is None or balance < 0 or balance > 2 ** 53 or observed is None or observed < 0
                or observed > time.time() + 60 or not _text(body.get("organization_id"))):
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "credits", "accountLabel": _text(body.get("organization_id")),
                "observedAt": _iso(observed), "details": _amount("Organization credits across projects", body.get("available_credits"), "credits")}
    raise Unreadable(f"No reader for {adapter}")


# ── asking ──────────────────────────────────────────────────────────────────


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 — a key never follows a redirect
        return None


def fetch_reading(adapter: str, key: str, *, timeout: float = 12.0) -> tuple[int, Any]:
    """(HTTP status, parsed JSON or None). A denial's body is never read: it can echo the credential."""
    url, scheme = REQUESTS[adapter]
    header = {"xi-api-key": key} if scheme == "xi-api-key" else {"Authorization": f"{scheme} {key}"}
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "passbook-balances", **header})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(2_000_000).decode("utf-8"))
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, None


# ── a provider's line ───────────────────────────────────────────────────────


def provider(provider_id: str) -> dict | None:
    return next((entry for entry in PROVIDERS if entry["id"] == provider_id), None)


def top_up_url(entry: Mapping[str, Any]) -> str:
    return str(entry.get("billing_url") or entry.get("console_url") or "")


def _base(entry: Mapping[str, Any], present: set[str], checked_at: str) -> dict:
    names = (*entry.get("keys", ()), *entry.get("reading_keys", ()))
    return {
        "providerId": entry["id"], "name": entry["name"], "category": entry["category"],
        "billing": BILLING_LABELS.get(entry.get("billing", "unknown"), BILLING_LABELS["unknown"]),
        "credentialPresent": any(name in present for name in names), "keyNames": list(names),
        "status": "manual", "checkedAt": checked_at, "observedAt": None, "balance": None, "unit": None,
        "usageUsd": None, "usagePeriod": None, "accountLabel": None, "details": [], "allowance": None,
        "topUpUrl": top_up_url(entry), "paymentNote": entry.get("payment_note", ""),
        "message": entry.get("reading_note") or MANUAL_NOTE,
    }


def fingerprint(salt: bytes, provider_id: str, key: str) -> str:
    """The same while a key is unchanged, different once it is rotated, and nothing about the key itself:
    an HMAC under a random secret that never leaves this machine (`salt_for`)."""
    return hmac.new(salt, f"{provider_id}\0{key}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def salt_for(root: Path) -> bytes:
    path = Path(root) / SALT_FILE
    try:
        salt = bytes.fromhex(path.read_text(encoding="utf-8").strip())
        if len(salt) == 32:
            return salt
    except (OSError, ValueError):
        pass
    salt = secrets.token_bytes(32)
    path.write_text(salt.hex() + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return salt


def read_provider(entry: Mapping[str, Any], values: Mapping[str, str], present: set[str], *,
                  fetch: Callable[[str, str], tuple[int, Any]] = fetch_reading, now: Callable[[], float] = time.time,
                  salt: bytes = b"", fresh_from: Mapping[str, dict] | None = None) -> dict:
    """One provider's reading: ready, error, missing (no key), locked (held but not readable here) or manual."""
    reading = _base(entry, present, _iso(now()))
    adapter = entry.get("adapter")
    if not adapter:
        return reading
    names = tuple(entry.get("reading_keys") or entry.get("keys") or ())
    key_name = next((name for name in names if values.get(name) and not str(values[name]).startswith("hive-sealed:")), None)
    if key_name and fresh_from and salt:
        kept = fresh_from.get(entry["id"])
        if kept and kept.get("connection") == fingerprint(salt, entry["id"], values[key_name]):
            return kept
    if not key_name:
        held = any(name in present for name in names)
        billing = entry.get("billing_key")
        reading.update(status="locked" if held else "missing", message=(
            "The saved key could not be read here. Open the vault and refresh." if held
            else f"Add your {billing['label']} ({billing['key']}) to read the balance. {billing['permission']}" if billing
            else f"Reading the balance needs its own billing key ({', '.join(names)}); an inference key cannot read billing."
            if entry.get("reading_keys") else "No saved key can read this balance."))
        return reading
    # Which key this reading is from, said without the key: its name, and an opaque fingerprint that changes
    # when the key does (`connection`), so a rotated key is never shown the old account's numbers.
    reading.update(keyName=key_name, connection=fingerprint(salt, entry["id"], values[key_name]) if salt else None)
    try:
        status, payload = fetch(adapter, values[key_name])
    except Exception:  # noqa: BLE001 — offline, a timeout, a refused redirect: no balance is assumed
        reading.update(status="error", message="The provider did not answer. Try again; no balance is assumed.")
        return reading
    if status in (401, 403):
        reading.update(status="error", providerError={"httpStatus": status,
                       "category": "authentication-rejected" if status == 401 else "access-denied"},
                       message="The provider rejected the key. Check it and the account on the provider's site." if status == 401
                       else "The provider refused this key billing access. Check its permissions on the provider's site.")
        return reading
    if status >= 400:
        reading.update(status="error", message=f"The provider answered {status}. Try again; no balance is assumed.")
        return reading
    try:
        parsed = parse_reading(adapter, payload)
    except Unreadable:
        reading.update(status="error", message="The provider's answer was not understood; no balance is assumed.")
        return reading
    reading.update(parsed)
    reading.update(status="ready", observedAt=parsed.get("observedAt") or reading["checkedAt"],
                   message=READY_NOTES.get(adapter, READY_NOTE))
    return reading


def wanted_keys(present: Iterable[str], *, everything: bool = False, only: Iterable[str] = ()) -> list[str]:
    """The keys the readers need, among those held: what `run` must open for this."""
    held = set(present)
    chosen = _chosen(held, everything=everything, only=only)
    return sorted({name for entry in chosen if entry.get("adapter")
                   for name in (entry.get("reading_keys") or entry.get("keys") or ()) if name in held})


def _chosen(held: set[str], *, everything: bool, only: Iterable[str]) -> list[dict]:
    asked = {str(name).strip() for name in only if str(name).strip()}
    if asked:
        return [entry for entry in PROVIDERS if entry["id"] in asked]
    if everything:
        return list(PROVIDERS)
    return [entry for entry in PROVIDERS if any(name in held for name in (*entry.get("keys", ()), *entry.get("reading_keys", ())))]


def readings(values: Mapping[str, str], present: Iterable[str], *, everything: bool = False, only: Iterable[str] = (),
             fetch: Callable[[str, str], tuple[int, Any]] = fetch_reading, now: Callable[[], float] = time.time,
             salt: bytes = b"", fresh_from: Mapping[str, dict] | None = None) -> list[dict]:
    """A reading per provider you hold a key for (every provider with `everything`, or the ones named).
    `fresh_from` answers a provider from a recent reading when the same key made it (see `fingerprint`)."""
    held = set(present)
    return [read_provider(entry, values, held, fetch=fetch, now=now, salt=salt, fresh_from=fresh_from)
            for entry in _chosen(held, everything=everything, only=only)]


# ── the opt-in, and the short memory of readings ────────────────────────────


def settings(root: Path) -> dict:
    try:
        loaded = json.loads((Path(root) / SETTINGS_FILE).read_text(encoding="utf-8"))
        return {"enabled": bool(loaded.get("enabled")), "enabledAt": loaded.get("enabledAt")}
    except (OSError, ValueError, AttributeError):
        return {"enabled": False, "enabledAt": None}


def set_enabled(root: Path, enabled: bool, *, now: Callable[[], float] = time.time) -> dict:
    record = {"enabled": bool(enabled), "enabledAt": _iso(now()) if enabled else None}
    path = Path(root) / SETTINGS_FILE
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    if not enabled:
        (Path(root) / CACHE_FILE).unlink(missing_ok=True)
    return record


def cached(root: Path, *, now: Callable[[], float] = time.time) -> dict[str, dict]:
    """Recent live readings by provider, while they are fresh. Numbers only: a reading never holds a key,
    and one is reused only for the same key (`read_provider` compares `connection`)."""
    try:
        loaded = json.loads((Path(root) / CACHE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(loaded, dict) or now() - float(loaded.get("at") or 0) > CACHE_SECONDS:
        return {}
    rows = loaded.get("providers")
    return {row["providerId"]: row for row in rows if isinstance(row, dict) and row.get("status") == "ready"
            and row.get("connection")} if isinstance(rows, list) else {}


def remember(root: Path, rows: list[dict], *, now: Callable[[], float] = time.time) -> None:
    clean = [row for row in rows if row.get("status") == "ready" and row.get("connection")]
    path = Path(root) / CACHE_FILE
    path.write_text(json.dumps({"at": now(), "providers": clean}) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
