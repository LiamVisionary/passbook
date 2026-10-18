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
    {"id": "openrouter", "name": "OpenRouter", "category": "Models", "keys": ('OPENROUTER_API_KEY',), "key_patterns": (r"^OPENROUTER_[A-Z0-9_]*KEY$",), "identify": "openrouter", "reading_keys": ('OPENROUTER_MANAGEMENT_KEY',), "accounts": ({"key": "OPENROUTER_BENCH_API_KEY", "label": "bench key", "adapter": "openrouter-key"},), "billing_key": {"key": "OPENROUTER_BALANCE_KEY", "why": "Only a management key can see the account's credits.", "label": "OpenRouter management key", "permission": "A management key. Inference keys cannot read the account's credits.", "create_url": "https://openrouter.ai/settings/management-keys"}, "billing": "prepaid", "console_url": "https://openrouter.ai", "billing_url": "https://openrouter.ai/settings/credits", "adapter": "openrouter", "docs_url": "https://openrouter.ai/docs/api/api-reference/credits/get-remaining-credits", "verified": "2026-10-02", "payment_note": "Buy credits on OpenRouter. Its former Coinbase Commerce top-up API is deprecated; no payment is made here."},
    {"id": "openai-api", "name": "OpenAI API", "category": "Models", "keys": ('OPENAI_API_KEY',), "key_patterns": (r"^OPENAI_[A-Z0-9_]*API_KEY[A-Z0-9_]*$",), "reading_keys": (), "refusal_is_permission": True, "adapter": "openai-costs", "billing": "mixed", "billing_key": {"key": "OPENAI_BALANCE_KEY", "why": "OpenAI shows spend only to organization Admin keys.", "label": "OpenAI admin key", "permission": "An organization Admin key (made by an organization owner). OpenAI reports spend to it, not the credit left: no key can read the prepaid balance.", "create_url": "https://platform.openai.com/settings/organization/admin-keys"}, "console_url": "https://platform.openai.com", "billing_url": "https://platform.openai.com/settings/organization/billing/overview", "docs_url": "https://platform.openai.com/docs/api-reference/usage/costs", "verified": "2026-10-18", "payment_note": "API billing is separate from ChatGPT subscriptions. Purchase credits on the OpenAI billing page."},
    {"id": "anthropic", "name": "Anthropic API", "category": "Models", "keys": ('ANTHROPIC_API_KEY',), "key_patterns": (r"^(ANTHROPIC|CLAUDE)_[A-Z0-9_]*API_KEY[A-Z0-9_]*$",), "identify": "anthropic", "try_each": True, "refusal_is_permission": True, "adapter": "anthropic-costs", "billing": "mixed", "billing_key": {"key": "ANTHROPIC_BALANCE_KEY", "why": "Anthropic shows spend only to an Admin key, or an organization key allowed to read cost.", "label": "Anthropic Admin API key", "permission": "An Admin API key (sk-ant-admin…), or an organization-scoped key with permission to read usage and cost, made in this organization. Anthropic reports spend to it, not the credit left.", "create_url": "https://platform.claude.com/settings/admin-keys"}, "console_url": "https://platform.claude.com", "billing_url": "https://platform.claude.com/settings/billing", "docs_url": "https://platform.claude.com/docs/en/api/admin-api/usage-cost/get-cost-report", "verified": "2026-10-18", "payment_note": "API billing is separate from Claude subscriptions. Confirm your account’s billing model on the billing page."},
    {"id": "xai", "name": "xAI API", "category": "Models", "keys": ('XAI_API_KEY',), "billing": "mixed", "console_url": "https://console.x.ai", "docs_url": "https://docs.x.ai/developers/rest-api-reference/management/billing", "verified": "2026-10-02", "payment_note": "xAI documents a top-up API requiring a management key and team. In-app charging stays unavailable until payment identity and duplicate-charge reconciliation are verified. Use the console for now.", "reading_note": "xAI reports the prepaid balance only to a management key (Console → Settings → Management keys) together with your team id; PassBook does not read it yet. Check it on the console."},
    {"id": "fal", "name": "fal", "category": "Media", "keys": ('FAL_KEY',), "reading_keys": ('FAL_ADMIN_KEY', 'FAL_KEY'), "accounts": ({"key": "FAL_KEY_BACKUP", "label": "backup key"},), "billing_key": {"key": "FAL_BALANCE_KEY", "why": "Only a key with billing read access (the Billing preset) can see it.", "label": "fal Admin key", "permission": "A key with the Billing or Read-only preset (it carries billing:usage:read), or a legacy ADMIN key. API keys run models but cannot read billing.", "create_url": "https://fal.ai/dashboard/keys"}, "billing": "prepaid", "console_url": "https://fal.ai/dashboard", "billing_url": "https://fal.ai/dashboard/usage-billing/billing", "adapter": "fal", "docs_url": "https://fal.ai/docs/platform-apis/v1/account/billing", "verified": "2026-10-02", "payment_note": "A billing read requires an Admin key. An existing FAL_KEY is tried read-only; the provider enforces its permissions. Complete purchases on fal’s billing page."},
    {"id": "meshy", "name": "Meshy", "category": "Media", "keys": ('MESHY_API_KEY', 'MESHY_AMI_API_KEY'), "billing": "mixed", "console_url": "https://www.meshy.ai/workspace", "adapter": "meshy", "docs_url": "https://docs.meshy.ai/en/api/balance", "verified": "2026-10-02", "payment_note": "Meshy reports credits, not dollars. Subscription credits and API purchases must be checked on the provider’s site."},
    {"id": "vast", "name": "Vast.ai", "category": "Cloud", "keys": ('VAST_API_KEY', 'VASTAI_API_KEY'), "billing": "prepaid", "console_url": "https://console.vast.ai", "adapter": "vast", "docs_url": "https://docs.vast.ai/api-reference/accounts/show-user", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "apify", "name": "Apify", "category": "Research", "keys": ('APIFY_TOKEN', 'APIFY_API_KEY', 'APIFY_API_TOKEN'), "billing": "mixed", "console_url": "https://console.apify.com", "billing_url": "https://console.apify.com/billing", "adapter": "apify", "docs_url": "https://docs.apify.com/api/v2/users-me-usage-monthly-get", "verified": "2026-10-02", "payment_note": "The live reading is monthly usage, not a remaining credit balance. Manage the plan and spending limits on Apify."},
    {"id": "runware", "name": "Runware", "category": "Media", "keys": ('RUNWARE_API_KEY', 'RUNWARE_API_KEY_HIVEMINDOS'), "billing": "prepaid", "console_url": "https://my.runware.ai", "adapter": "runware", "docs_url": "https://runware.ai/docs/models-api/account-management", "verified": "2026-10-18", "payment_note": "Top up inference credits on the Runware dashboard. Serverless credit is a separate pool; no balance conversion is assumed."},
    {"id": "tripo", "name": "Tripo API", "category": "Media", "keys": ('TRIPO_API_KEY', 'TRIPO_AMI_API_KEY'), "billing": "prepaid", "adapter": "tripo", "billing_url": "https://platform.tripo3d.ai/billing", "console_url": "https://platform.tripo3d.ai", "docs_url": "https://docs.tripo3d.ai/other/wallet.html", "verified": "2026-10-18", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "ideogram", "name": "Ideogram", "category": "Media", "keys": ('IDEOGRAM_API_KEY', 'IDEOGRAM_API_KEY_HIVEMIND_OS'), "billing": "prepaid", "console_url": "https://ideogram.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "kie", "name": "KIE", "category": "Media", "keys": ('KIE_API_KEY', 'KIE_API_KEY_HIVEMINDOS'), "billing": "prepaid", "console_url": "https://kie.ai", "billing_url": "https://kie.ai/billing", "adapter": "kie", "docs_url": "https://docs.kie.ai/common-api/get-account-credits", "verified": "2026-10-18", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "icypeas", "name": "Icypeas", "category": "Research", "keys": ('ICYPEAS_API_KEY',), "billing": "mixed", "console_url": "https://app.icypeas.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "kinovi", "name": "Kinovi", "category": "Media", "keys": ('KINOVI_API_KEY',), "billing": "prepaid", "console_url": "https://kinovi.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "alchemy", "name": "Alchemy", "category": "Developer tools", "keys": ('ALCHEMY_API_KEY',), "billing": "unknown", "console_url": "https://dashboard.alchemy.com", "docs_url": "https://www.alchemy.com/docs/admin-api/usage/get-usage-summary", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Usage reporting requires an Alchemy admin key with usage-read permission. Your saved RPC key alone does not establish billing access."},
    {"id": "ngrok", "name": "ngrok", "category": "Developer tools", "keys": ('NGROK_API_KEY', 'NGROK_AUTHTOKEN'), "billing": "unknown", "console_url": "https://dashboard.ngrok.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "vercel", "name": "Vercel", "category": "Cloud", "keys": ('VERCEL_TOKEN', 'VERCEL_OIDC_TOKEN'), "billing": "unknown", "console_url": "https://vercel.com/dashboard", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "vultr", "name": "Vultr", "category": "Cloud", "keys": ('VULTR_API_KEY',), "billing_key": {"key": "VULTR_BALANCE_KEY", "why": "Any Vultr API key that allows this computer's address.", "label": "Vultr API key", "permission": "Any Vultr API key. Vultr keys only work from the addresses on their Access Control list, so allow this computer's address (or all IPv4) for it.", "create_url": "https://my.vultr.com/settings/#settingsapi"}, "billing": "postpaid", "console_url": "https://my.vultr.com", "adapter": "vultr", "docs_url": "https://github.com/vultr/govultr/blob/master/account.go", "verified": "2026-10-02", "payment_note": "Account balance and pending charges are shown as reported. Their signs are not interpreted as spendable funds. Complete payments on Vultr."},
    {"id": "composio", "name": "Composio", "category": "Developer tools", "keys": ('COMPOSIO_API_KEY', 'COMPOSIO_API_KEY_HIVEMINDOS', 'COMPOSIO_API_KEY_HIVEMINDOS_FULL'), "billing": "unknown", "console_url": "https://platform.composio.dev", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "google-cloud", "name": "Google Cloud", "category": "Cloud", "billing": "unknown", "console_url": "https://console.cloud.google.com/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "cloudflare", "name": "Cloudflare", "category": "Cloud", "keys": ('CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_INFRA_ADMIN_API_KEY', 'CLOUDFLARE_PAGES_API_TOKEN'), "billing": "unknown", "console_url": "https://dash.cloudflare.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "supabase", "name": "Supabase", "category": "Cloud", "keys": ('SUPABASE_ACCESS_TOKEN',), "billing": "unknown", "console_url": "https://supabase.com/dashboard", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "github", "name": "GitHub", "category": "Developer tools", "keys": ('GITHUB_TOKEN', 'GH_TOKEN', 'GH_GLOBAL'), "billing": "unknown", "console_url": "https://github.com/settings/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "resend", "name": "Resend", "category": "Developer tools", "keys": ('RESEND_API_KEY',), "billing": "mixed", "console_url": "https://resend.com", "adapter": "resend", "docs_url": "https://resend.com/docs/api-reference/usage/retrieve-usage", "verified": "2026-10-02", "payment_note": "Email and other allowances are usage limits, not cash. Review your plan and billing on Resend."},
    {"id": "hetzner", "name": "Hetzner", "category": "Cloud", "keys": ('HETZNER_API_TOKEN', 'HCLOUD_TOKEN', 'HETZNER_COUSIN_API_KEY'), "billing": "postpaid", "console_url": "https://console.hetzner.cloud", "docs_url": "https://docs.hetzner.com/cloud/billing/faq/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Resource prices can support an estimate, but they do not report your invoice or account balance. Review Hetzner billing."},
    {"id": "agentmail", "name": "AgentMail", "category": "Developer tools", "keys": ('AGENTMAIL_API_KEY',), "billing": "unknown", "console_url": "https://console.agentmail.to", "adapter": "agentmail", "docs_url": "https://docs.agentmail.to/api-reference/organizations/get", "verified": "2026-10-02", "payment_note": "The organization endpoint reports connected inboxes and domains, not a monetary balance. Review your plan and payment on AgentMail."},
    {"id": "scrapecreators", "name": "Scrape Creators", "category": "Research", "keys": ('SCRAPECREATORS_API_KEY', 'SCRAPE_CREATORS_API_KEY'), "billing": "prepaid", "console_url": "https://scrapecreators.com", "docs_url": "https://docs.scrapecreators.com/v1/account/credit-balance/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "Checking this balance costs one provider credit. Automatic reads are disabled; review the balance on Scrape Creators."},
    {"id": "resemble", "name": "Resemble AI", "category": "Media", "keys": ('RESEMBLE_API_KEY',), "billing": "unknown", "console_url": "https://app.resemble.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "quiver", "name": "QuiverAI", "category": "Media", "keys": ('QUIVER_API_KEY', 'QUIVERAI_API_KEY'), "reading_keys": ('QUIVER_BILLING_ADMIN_KEY',), "billing": "prepaid", "console_url": "https://quiver.ai", "adapter": "quiver", "docs_url": "https://docs.quiver.ai/api-reference/organization/get-organization-balance", "verified": "2026-10-02", "payment_note": "Balance reporting uses a separate existing organization Admin key with billing-read permission. Your inference key stays separate. Credits cover the organization across projects. Purchase credits on QuiverAI.", "billing_key": {"key": "QUIVER_BILLING_ADMIN_KEY", "why": "Only an organization Admin key can see billing.", "label": "QuiverAI organization billing key", "permission": "An existing organization Admin key with billing-read permission. Project keys cannot read organization billing; Admin keys cannot run inference."}},
    {"id": "nansen", "name": "Nansen", "category": "Research", "keys": ('NANSEN_API_KEY',), "billing": "unknown", "console_url": "https://app.nansen.ai", "docs_url": "https://docs.nansen.ai/getting-started/credits", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated.", "reading_note": "A supported credit-balance endpoint has not been verified. Review your credit balance on the Nansen dashboard."},
    {"id": "vadoo", "name": "Vadoo", "category": "Media", "keys": ('VADOO_API_KEY',), "billing": "unknown", "console_url": "https://www.vadoo.tv", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "termly", "name": "Termly", "category": "Developer tools", "billing": "unknown", "console_url": "https://app.termly.io", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "apple-developer", "name": "Apple Developer", "category": "Developer tools", "billing": "unknown", "console_url": "https://developer.apple.com/account", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "chatgpt", "name": "ChatGPT subscription", "category": "Models", "billing": "unknown", "console_url": "https://chatgpt.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "claude-plan", "name": "Claude subscription", "category": "Models", "billing": "unknown", "console_url": "https://claude.ai", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "elevenlabs", "name": "ElevenLabs", "category": "Media", "keys": ('ELEVENLABS_API_KEY',), "billing": "mixed", "console_url": "https://elevenlabs.io/app", "adapter": "elevenlabs", "docs_url": "https://elevenlabs.io/docs/api-reference/user/subscription/get", "verified": "2026-10-02", "payment_note": "Plan allowance, usage, overage and the next invoice are distinct from a cash balance. Review your plan or additional credits on ElevenLabs."},
    {"id": "muapi", "name": "Muapi", "category": "Media", "keys": ('MUAPI_API_KEY',), "billing": "mixed", "console_url": "https://muapi.ai", "billing_url": "https://muapi.ai/topup", "adapter": "muapi", "docs_url": "https://muapi.ai/docs/credits", "verified": "2026-10-18", "payment_note": "Buy credits on Muapi’s official billing page. Check whether the selected plan includes credits before purchasing more."},
    {"id": "supergrok", "name": "SuperGrok subscription", "category": "Models", "billing": "unknown", "console_url": "https://grok.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "codex-credits", "name": "Codex / Work credits", "category": "Models", "billing": "unknown", "console_url": "https://chatgpt.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "azure", "name": "Microsoft Azure", "category": "Cloud", "billing": "unknown", "console_url": "https://portal.azure.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "render", "name": "Render", "category": "Cloud", "keys": ('RENDER_API_KEY', 'RENDER_MANAGEMENT_KEY'), "billing": "unknown", "console_url": "https://dashboard.render.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "huggingface", "name": "Hugging Face", "category": "Models", "keys": ('HF_TOKEN', 'HUGGING_FACE_HUB_TOKEN', 'HUGGINGFACE_READ_WRITE_KEY'), "billing": "unknown", "console_url": "https://huggingface.co/settings/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "colab", "name": "Google Colab", "category": "Cloud", "billing": "unknown", "console_url": "https://colab.research.google.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "aws", "name": "Amazon Web Services", "category": "Cloud", "billing": "unknown", "console_url": "https://console.aws.amazon.com/billing", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "obsidian-sync", "name": "Obsidian Sync", "category": "Developer tools", "billing": "unknown", "console_url": "https://obsidian.md/account", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "google-one", "name": "Google One / AI plan", "category": "Models", "billing": "unknown", "console_url": "https://one.google.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "streamoji", "name": "Streamoji Avatars", "category": "Media", "billing": "unknown", "console_url": "https://streamoji.com", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "universal-sign-in", "name": "Universal Sign In", "category": "Developer tools", "billing": "unknown", "console_url": "https://universal-sign-in.com/auth/login", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "deepseek", "name": "DeepSeek", "category": "Models", "keys": ('DEEPSEEK_API_KEY',), "billing": "prepaid", "console_url": "https://platform.deepseek.com", "adapter": "deepseek", "docs_url": "https://api-docs.deepseek.com/api/get-user-balance/", "verified": "2026-10-02", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
    {"id": "bankr", "name": "Bankr LLM", "category": "Models", "keys": ('BANKR_LLM_KEY',), "reading_keys": ('BANKR_MANAGEMENT_API_KEY', 'BANKR_MANAGEMENT_KEY', 'BANKR_LLM_KEY'), "billing": "prepaid", "console_url": "https://bankr.bot", "billing_url": "https://bankr.bot/terminal/llm", "adapter": "bankr", "docs_url": "https://docs.bankr.bot/llm-gateway/api-reference/", "verified": "2026-10-18", "payment_note": "The available balance covers this wallet across its API keys and includes pending usage. Daily spending limits are separate. Complete purchases on Bankr."},
    {"id": "venice", "name": "Venice AI", "category": "Models", "keys": ('VENICE_API_KEY',), "billing": "mixed", "console_url": "https://venice.ai", "adapter": "venice", "docs_url": "https://docs.venice.ai/api-reference/endpoint/api_keys/rate_limits", "verified": "2026-10-18", "payment_note": "USD funds and DIEM allowance are shown separately. DIEM is not added to your dollar balance. Manage payments on Venice."},
    {"id": "usepod", "name": "UsePod", "category": "Models", "keys": ('USEPOD_TOKEN',), "billing": "prepaid", "console_url": "https://usepod.com", "docs_url": "https://docs.usepod.ai/using/funding/", "verified": "2026-10-02", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding.", "reading_note": "UsePod reports balance with paid responses. This dashboard does not spend money to obtain a balance; review your funding page."},
    {"id": "groq", "name": "Groq", "category": "Models", "keys": ('GROQ_API_KEY',), "billing": "unknown", "console_url": "https://console.groq.com", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "dot", "name": "Dot", "category": "Models", "keys": ('DOT_API_KEY',), "billing": "unknown", "console_url": "https://usedot.xyz", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "engy", "name": "engy", "category": "Models", "keys": ('ENGYAI_API_KEY',), "billing": "unknown", "console_url": "https://engy.ai", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "nearai", "name": "NEAR AI", "category": "Models", "keys": ('NEAR_AI_API_KEY',), "billing": "unknown", "console_url": "https://cloud.near.ai", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "gemini", "name": "Gemini", "category": "Models", "keys": ('GEMINI_API_KEY', 'GOOGLE_AI_STUDIO_API_KEY'), "billing": "unknown", "console_url": "https://aistudio.google.com", "payment_note": "Billing coverage is not integrated. Check this provider’s account and payment options before funding."},
    {"id": "runpod", "name": "RunPod", "category": "Cloud", "keys": ('RUNPOD_API_KEY', 'RUNPOD_MANAGEMENT_API_KEY'), "accounts": ({"key": "RUNPOD_SECOND_MANAGEMENT_API_KEY", "label": "second account"},), "billing": "prepaid", "console_url": "https://console.runpod.io", "billing_url": "https://console.runpod.io/user/billing", "adapter": "runpod", "docs_url": "https://docs.runpod.io/sdks/graphql/manage-pods", "verified": "2026-10-18", "payment_note": "Add funds on RunPod's billing page. PassBook only reads the balance."},
    {"id": "stripe", "name": "Stripe", "category": "Money", "keys": ('STRIPE_SECRET_KEY', 'STRIPE_MANAGEMENT_API_KEY', 'PORTFOLIO_STRIPE_SECRET_KEY'), "billing": "unknown", "console_url": "https://dashboard.stripe.com", "billing_url": "https://dashboard.stripe.com/balance", "adapter": "stripe", "docs_url": "https://docs.stripe.com/api/balance/balance_retrieve", "verified": "2026-10-18", "payment_note": "This is money Stripe holds for you (sales not yet paid out), not credit to spend. Payouts happen on Stripe.", "billing_key": {"key": "STRIPE_BALANCE_KEY", "why": "A restricted key with Balance: Read is enough.", "label": "Stripe restricted key", "permission": "A restricted key with Balance: Read and nothing else.", "create_url": "https://dashboard.stripe.com/apikeys"}},
    {"id": "alpaca", "name": "Alpaca", "category": "Money", "keys": ('ALPACA_API_SECRET_KEY',), "pairs": {"ALPACA_API_SECRET_KEY": "ALPACA_API_KEY_ID"}, "billing": "unknown", "console_url": "https://app.alpaca.markets", "billing_url": "https://app.alpaca.markets/brokerage/banking", "adapter": "alpaca", "docs_url": "https://docs.alpaca.markets/reference/getaccount-1", "verified": "2026-10-18", "payment_note": "A brokerage account: cash and holdings move with the market, so they are shown as reported and never counted as spend. Deposits happen on Alpaca."},
    {"id": "bfl", "name": "Black Forest Labs", "category": "Media", "keys": ('BFL_API_KEY', 'BLACK_FOREST_LABS_API_KEY'), "billing": "prepaid", "console_url": "https://dashboard.bfl.ai", "billing_url": "https://dashboard.bfl.ai", "adapter": "bfl", "docs_url": "https://docs.bfl.ml/api-reference/get-the-users-credits", "verified": "2026-10-18", "payment_note": "Buy credits on the BFL dashboard. PassBook only reads the balance."},
    {"id": "fish", "name": "Fish Audio", "category": "Media", "keys": ('FISH_AUDIO_API_KEY',), "billing": "prepaid", "console_url": "https://fish.audio", "billing_url": "https://fish.audio/app/billing/", "adapter": "fish", "docs_url": "https://docs.fish.audio/api-reference/openapi.json", "verified": "2026-10-18", "payment_note": "Top up API credit on Fish Audio. Its API reports the credit without a unit; it is bought in dollars, so it is shown as dollars. PassBook only reads the balance."},
    {"id": "browser-use", "name": "Browser Use", "category": "Developer tools", "keys": ('BROWSER_USE_API_KEY', 'BROWSER_USE_API_KEY_HIVEMIND_OS'), "billing": "prepaid", "console_url": "https://cloud.browser-use.com", "billing_url": "https://cloud.browser-use.com/billing", "adapter": "browser-use", "docs_url": "https://docs.browser-use.com/cloud/api-v2/billing/get-account-billing", "verified": "2026-10-18", "payment_note": "Buy credits on Browser Use. PassBook only reads the balance."},
    {"id": "bankr-wallet", "name": "Bankr wallets", "category": "Money", "keys": ('BANKR_MANAGEMENT_API_KEY', 'BANKR_MANAGEMENT_KEY'), "billing": "unknown", "console_url": "https://bankr.bot", "billing_url": "https://bankr.bot/terminal", "adapter": "bankr-wallet", "docs_url": "https://docs.bankr.bot/docs/wallet-api/portfolio", "verified": "2026-10-18", "payment_note": "Tokens on your Bankr wallets, valued in dollars by Bankr. Prices move, so the value is shown as reported and never counted as spend."},
    {"id": "modal", "name": "Modal", "category": "Cloud", "keys": ('MODAL_TOKEN_SECRET', 'MODAL_TOKEN_SECRET_HIVEMIND_OS'), "billing": "postpaid", "console_url": "https://modal.com/settings/usage", "payment_note": "Review billing and complete any payment on the provider’s site. In-app payment is not integrated."},
)

# Where each reader asks, and how it says who it is: `Bearer` and `Key` go in Authorization, `alpaca` is
# its id-and-secret pair, anything else is the header's own name. A third item is a JSON body (a POST).
# `{month_start}` and `{month_start_iso}` are the first of this month, UTC. The documented Vast endpoint
# redirects to this trailing-slash address; asking it directly means the key never follows a redirect.
RUNPOD_QUERY = {"query": "query { myself { clientBalance currentSpendPerHr spendLimit } }"}
REQUESTS: dict[str, tuple] = {
    "openrouter": ("https://openrouter.ai/api/v1/credits", "Bearer"),
    "fal": ("https://api.fal.ai/v1/account/billing?expand=credits", "Key"),
    "meshy": ("https://api.meshy.ai/openapi/v1/balance", "Bearer"),
    "vast": ("https://console.vast.ai/api/v0/users/current/", "Bearer"),
    "apify": ("https://api.apify.com/v2/users/me/usage/monthly", "Bearer"),
    "deepseek": ("https://api.deepseek.com/user/balance", "Bearer"),
    # The per-key rate-limits answer carries the account's balances and is open to an inference key;
    # /billing/balance answers 401 to one (probed 2026-10-18).
    "venice": ("https://api.venice.ai/api/v1/api_keys/rate_limits", "Bearer"),
    "bankr": ("https://llm.bankr.bot/v1/credits", "X-API-Key"),
    "elevenlabs": ("https://api.elevenlabs.io/v1/user/subscription", "xi-api-key"),
    "agentmail": ("https://api.agentmail.to/v0/organizations", "Bearer"),
    "vultr": ("https://api.vultr.com/v2/account", "Bearer"),
    "resend": ("https://api.resend.com/usage", "Bearer"),
    "quiver": ("https://api.quiver.ai/v1/organization/balance", "Bearer"),
    "openrouter-key": ("https://openrouter.ai/api/v1/key", "Bearer"),
    "runpod": ("https://api.runpod.io/graphql", "Bearer", RUNPOD_QUERY),
    "stripe": ("https://api.stripe.com/v1/balance", "Bearer"),
    "runware": ("https://api.runware.ai/v1", "Bearer", [{"taskType": "accountManagement", "operation": "getDetails",
                                                          "taskUUID": "6f1d2b1e-5a0c-4b7e-9c55-2f7a1d3e9b40"}]),
    "muapi": ("https://api.muapi.ai/api/v1/account/balance", "x-api-key"),
    "bankr-wallet": ("https://api.bankr.bot/wallet/portfolio", "X-API-Key"),
    "alpaca": ("https://api.alpaca.markets/v2/account", "alpaca"),
    "kie": ("https://api.kie.ai/api/v1/chat/credit", "Bearer"),
    "tripo": ("https://api.tripo3d.ai/v2/openapi/user/balance", "Bearer"),
    "bfl": ("https://api.bfl.ai/v1/credits", "x-key"),
    "fish": ("https://api.fish.audio/wallet/self/api-credit", "Bearer"),
    "browser-use": ("https://api.browser-use.com/api/v2/billing/account", "X-Browser-Use-API-Key"),
    "openai-costs": ("https://api.openai.com/v1/organization/costs?start_time={month_start}&bucket_width=1d&limit=31", "Bearer"),
    "anthropic-costs": ("https://api.anthropic.com/v1/organizations/cost_report?starting_at={month_start_iso}&bucket_width=1d&limit=31", "x-api-key"),
}

# Which account a key belongs to, for a provider that will say so to any key. Keys of one account are one
# row; keys of different accounts are different rows, each with its own balance-only key. Anthropic answers
# `/v1/organizations/me` to an ordinary key with the organization's id and name (seen live on six keys,
# 2026-10-18, though the docs file it under the Admin API); OpenRouter's `/api/v1/key` names the workspace.
IDENTIFY: dict[str, tuple[str, str]] = {
    "anthropic": ("https://api.anthropic.com/v1/organizations/me", "x-api-key"),
    "openrouter": ("https://openrouter.ai/api/v1/key", "Bearer"),
}
IDENTITY_FILE = "balances-identities.json"
IDENTITY_SECONDS = 7 * 86400


def parse_identity(kind: str, payload: Any) -> dict | None:
    """{"id", "name"} of the account a key belongs to, or None when the answer does not say."""
    body = _record(payload)
    if kind == "anthropic":
        found = {"id": _text(body.get("id")), "name": _text(body.get("name"))}
    elif kind == "openrouter":
        data = _record(body.get("data"))
        found = {"id": _text(data.get("workspace_id")) or _text(data.get("organization_id")) or _text(data.get("creator_user_id")),
                 "name": None}
    else:
        return None
    return found if found["id"] else None


def fetch_identity(kind: str, key: str, *, timeout: float = 12.0) -> tuple[int, Any]:
    url, scheme = IDENTIFY[kind]
    return _get(url, scheme, key, timeout, 200_000)


# What a ready reading means, said once per kind: the reading is never more than the provider reported.
READY_NOTES = {
    "apify": "Provider-reported usage. Remaining credits are not reported here.",
    "elevenlabs": "Plan allowance and invoices are not a cash balance.",
    "resend": "Plan usage and allowances are not a cash balance. An uncapped daily allowance does not remove your monthly plan limit.",
    "agentmail": "Organization counts and limits are not a cash balance.",
    "vultr": "Accounting amounts are shown as reported, without assuming spendable funds or combining pending charges.",
    "openrouter-key": "This key's own spending limit, not the account's credits.",
    "stripe": "Money Stripe holds for you, not credit to spend.",
    "venice": "What this key can spend: the account's balance, capped by any limit on the key.",
    "bankr-wallet": "Token value as Bankr prices it; prices move, so it is not counted as spend.",
    "alpaca": "Brokerage cash and holdings as reported; market moves are not spend.",
    "openai-costs": "Spend this month so far. OpenAI does not report the credit left to any key.",
    "anthropic-costs": "Spend this month so far. Anthropic does not report the credit left to any key.",
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
        # The rate-limits answer (`data.balances`, upper-case) or the billing one (`balances`, lower-case).
        balances = _record(data.get("balances")) or _record(body.get("balances"))
        pick = lambda *names: next((balances[name] for name in names if name in balances), None)  # noqa: E731
        balance = _number(pick("usd", "USD"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "USD", "details": (
            _amount("DIEM allowance remaining", pick("diem", "DIEM"), "DIEM")
            + _amount("DIEM epoch allocation", body.get("diemEpochAllocation"), "DIEM")
            + _amount("Bundled credits", pick("bundledCredits", "BUNDLED_CREDITS"), "credits")
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
    if adapter == "openrouter-key":
        limit, left = _number(data.get("limit")), _number(data.get("limit_remaining"))
        month = _number(data.get("usage_monthly"))
        if month is None or (limit is not None and left is None):
            raise Unreadable("Unexpected key response")
        reading = {"usageUsd": month, "usagePeriod": "This month, this key", "details": (
            _amount("This key's spend, all time", data.get("usage"), "USD") + _amount("Today", data.get("usage_daily"), "USD"))}
        if limit is not None:
            budget = _record(data.get("effective_budget"))
            reading["allowance"] = {"used": round(limit - left, 6), "limit": limit, "unit": "USD",
                                    "resetsAt": _timestamp(budget.get("resets_at"))}
        else:
            reading["details"].insert(0, {"label": "Spending limit", "value": "None on this key"})
        return reading
    if adapter == "runpod":
        me = _record(data.get("myself"))
        balance = _number(me.get("clientBalance"))
        if balance is None or body.get("errors"):
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "USD", "details": (
            _amount("Spending now, per hour", me.get("currentSpendPerHr"), "USD")
            + _amount("Spend limit", me.get("spendLimit"), "USD"))}
    if adapter == "stripe":
        available, pending = body.get("available"), body.get("pending")
        if not isinstance(available, list) or not isinstance(pending, list) or not isinstance(body.get("livemode"), bool):
            raise Unreadable("Unexpected balance response")
        def money(label: str, rows: list) -> list[dict]:
            return [item for row in map(_record, rows) if _currency(row.get("currency")) and _number(row.get("amount")) is not None
                    for item in _amount(label, row["amount"] / 100, _currency(row["currency"]))]
        # Money held for you, not credit to spend: figures only, so it is never taken for spend or a top-up.
        return {"details": money("Available", available) + money("Pending", pending)
                + [{"label": "Mode", "value": "Live" if body["livemode"] else "Test"}]}
    if adapter == "alpaca":
        cash, equity = _decimal(body.get("cash")), _decimal(body.get("equity"))
        if cash is None or equity is None or not _currency(body.get("currency")):
            raise Unreadable("Unexpected account response")
        unit = _currency(body.get("currency"))
        # Holdings move with the market: shown as reported, never a balance whose fall is spend.
        return {"details": _amount("Account value", body.get("equity"), unit) + _amount("Cash", body.get("cash"), unit)
                + _amount("Buying power", body.get("buying_power"), unit)
                + ([{"label": "Status", "value": _text(body.get("status"))}] if _text(body.get("status")) else [])}
    if adapter == "runware":
        # The answer also lists the account's API keys: only the balance and the organization's name are kept.
        first = _record((body.get("data") or [None])[0] if isinstance(body.get("data"), list) else None)
        balance = _number(first.get("balance"))
        if balance is None:
            raise Unreadable("Unexpected account response")
        return {"balance": balance, "unit": "USD", "accountLabel": _text(first.get("organizationName"))}
    if adapter == "muapi":
        balance, unit = _number(body.get("balance")), _currency(body.get("currency") or "USD")
        if balance is None or not unit:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": unit}
    if adapter == "bankr-wallet":
        chains = _record(body.get("balances"))
        totals = {name: _decimal(_record(chain).get("total")) for name, chain in chains.items()}
        if body.get("success") is not True or not chains or any(value is None for value in totals.values()):
            raise Unreadable("Unexpected portfolio response")
        held = sorted(((value, name) for name, value in totals.items() if value), reverse=True)
        # Prices move: shown as reported, so a falling token is never read as spend.
        return {"details": [{"label": "Wallet value", "value": f"{round(sum(totals.values()), 2):g} USD"}]
                + [{"label": f"On {name}", "value": f"{round(value, 2):g} USD"} for value, name in held]}
    if adapter == "kie":
        balance = _number(body.get("data"))
        if body.get("code") != 200 or balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "credits"}
    if adapter == "tripo":
        balance = _number(data.get("balance"))
        if body.get("code") != 0 or balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "credits", "details": _amount("Held for running tasks", data.get("frozen"), "credits")}
    if adapter == "bfl":
        balance = _number(body.get("credits"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "credits"}
    if adapter == "fish":
        balance = _decimal(body.get("credit"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        return {"balance": balance, "unit": "USD", "details": _amount("Topped up, all time", body.get("cumulative_top_up"), "USD")}
    if adapter == "browser-use":
        balance = _number(body.get("totalCreditsBalanceUsd"))
        if balance is None:
            raise Unreadable("Unexpected balance response")
        plan = _record(body.get("planInfo"))
        return {"balance": balance, "unit": "USD", "details": (
            _amount("Monthly plan credits", body.get("monthlyCreditsBalanceUsd"), "USD")
            + _amount("Bought credits", body.get("additionalCreditsBalanceUsd"), "USD")
            + ([{"label": "Plan", "value": _text(plan.get("planName"))}] if _text(plan.get("planName")) else []))}
    if adapter in ("openai-costs", "anthropic-costs"):
        buckets = body.get("data")
        if not isinstance(buckets, list):
            raise Unreadable("Unexpected cost response")
        total = 0.0
        for bucket in map(_record, buckets):
            for result in map(_record, bucket.get("results") or []):
                amount = result.get("amount")
                # OpenAI: {"value": dollars, "currency": "usd"}. Anthropic: a decimal string of cents.
                value = _number(_record(amount).get("value")) if adapter == "openai-costs" else _decimal(amount)
                currency = str(_record(amount).get("currency") or "usd") if adapter == "openai-costs" else str(result.get("currency") or "USD")
                if value is None or currency.upper() != "USD":
                    raise Unreadable("Unexpected cost response")
                total += value if adapter == "openai-costs" else value / 100
        if body.get("has_more"):
            raise Unreadable("More cost pages than one month holds")
        return {"usageUsd": round(total, 4), "usagePeriod": "This month so far"}
    raise Unreadable(f"No reader for {adapter}")


# ── asking ──────────────────────────────────────────────────────────────────


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 — a key never follows a redirect
        return None


def _headers(scheme: str, key: str, url: str) -> dict[str, str]:
    if scheme in ("Bearer", "Key"):
        return {"Authorization": f"{scheme} {key}"}
    if scheme == "alpaca":
        # A pair: the key id and its secret, joined by a newline in `read_provider`.
        key_id, _, secret = key.partition("\n")
        return {"APCA-API-KEY-ID": key_id, "APCA-API-SECRET-KEY": secret}
    extra = {"anthropic-version": "2023-06-01"} if url.startswith("https://api.anthropic.com/") else {}
    return {scheme: key, **extra}


def _month_start(now: float) -> datetime:
    today = datetime.fromtimestamp(now, timezone.utc)
    return today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _get(url: str, scheme: str, key: str, timeout: float, limit: int, body: Any = None) -> tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers={
        "Accept": "application/json", "User-Agent": "passbook-balances", **_headers(scheme, key, url),
        **({"Content-Type": "application/json"} if data else {})})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(limit).decode("utf-8"))
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, None


def fetch_reading(adapter: str, key: str, *, timeout: float = 12.0) -> tuple[int, Any]:
    """(HTTP status, parsed JSON or None). A denial's body is never read: it can echo the credential."""
    url, scheme, *body = REQUESTS[adapter]
    start = _month_start(time.time())
    url = url.replace("{month_start}", str(int(start.timestamp()))).replace(
        "{month_start_iso}", start.isoformat().replace("+00:00", "Z"))
    return _get(url, scheme, key, timeout, 2_000_000, body[0] if body else None)


# ── a provider's own daily spend ────────────────────────────────────────────
#
# Spend per day is otherwise pieced together from how the readings moved (passbook_insights.py), which
# starts the day Balances was turned on. A provider that reports its own daily figures gives real history
# at once, and exact days after. OpenRouter does: a row per day, model and provider for the last 31
# finished days, to the management key that reads its credits. Read-only, like every other request here.

DAILY_REQUESTS: dict[str, tuple[str, str]] = {
    "openrouter": ("https://openrouter.ai/api/v1/activity", "Bearer"),
}
DAILY_SECONDS = 6 * 3600


def parse_daily(adapter: str, payload: Any) -> dict[str, float]:
    """{YYYY-MM-DD: dollars spent that day}. Raises Unreadable on an answer it does not understand."""
    if adapter == "openrouter":
        rows = _record(payload).get("data")
        if not isinstance(rows, list):
            raise Unreadable("Unexpected activity response")
        days: dict[str, float] = {}
        for row in map(_record, rows):
            date, spent = str(row.get("date") or "")[:10], _number(row.get("usage"))
            if _timestamp(date + "T00:00:00Z") and spent is not None and spent >= 0:
                days[date] = days.get(date, 0.0) + spent
        return days
    raise Unreadable(f"no daily reader for {adapter}")


def fetch_daily(adapter: str, key: str, *, timeout: float = 20.0) -> tuple[int, Any]:
    url, scheme = DAILY_REQUESTS[adapter]
    return _get(url, scheme, key, timeout, 16_000_000)


def refresh_daily(root: Path, rows: Iterable[Mapping[str, Any]], values: Mapping[str, str], *,
                  fetch: Callable[[str, str], tuple[int, Any]] = fetch_daily, now: Callable[[], float] = time.time,
                  force: bool = False) -> None:
    """Ask each live provider that reports daily spend for it, a few times a day at most.

    Best effort: a refusal or an odd answer changes nothing, and the page falls back to what the readings
    themselves show. The figures are kept by key fingerprint, like the readings.
    """
    import passbook_insights as insights

    kept = insights.daily(root)
    for row in rows:
        entry = provider(str(row.get("providerId")))
        adapter = (entry or {}).get("adapter")
        key = values.get(str(row.get("keyName") or ""))
        if row.get("status") != "ready" or adapter not in DAILY_REQUESTS or not key or not row.get("connection"):
            continue
        last = kept.get(row["providerId"]) or {}
        if not force and last.get("c") == row["connection"] and now() - float(last.get("at") or 0) < DAILY_SECONDS:
            continue
        try:
            status, payload = fetch(adapter, key)
            if status == 200:
                insights.remember_daily(root, row["providerId"], row["connection"], parse_daily(adapter, payload), now=now)
        except Exception:  # noqa: BLE001 — offline, a timeout, an odd answer: the readings still stand
            continue


def enrich(root: Path, rows: list[dict], *, now: Callable[[], float] = time.time) -> dict:
    """Put each live row's meter, spend and runway on it (`insights`), and return the page's summary."""
    import passbook_insights as insights

    history, provided, marks = insights.load(root), insights.daily(root), insights.marks(root)
    moment = now()
    for row in rows:
        if row.get("status") == "ready":
            row["insights"] = insights.for_row(row, history.get(row["providerId"], []), provided.get(row["providerId"]),
                                               marks.get(row["providerId"]), now=moment)
    return insights.summary(rows, now=moment)


# ── a provider's line ───────────────────────────────────────────────────────


# The apps that run the balance readers, and so the only ones a balance-only key is opened for: the CLI,
# PassBook's own window, and HivemindOS (service-accounts/readings.ts). Each gets numbers, never the key.
BALANCE_KEY_READERS = ("passbook-balances", "passbook-app", "hivemindos")


def provider(provider_id: str) -> dict | None:
    """A catalog entry, or for a second account (`fal/FAL_KEY_BACKUP`) the entry that reads it."""
    base_id, _, key = str(provider_id).partition("/")
    entry = next((entry for entry in PROVIDERS if entry["id"] == base_id), None)
    if entry is None or not key:
        return entry
    account = next((item for item in entry.get("accounts", ()) if item["key"] == key), None)
    if account:
        return _account_entry(entry, account)
    # Another account of the provider, named by the first of its keys (`anthropic/CLAUDE_API_KEY_LIAM_NABUT`).
    return _group_entry(entry, [key], None) if entry.get("adapter") else None


def _account_entry(entry: Mapping[str, Any], account: Mapping[str, Any]) -> dict:
    """Another account of the same provider, read with its own key and shown as its own row."""
    return {**entry, "id": f"{entry['id']}/{account['key']}", "name": f"{entry['name']} · {account['label']}",
            "keys": (account["key"],), "reading_keys": (account["key"],), "accounts": (), "billing_key": None,
            "adapter": account.get("adapter", entry.get("adapter")), "base": entry["id"]}


def _group_entry(entry: Mapping[str, Any], keys: list[str], identity: Mapping[str, Any] | None) -> dict:
    """An account of the provider other than the one its first key belongs to: its own row, named by the
    account when the provider says what it is called, else by its first key, and with a balance-only key of
    its own. The id is the provider's and that first key, so removing the key renames the row."""
    anchor = sorted(keys)[0]
    given = dict(entry.get("billing_key") or {})
    given["key"] = f"{anchor}_BALANCE_KEY"
    return {**entry, "id": f"{entry['id']}/{anchor}", "base": entry["id"], "group": True, "accounts": (),
            "name": f"{entry['name']} · {(identity or {}).get('name') or anchor}", "billing_key": given}


def top_up_url(entry: Mapping[str, Any]) -> str:
    return str(entry.get("billing_url") or entry.get("console_url") or "")


def balance_key(entry: Mapping[str, Any]) -> dict | None:
    """The key PassBook reads this provider's balance with and nothing else uses, when it can have one.

    Every provider with a reader can have one, so a key that runs models keeps the permissions it has and
    the balance is read with a stronger key kept apart for it. The catalog names the permission it needs
    where that is known; otherwise any key of the account that can read billing.
    """
    if not entry.get("adapter") or entry.get("pairs") or (entry.get("base") and not entry.get("group")):
        return None
    given = entry.get("billing_key") or {}
    stem = entry["id"].upper().replace("-", "_")
    return {"key": given.get("key") or f"{stem}_BALANCE_KEY", "label": given.get("label") or f"{entry['name']} balance key",
            "why": given.get("why") or "",
            "permission": given.get("permission") or f"A {entry['name']} key that can read the account's balance.",
            "createUrl": given.get("create_url") or entry.get("console_url") or ""}


def _reading_names(entry: Mapping[str, Any]) -> tuple[str, ...]:
    """The keys tried, in order: the balance-only key, then the billing keys, else the provider's keys.
    A catalog `reading_keys` (even an empty one) means its other keys cannot read billing."""
    slot = (balance_key(entry) or {}).get("key")
    names = entry["reading_keys"] if "reading_keys" in entry else entry.get("keys", ())
    return tuple(dict.fromkeys(name for name in (slot, *names) if name))


def _slot_names() -> set[str]:
    return {slot["key"] for slot in map(balance_key, PROVIDERS) if slot}


def held_names(entry: Mapping[str, Any], held: Iterable[str]) -> list[str]:
    """Every key held for this provider, in the catalog's order and then by name: the ones it lists, and any
    other key named like them (`key_patterns`), so a fifth Anthropic key is read without a release. Never a
    balance-only key, another account's own key (`accounts`) or the id half of a pair."""
    held = set(held)
    import re

    skip = _slot_names() | {item["key"] for item in entry.get("accounts", ())} | set((entry.get("pairs") or {}).values())
    listed = [name for name in dict.fromkeys((*entry.get("keys", ()), *entry.get("reading_keys", ()))) if name in held]
    found = sorted(name for name in held if any(re.match(pattern, name) for pattern in entry.get("key_patterns", ())))
    return [name for name in dict.fromkeys((*listed, *found))
            if name not in skip and not name.endswith("_BALANCE_KEY")]


def _all_names(entry: Mapping[str, Any]) -> tuple[str, ...]:
    slot = (balance_key(entry) or {}).get("key")
    return tuple(dict.fromkeys(name for name in (*entry.get("keys", ()), *entry.get("reading_keys", ()), slot) if name))


def _base(entry: Mapping[str, Any], present: set[str], checked_at: str) -> dict:
    names = _all_names(entry)
    slot = balance_key(entry)
    return {
        "providerId": entry["id"], "provider": entry.get("base") or entry["id"], "name": entry["name"],
        "category": entry["category"],
        "billing": BILLING_LABELS.get(entry.get("billing", "unknown"), BILLING_LABELS["unknown"]),
        "credentialPresent": any(name in present for name in names), "keyNames": list(names),
        "status": "manual", "checkedAt": checked_at, "observedAt": None, "balance": None, "unit": None,
        "usageUsd": None, "usagePeriod": None, "accountLabel": None, "details": [], "allowance": None,
        "topUpUrl": top_up_url(entry), "paymentNote": entry.get("payment_note", ""),
        "message": entry.get("reading_note") or MANUAL_NOTE,
        "balanceKey": {**slot, "held": slot["key"] in present} if slot else None,
        "accountKeys": [], "accountId": None,
    }


# What needs doing, said once for every surface: which row, what is wrong in a few words, what fixes it,
# and the one action that does. Worst first by `rank`. A ready row has none.
ISSUE_RANK = {"key-rejected": 1, "wrong-account": 1, "needs-balance-key": 2, "missing-key": 2, "locked": 3, "unreachable": 4,
              "no-api": 9}


def _a(words: str) -> str:
    return f"an {words}" if words[:1].upper() in "AEIOU" else f"a {words}"


def issue_for(row: Mapping[str, Any]) -> dict | None:
    """`title` is the headline, `fix` one short line under it, `detail` what the paste form explains."""
    status, slot, name = row.get("status"), row.get("balanceKey"), row.get("name")
    used = row.get("keyName") or ""
    http = (row.get("providerError") or {}).get("httpStatus")
    add = {"action": "add-key", "key": slot["key"], "createUrl": slot["createUrl"],
           "detail": f"What to make: {slot['permission']}"} if slot else {"action": "open"}

    def made(kind: str, title: str, fix: str, **extra: Any) -> dict:
        return {"kind": kind, "rank": ISSUE_RANK[kind], "title": title, "fix": fix, **extra}

    if status == "ready":
        return None
    if status == "locked":
        return made("locked", "Locked", "Its key is sealed. Unlock PassBook to read it.", action="unlock")
    if status == "manual":
        return made("no-api", "Not readable by API", row.get("message") or MANUAL_NOTE, action="open")
    if status == "missing":
        if row.get("needsKey"):
            return made("missing-key", f"Needs {row['needsKey']}",
                        f"{name} signs in with a key id and a secret; only {used} is here.", action="open")
        if slot:
            return made("needs-balance-key", f"Needs {_a(slot['label'])}", slot["why"] or slot["permission"], **add)
        return made("missing-key", "No key", "No saved key can read this balance.", action="open")
    if http in (401, 403) and row.get("refusalIsPermission") and slot:
        # For a cost report a refusal says the key lacks the permission, not that it is dead (Anthropic: 401
        # "requires an Admin API key or an organization-scoped API key", 403 to an organization key without it).
        lacks = (f"{used} is an organization key without permission to read cost." if http == 403
                 else f"{used} can't read cost. {slot['why'] or slot['permission']}")
        return made("needs-balance-key", f"Needs {_a(slot['label'])}", lacks, **add)
    if http == 401:
        why = "Revoked or expired"
        why += ", or this computer's address is not on the key's allowed list" if row["provider"] == "vultr" else ""
        return made("key-rejected", f"{name} refused {used}", why + ". Paste a new key to read the balance.",
                    **({**add, "detail": f"{add['detail']} Apps that use {used} need it replaced too, under Keys."} if slot else add))
    if http == 403:
        return made("needs-balance-key", f"{used} can't see billing",
                    f"{slot['why'] or 'It needs more permission.'} {used} stays as it is." if slot else "It needs more permission.", **add)
    return made("unreachable", "Didn't answer", "Try again in a moment; no balance is assumed.", action="retry")


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


def _open(values: Mapping[str, str], name: str) -> str:
    value = str(values.get(name) or "")
    return "" if value.startswith("hive-sealed:") else value


def read_provider(entry: Mapping[str, Any], values: Mapping[str, str], present: set[str], *,
                  fetch: Callable[[str, str], tuple[int, Any]] = fetch_reading, now: Callable[[], float] = time.time,
                  salt: bytes = b"", fresh_from: Mapping[str, dict] | None = None,
                  names: Iterable[str] | None = None) -> dict:
    """One account's reading: ready, error, missing (no key), locked (held but not readable here) or manual.
    `names` are the keys to try, in order (the account's own, when a provider holds several)."""
    reading = _base(entry, present, _iso(now()))
    adapter = entry.get("adapter")
    if not adapter:
        reading["issue"] = issue_for(reading)
        return reading
    names = tuple(names) if names is not None else _reading_names(entry)
    openable = [name for name in names if _open(values, name)]
    if entry.get("try_each") and len(openable) > 1:
        # Several keys may stand for the account and only some may read its cost: ask each until one does,
        # and if none can, say what the last one was told.
        for name in openable[:-1]:
            first = read_provider(entry, values, present, fetch=fetch, now=now, salt=salt, fresh_from=fresh_from, names=(name,))
            if first.get("status") == "ready":
                return first
        names = (openable[-1],)
    key_name = next((name for name in names if _open(values, name)), None)
    key = values.get(key_name or "", "")
    pair = (entry.get("pairs") or {}).get(key_name or "")
    if pair:
        if not values.get(pair) or str(values[pair]).startswith("hive-sealed:"):
            reading.update(status="missing", keyName=key_name, needsKey=pair,
                           message=f"Reading the balance needs {pair} as well as {key_name}.")
            reading["issue"] = issue_for(reading)
            return reading
        key = f"{values[pair]}\n{key}"
    if key_name and fresh_from and salt:
        kept = fresh_from.get(entry["id"])
        if kept and kept.get("connection") == fingerprint(salt, entry["id"], key):
            # The very same object: the command tells a reading just asked from a remembered one by identity.
            kept.update(balanceKey=reading["balanceKey"], provider=reading["provider"], issue=None)
            return kept
    if not key_name:
        held = any(name in present for name in names)
        billing = balance_key(entry)
        reading.update(status="locked" if held else "missing", message=(
            "The saved key could not be read here. Open the vault and refresh." if held
            else f"Add your {billing['label']} ({billing['key']}) to read the balance. {billing['permission']}" if billing
            and "reading_keys" in entry
            else "No saved key can read this balance."))
        reading["issue"] = issue_for(reading)
        return reading
    # Which key this reading is from, said without the key: its name, and an opaque fingerprint that changes
    # when the key does (`connection`), so a rotated key is never shown the old account's numbers.
    reading.update(keyName=key_name, connection=fingerprint(salt, entry["id"], key) if salt else None)
    try:
        status, payload = fetch(adapter, key)
    except Exception:  # noqa: BLE001 — offline, a timeout, a refused redirect: no balance is assumed
        reading.update(status="error", message="The provider did not answer. Try again; no balance is assumed.")
        reading["issue"] = issue_for(reading)
        return reading
    if status in (401, 403):
        reading.update(status="error", providerError={"httpStatus": status,
                       "category": "authentication-rejected" if status == 401 else "access-denied"},
                       refusalIsPermission=bool(entry.get("refusal_is_permission")),
                       message="The provider rejected the key. Check it and the account on the provider's site." if status == 401
                       else "The provider refused this key billing access. Check its permissions on the provider's site.")
        reading["issue"] = issue_for(reading)
        return reading
    if status >= 400:
        reading.update(status="error", message=f"The provider answered {status}. Try again; no balance is assumed.")
        reading["issue"] = issue_for(reading)
        return reading
    try:
        parsed = parse_reading(adapter, payload)
    except Unreadable:
        reading.update(status="error", message="The provider's answer was not understood; no balance is assumed.")
        reading["issue"] = issue_for(reading)
        return reading
    reading.update(parsed)
    reading.update(status="ready", observedAt=parsed.get("observedAt") or reading["checkedAt"],
                   message=READY_NOTES.get(adapter, READY_NOTE), issue=None)
    return reading


def _accounts(entry: Mapping[str, Any], held: set[str]) -> list[dict]:
    return [_account_entry(entry, item) for item in entry.get("accounts", ()) if item["key"] in held]


def wanted_keys(present: Iterable[str], *, everything: bool = False, only: Iterable[str] = ()) -> list[str]:
    """The keys the readers need, among those held: what `run` must open for this. Every key of a provider
    with a reader, since each may be a different account, and every balance-only key."""
    held = set(present)
    names: set[str] = {name for name in held if name.endswith("_BALANCE_KEY")} | (_slot_names() & held)
    for entry in _chosen(held, everything=everything, only=only):
        if not entry.get("adapter"):
            continue
        mine = set(held_names(entry, held)) | {item["key"] for item in entry.get("accounts", ())} | set(_reading_names(entry))
        names |= mine | {pair for name, pair in (entry.get("pairs") or {}).items() if name in mine}
    return sorted(name for name in names if name in held)


def _chosen(held: set[str], *, everything: bool, only: Iterable[str]) -> list[dict]:
    asked = {str(name).strip() for name in only if str(name).strip()}
    if asked:
        return [entry for entry in PROVIDERS if entry["id"] in asked]
    if everything:
        return list(PROVIDERS)
    return [entry for entry in PROVIDERS if held_names(entry, held) or any(name in held for name in (
        *_all_names(entry), *(item["key"] for item in entry.get("accounts", ()))))]


def _same_account(one: Mapping[str, Any], other: Mapping[str, Any]) -> bool:
    """Two keys that read the very same figures are one account, shown once."""
    figures = ("balance", "unit", "accountLabel", "usageUsd", "allowance", "details")
    return one.get("status") == other.get("status") == "ready" and all(one.get(f) == other.get(f) for f in figures)


def identities(root: Path) -> dict[str, dict]:
    """Which account each key belongs to, by key fingerprint: kept so a row keeps its id while offline."""
    try:
        loaded = json.loads((Path(root) / IDENTITY_FILE).read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        return {}


def remember_identities(root: Path, known: Mapping[str, dict]) -> None:
    path = Path(root) / IDENTITY_FILE
    path.write_text(json.dumps(dict(known)) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _identity(entry: Mapping[str, Any], name: str, values: Mapping[str, str], *, identify: Callable[[str, str], tuple[int, Any]],
              known: dict[str, dict] | None, salt: bytes, now: Callable[[], float]) -> dict | None:
    kind, value = entry.get("identify"), _open(values, name)
    if not kind or not value:
        return None
    mark = fingerprint(salt, f"{entry['id']}#who", value) if salt else ""
    kept = (known or {}).get(mark) if mark else None
    if kept and now() - float(kept.get("at") or 0) < IDENTITY_SECONDS:
        return {"id": kept["id"], "name": kept.get("name")}
    try:
        status, payload = identify(kind, value)
        found = parse_identity(kind, payload) if status == 200 else None
    except Exception:  # noqa: BLE001 — offline: an identity read before still stands, however old
        found = None
    if found and known is not None and mark:
        known[mark] = {**found, "at": now()}
    return found or ({"id": kept["id"], "name": kept.get("name")} if kept else None)


def _account_groups(entry: Mapping[str, Any], names: list[str], values: Mapping[str, str], **who: Any) -> list[tuple[list[str], dict | None]]:
    """The provider's held keys, by account. A key whose account cannot be told is an account of its own,
    never quietly merged; the account holding the catalog's first key comes first and keeps the bare id."""
    if not names:
        return [([], None)]
    if entry.get("identify"):
        grouped: dict[str, tuple[list[str], dict]] = {}
        alone: list[tuple[list[str], dict | None]] = []
        for name in names:
            found = _identity(entry, name, values, **who)
            if found:
                grouped.setdefault(found["id"], ([], found))[0].append(name)
            else:
                alone.append(([name], None))
        groups = [*grouped.values(), *alone]
        return sorted(groups, key=lambda group: names.index(group[0][0]))
    if "reading_keys" in entry:
        # Its billing keys read for the account; which account the other keys are in is not known.
        return [(names, None)]
    return [([name], None) for name in names]


def readings(values: Mapping[str, str], present: Iterable[str], *, everything: bool = False, only: Iterable[str] = (),
             fetch: Callable[[str, str], tuple[int, Any]] = fetch_reading, now: Callable[[], float] = time.time,
             salt: bytes = b"", fresh_from: Mapping[str, dict] | None = None,
             identify: Callable[[str, str], tuple[int, Any]] = fetch_identity, known: dict[str, dict] | None = None) -> list[dict]:
    """A reading per account you hold a key for (every provider with `everything`, or the ones named).

    A person can hold several keys for one provider (six for Anthropic, in four organizations). Each account
    is its own row, saying which keys are in it, with a balance-only key of its own; two keys that read the
    same figures are one account. `fresh_from` answers from a recent reading made with the same key.
    """
    held = set(present)
    who = {"identify": identify, "known": known, "salt": salt, "now": now}
    rows: list[dict] = []
    for entry in _chosen(held, everything=everything, only=only):
        if not entry.get("adapter"):
            row = read_provider(entry, values, held, fetch=fetch, now=now, salt=salt, fresh_from=fresh_from)
            row["accountKeys"] = held_names(entry, held)
            rows.append(row)
            continue
        names = held_names(entry, held)
        mine: list[dict] = []
        for index, (keys, found) in enumerate(_account_groups(entry, names, values, **who)):
            account = entry if index == 0 else _group_entry(entry, keys, found)
            slot = (balance_key(account) or {}).get("key")
            # A balance-only key made in another account is never read as this one's (`wrong-account`).
            elsewhere = _identity(entry, slot, values, **who) if slot and found and _open(values, slot) else None
            stray = elsewhere if elsewhere and elsewhere["id"] != found["id"] else None
            reading_keys = entry["reading_keys"] if "reading_keys" in entry else keys
            tried = [name for name in (None if stray else slot, *reading_keys) if name and (name in keys or name == slot or not found)]
            row = read_provider(account, values, held, fetch=fetch, now=now, salt=salt, fresh_from=fresh_from, names=tried)
            row.update(accountKeys=list(keys), accountId=(found or {}).get("id"))
            if found and found.get("name"):
                row["accountLabel"] = row.get("accountLabel") or found["name"]
                if index == 0:
                    row["name"] = f"{entry['name']} · {found['name']}"
                if row.get("issue") and row["issue"]["kind"] == "needs-balance-key":
                    # Which of several accounts it is for, in the headline itself.
                    row["issue"] = {**row["issue"], "title": f"{row['issue']['title']} for {found['name']}"}
            if stray:
                row["issue"] = {"kind": "wrong-account", "rank": ISSUE_RANK["wrong-account"], "action": "add-key", "key": slot,
                                "createUrl": row["balanceKey"]["createUrl"], "detail": f"What to make: {row['balanceKey']['permission']}",
                                "title": f"{slot} is from another account",
                                "fix": f"It was made in {stray.get('name') or 'another account'}, not {found.get('name') or 'this one'}. "
                                       f"Paste a key made in {found.get('name') or 'this account'}."}
            same = next((kept for kept in mine if _same_account(kept, row)), None)
            if same:
                same["accountKeys"] = [*same["accountKeys"], *keys]
                continue
            mine.append(row)
        for extra in _accounts(entry, held):
            row = read_provider(extra, values, held, fetch=fetch, now=now, salt=salt, fresh_from=fresh_from)
            row["accountKeys"] = [extra["keys"][0]]
            if not any(_same_account(kept, row) for kept in mine):
                mine.append(row)
        rows.extend(mine)
    return rows


def issues(rows: Iterable[Mapping[str, Any]]) -> list[dict]:
    """Everything that needs doing, worst first: the page's and the command's first lines."""
    found = [{"providerId": row["providerId"], "provider": row.get("provider") or row["providerId"], "name": row["name"],
              "category": row.get("category"), "account": row.get("accountLabel"), "keys": row.get("accountKeys") or [],
              **row["issue"]} for row in rows if row.get("issue")]
    return sorted(found, key=lambda item: (item["rank"], item["name"].lower()))


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
        # Off means gone: the last readings, the history made from them, and the logos fetched for them.
        import passbook_insights
        import passbook_logos

        (Path(root) / CACHE_FILE).unlink(missing_ok=True)
        (Path(root) / IDENTITY_FILE).unlink(missing_ok=True)
        passbook_insights.forget(root)
        passbook_logos.forget(root)
        # Alerts stop with the readings they are made from; where they went is kept for next time.
        import passbook_alerts

        if passbook_alerts.settings(root)["on"]:
            passbook_alerts.configure(root, on=False)
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
    # Without `insights`: those are worked out again from the history each time, never replayed.
    clean = [{name: value for name, value in row.items() if name != "insights"}
             for row in rows if row.get("status") == "ready" and row.get("connection")]
    path = Path(root) / CACHE_FILE
    path.write_text(json.dumps({"at": now(), "providers": clean}) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
