-- SPDX-License-Identifier: Apache-2.0
-- The PassBook relay's tables (Cloudflare D1, which is SQLite). Apply with:
--   wrangler d1 execute passbook_relay --remote --file=./schema.sql
-- Nothing stored here can be opened by the relay: envelopes are sealed to the machine they are for,
-- backups are encrypted with a passphrase the relay never sees, and an invite's secret never arrives.

-- A second computer joins through an invite, then collects envelopes sealed to it.
CREATE TABLE IF NOT EXISTS passbook_machine_invites (
  id TEXT PRIMARY KEY,
  issuer_did TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'machine',  -- 'machine': the owner's own computer. 'member': another person.
  device_did TEXT,
  pairing_token TEXT,
  join_mac TEXT,
  device_label TEXT,
  envelope TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  answered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_passbook_machine_invites_issuer ON passbook_machine_invites(issuer_did, expires_at);

CREATE TABLE IF NOT EXISTS passbook_machine_mailboxes (
  device_did TEXT NOT NULL,
  issuer_did TEXT NOT NULL,
  label TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'machine',
  envelope TEXT,
  envelope_at TEXT,
  linked_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (device_did, issuer_did)
);

CREATE INDEX IF NOT EXISTS idx_passbook_machine_mailboxes_issuer ON passbook_machine_mailboxes(issuer_did, revoked_at);

-- An encrypted backup of a store (src/backup.ts). `blob` is the text `passbook export` writes,
-- encrypted with a passphrase that never comes here. `recovery_hash` is the SHA-256 of a secret
-- PassBook showed its owner once, so a new machine can ask for the ciphertext.
CREATE TABLE IF NOT EXISTS passbook_backups (
  id TEXT PRIMARY KEY,
  owner_did TEXT NOT NULL,
  label TEXT NOT NULL,
  blob TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  digest TEXT NOT NULL,
  recovery_hash TEXT NOT NULL,
  misses INTEGER NOT NULL DEFAULT 0,
  missed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passbook_backups_owner ON passbook_backups(owner_did, created_at);

-- A phone that may be asked to allow or deny a request (src/phones.ts). The two keys are public:
-- one the phone signs its answers with, one PassBook encrypts questions to.
CREATE TABLE IF NOT EXISTS passbook_phones (
  id TEXT PRIMARY KEY,
  owner_did TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,             -- open, joined, linked, revoked
  sign_key TEXT,
  seal_key TEXT,
  join_mac TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  linked_at TEXT,
  seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_passbook_phones_owner ON passbook_phones(owner_did, status);

-- A question waiting on a phone. `sealed` is encrypted to the phone; `decision` is the phone's
-- signed answer exactly as it sent it, which only PassBook can check.
CREATE TABLE IF NOT EXISTS passbook_approvals (
  id TEXT PRIMARY KEY,
  phone_id TEXT NOT NULL,
  owner_did TEXT NOT NULL,
  sealed TEXT NOT NULL,
  status TEXT NOT NULL,             -- waiting, decided
  decision TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_passbook_approvals_phone ON passbook_approvals(phone_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_passbook_approvals_owner ON passbook_approvals(owner_did, expires_at);

-- What members reported about their use of an owner's keys (src/team.ts), sealed to the owner.
CREATE TABLE IF NOT EXISTS passbook_team_events (
  id TEXT PRIMARY KEY,
  owner_did TEXT NOT NULL,
  member_did TEXT NOT NULL,
  sealed TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passbook_team_events_owner ON passbook_team_events(owner_did, created_at, id);
