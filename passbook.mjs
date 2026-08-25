// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
// The PassBook standard, v1 — Node reference implementation.
//
// One credential store per machine, shared by every app that opts in. See
// SPEC.md. Single file, no dependencies, meant to be copied into a project.
//
// The twin of passbook.py: same path, same format, same precedence, so an
// Electron main process and a Python backend in the same app resolve exactly
// the same credentials.
//
//     import { ensure, apply } from './passbook.mjs';
//     ensure({ app: 'my-app', name: 'My App' });   // idempotent, converges
//     apply();                                     // fill missing process vars
//
// Values never leave this module except through load()/apply(), which put them
// where the caller asked. Every status surface returns key NAMES.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const SPEC_VERSION = 1;

const ROOT_ENV_VAR = 'HIVE_HOME';
const DEFAULT_ROOT_NAME = '.hivemindos';
const ENV_FILENAME = '.env';
const APPS_FILENAME = 'apps.json';
const WORKSPACES_MANIFEST = 'workspaces.json';
const WORKSPACES_DIRNAME = 'workspaces';
const WORKSPACE_ENV_VAR = 'HIVE_WORKSPACE';
const ROOT_WORKSPACE_ID = 'main';

const ROOT_MODE = 0o700;
const FILE_MODE = 0o600;

const KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const WORKSPACE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

// ── location ───────────────────────────────────────────────────────────────

/** The hive root: `$HIVE_HOME`, else `~/.hivemindos`. */
export function root(environ = process.env) {
    const configured = String(environ[ROOT_ENV_VAR] || '').trim();
    if (configured) return expand(configured, environ);
    return path.join(environ.HOME || os.homedir(), DEFAULT_ROOT_NAME);
}

/** The canonical credential store, whether or not it exists yet. */
export function envPath(environ = process.env) {
    return path.join(root(environ), ENV_FILENAME);
}

export function appsPath(environ = process.env) {
    return path.join(root(environ), APPS_FILENAME);
}

// ── workspaces ─────────────────────────────────────────────────────────────
//
// Parity with the Python side is not a nicety here. Two implementations that
// resolve different stores on the same machine would hand a Node app and a
// Python app different credentials, and the disagreement would surface as a
// provider mysteriously failing in one process and working in the other.

/** HivemindOS's own workspace manifest, when the machine has one. */
export function workspaceManifest(environ = process.env) {
    try {
        const payload = JSON.parse(fs.readFileSync(path.join(root(environ), WORKSPACES_MANIFEST), 'utf8'));
        return payload && typeof payload === 'object' ? payload : {};
    } catch {
        return {};
    }
}

/** The workspace this process acts for. `HIVE_WORKSPACE` beats the manifest. */
export function workspace(environ = process.env) {
    let name = String(environ[WORKSPACE_ENV_VAR] || '').trim();
    if (!name) name = String(workspaceManifest(environ).activeWorkspaceId || '').trim();
    if (!name) return '';
    if (!WORKSPACE.test(name)) throw new Error(`${name} is not a valid workspace id`);
    return name;
}

/** Where one workspace's store lives. `main` is the hive root itself. */
export function workspaceEnvPath(name, environ = process.env) {
    if (!WORKSPACE.test(name)) throw new Error(`${name} is not a valid workspace id`);
    for (const entry of workspaceManifest(environ).workspaces || []) {
        if (entry && typeof entry === 'object' && String(entry.id || '') === name) {
            const declared = String(entry.envPath || '').trim();
            if (declared) return expand(declared, environ);
        }
    }
    if (name === ROOT_WORKSPACE_ID) return envPath(environ);
    return path.join(root(environ), WORKSPACES_DIRNAME, name, ENV_FILENAME);
}

/** Every workspace on this machine: the manifest's, plus any on disk. */
export function workspaces(environ = process.env) {
    const named = new Set();
    for (const entry of workspaceManifest(environ).workspaces || []) {
        if (entry && typeof entry === 'object' && entry.id) named.add(String(entry.id));
    }
    try {
        for (const item of fs.readdirSync(path.join(root(environ), WORKSPACES_DIRNAME))) {
            if (fs.existsSync(path.join(root(environ), WORKSPACES_DIRNAME, item, ENV_FILENAME))) named.add(item);
        }
    } catch { /* no workspaces directory is not an error */ }
    return [...named].sort();
}

/** Does this workspace also see the machine-wide store? Default true. */
export function workspaceInherits(name, environ = process.env) {
    for (const entry of workspaceManifest(environ).workspaces || []) {
        if (entry && typeof entry === 'object' && String(entry.id || '') === name) {
            return entry.inherit === undefined ? true : Boolean(entry.inherit);
        }
    }
    return true;
}

/** The stores that feed this process, least specific first. */
function scopedPaths(environ = process.env) {
    const name = workspace(environ);
    const machine = envPath(environ);
    if (!name) return [machine];
    const scoped = workspaceEnvPath(name, environ);
    if (scoped === machine) return [machine];
    return workspaceInherits(name, environ) ? [machine, scoped] : [scoped];
}

/** Where a write lands: the named workspace, else the active one. */
export function targetPath(workspaceId = '', environ = process.env) {
    const name = workspaceId || workspace(environ);
    if (!name) return envPath(environ);
    return workspaceEnvPath(name, environ);
}

function expand(value, environ) {
    if (value === '~') return environ.HOME || os.homedir();
    if (value.startsWith('~/')) return path.join(environ.HOME || os.homedir(), value.slice(2));
    return value;
}

/**
 * Why `~` cannot be trusted here, or '' when it can.
 *
 * An explicit HIVE_HOME is always trusted: naming the path is the documented
 * way out of a container.
 */
export function containerHomeReason(environ = process.env) {
    if (String(environ[ROOT_ENV_VAR] || '').trim()) return '';
    if (environ.APP_SANDBOX_CONTAINER_ID) {
        return 'this process runs inside a macOS App Sandbox, so ~ is the app\'s private '
            + 'container rather than the real home directory';
    }
    const home = String(environ.HOME || os.homedir());
    if (home.includes('/Library/Containers/')) {
        return `HOME points inside a sandbox container (${home})`;
    }
    return '';
}

// ── format ─────────────────────────────────────────────────────────────────

/** Parse the Hive Env format. Later lines win. */
export function parseEnvText(text) {
    const values = {};
    for (const rawLine of String(text).split(/\r?\n/)) {
        let line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        if (line.startsWith('export ')) line = line.slice('export '.length).trim();
        const split = line.indexOf('=');
        if (split < 0) continue;
        const key = line.slice(0, split).trim();
        let value = line.slice(split + 1).trim();
        if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === "'")) {
            const quote = value[0];
            value = value.slice(1, -1);
            // Double quotes carry escapes, single quotes are literal — the same
            // split a shell makes, so a hand-edited file behaves as it looks.
            if (quote === '"') value = value.replace(/\\(.)/g, '$1');
        }
        if (KEY.test(key) && value) values[key] = value;
    }
    return values;
}

function read(file) {
    try {
        return parseEnvText(fs.readFileSync(file, 'utf8'));
    } catch {
        return {};
    }
}

function formatLine(key, value) {
    if (value && !/[\s#"'$`\\]/.test(value)) return `${key}=${value}`;
    return `${key}="${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// ── reading ────────────────────────────────────────────────────────────────

/**
 * Every credential visible here, in precedence order: process environment beats
 * project files, which beat the hive env. The hive env is a fleet-wide default
 * and never an override.
 */
export function load({ projectFiles = [], environ = process.env } = {}) {
    const values = {};
    for (const store of scopedPaths(environ)) Object.assign(values, read(store));
    for (const file of projectFiles) Object.assign(values, read(expand(file, environ)));
    for (const [key, value] of Object.entries(environ)) if (value) values[key] = value;
    return values;
}

/** Fill variables the process lacks. Returns the key NAMES that were set. */
export function apply({ projectFiles = [] } = {}) {
    const source = {};
    for (const store of scopedPaths()) Object.assign(source, read(store));
    for (const file of projectFiles) Object.assign(source, read(expand(file, process.env)));
    const filled = [];
    for (const [key, value] of Object.entries(source)) {
        if (value && process.env[key] === undefined) {
            process.env[key] = value;
            filled.push(key);
        }
    }
    return filled.sort();
}

/** The keys the store holds. Names only — values never leave. */
export function keyNames(environ = process.env) {
    const seen = {};
    for (const store of scopedPaths(environ)) Object.assign(seen, read(store));
    return Object.keys(seen).sort();
}

// ── writing ────────────────────────────────────────────────────────────────

function atomicWrite(file, text) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: ROOT_MODE });
    tighten(path.dirname(file), ROOT_MODE);
    const temporary = path.join(path.dirname(file), `.hive-env-${process.pid}-${Date.now()}`);
    try {
        fs.writeFileSync(temporary, text, { mode: FILE_MODE });
        fs.renameSync(temporary, file);
    } catch (error) {
        try { fs.unlinkSync(temporary); } catch {}
        throw error;
    }
}

/** Narrow permissions to `mode`, never widen them. */
function tighten(target, mode) {
    try {
        const current = fs.statSync(target).mode & 0o777;
        if (current & ~mode) fs.chmodSync(target, current & mode);
    } catch {}
}

/**
 * Add credentials to the canonical store, preserving everything else.
 * An existing key is kept unless `overwrite`. Returns key NAMES by outcome.
 */
export function setValues(values, { overwrite = false, workspaceId = '', environ = process.env } = {}) {
    const reason = containerHomeReason(environ);
    if (reason) {
        const error = new Error(
            `Refusing to write the hive env: ${reason}. `
            + `Set ${ROOT_ENV_VAR} to the real store, or ship the app unsandboxed.`,
        );
        error.code = 'HIVE_ENV_CONTAINER_HOME';
        throw error;
    }
    for (const key of Object.keys(values)) {
        if (!KEY.test(key)) throw new Error(`${key} is not a valid environment key`);
    }

    const file = targetPath(workspaceId, environ);
    const existing = read(file);
    const added = [], updated = [], kept = [];
    for (const [key, raw] of Object.entries(values)) {
        const value = String(raw ?? '').trim();
        if (!value) continue;
        if (!(key in existing)) added.push(key);
        else if (overwrite && existing[key] !== value) updated.push(key);
        else kept.push(key);
    }
    if (!added.length && !updated.length) {
        return { path: file, added: [], updated: [], kept: kept.sort() };
    }

    let lines;
    try {
        lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    } catch {
        lines = [
            '# Hive Env — the shared credential store for this machine.',
            `# One store, every app. Spec v${SPEC_VERSION}.`,
            '# Values are secret; key names are not. Mode 0600.',
        ];
    }

    const replacing = new Map(updated.map((key) => [key, String(values[key]).trim()]));
    const rewritten = lines.map((rawLine) => {
        const stripped = rawLine.trim();
        const body = stripped.startsWith('export ') ? stripped.slice('export '.length).trim() : stripped;
        const key = body.includes('=') ? body.slice(0, body.indexOf('=')).trim() : '';
        if (replacing.has(key)) {
            const line = formatLine(key, replacing.get(key));
            replacing.delete(key);
            return line;
        }
        return rawLine;
    });
    for (const [key, value] of replacing) rewritten.push(formatLine(key, value));
    for (const key of added) rewritten.push(formatLine(key, String(values[key]).trim()));

    atomicWrite(file, `${rewritten.join('\n').replace(/\n+$/, '')}\n`);
    return { path: file, added: added.sort(), updated: updated.sort(), kept: kept.sort() };
}

/**
 * Delete keys from the canonical store. Returns key NAMES by outcome.
 *
 * Removal is the one operation that can break another app on this machine, so
 * it is deliberately not part of `setValues` and never happens implicitly. A
 * key that was not there is reported as absent rather than thrown, because
 * "make sure this is gone" is the usual intent and it already is.
 */
export function removeValues(keys, { workspaceId = '', environ = process.env } = {}) {
    const reason = containerHomeReason(environ);
    if (reason) {
        throw new Error(
            `Refusing to write the hive env: ${reason}. `
            + `Set ${ROOT_ENV_VAR} to the real store, or ship the app unsandboxed.`,
        );
    }
    const file = targetPath(workspaceId, environ);
    const wanted = new Set([...keys].map((key) => String(key).trim()).filter(Boolean));
    const existing = read(file);
    const removed = [...wanted].filter((key) => key in existing).sort();
    const absent = [...wanted].filter((key) => !(key in existing)).sort();
    if (!removed.length) return { path: file, removed: [], absent };

    let raw = '';
    try {
        raw = fs.readFileSync(file, 'utf8');
    } catch {
        return { path: file, removed: [], absent: [...wanted].sort() };
    }
    const kept = raw.split('\n').filter((rawLine) => {
        const stripped = rawLine.trim();
        if (stripped.startsWith('#')) return true;
        const body = stripped.startsWith('export ') ? stripped.slice(7).trim() : stripped;
        if (!body.includes('=')) return true;
        return !wanted.has(body.split('=', 1)[0].trim());
    });
    atomicWrite(file, `${kept.join('\n').replace(/\n+$/, '')}\n`);
    return { path: file, removed, absent };
}

// ── participation ──────────────────────────────────────────────────────────

function now() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function readApps(file) {
    try {
        const payload = JSON.parse(fs.readFileSync(file, 'utf8'));
        return (payload?.apps || []).filter((item) => item && typeof item === 'object' && item.id);
    } catch {
        return [];
    }
}

/**
 * Record that `app` uses this store. A registry, never a lock — failing to
 * register is not worth failing a launch over.
 */
export function link(app, { name = '', environ = process.env } = {}) {
    const id = String(app || '').trim();
    if (!id) throw new Error('An app id is required to link to the hive env');
    const file = appsPath(environ);
    const apps = readApps(file);
    const stamp = now();
    const existing = apps.find((entry) => entry.id === id);
    if (existing) {
        existing.last_seen = stamp;
        if (name) existing.name = name;
    } else {
        apps.push({ id, name: name || id, first_seen: stamp, last_seen: stamp });
    }
    try {
        atomicWrite(file, `${JSON.stringify({ version: SPEC_VERSION, apps }, null, 2)}\n`);
    } catch (error) {
        return { linked: false, reason: error.message, apps: apps.map((entry) => entry.id) };
    }
    return { linked: true, apps: apps.map((entry) => entry.id) };
}

export function participants(environ = process.env) {
    return readApps(appsPath(environ));
}

// ── the one call an app makes at startup ───────────────────────────────────

/**
 * Join the machine's hive env, creating the canonical store if absent.
 *
 * Idempotent and convergent: the first app to call this creates
 * `~/.hivemindos/.env`, and every app after it — including the HivemindOS
 * desktop app — finds that same file and adopts it. No app ever gets a private
 * store, so there is never anything to merge.
 */
export function ensure({ app, name = '', seed = null, environ = process.env } = {}) {
    const reason = containerHomeReason(environ);
    if (reason) {
        return {
            ok: false,
            provisioned: false,
            linked: false,
            path: envPath(environ),
            reason,
            remedy: `Set ${ROOT_ENV_VAR} to the real store (for example ~/.hivemindos), or ship `
                + 'this app without the App Sandbox so it can reach the shared credential store.',
        };
    }

    const file = envPath(environ);
    const existed = fs.existsSync(file);
    if (!existed) {
        atomicWrite(file, [
            '# Hive Env — the shared credential store for this machine.',
            `# Created by: ${name || app}`,
            '#',
            '# Every HivemindOS-compatible app reads this one file, so a key added',
            '# here is available to all of them. Installing another app links it to',
            `# this store rather than creating another. Spec v${SPEC_VERSION}.`,
            '#',
            '# KEY=value, one per line. Values are secret; key names are not.',
            '',
        ].join('\n'));
    }
    if (seed) setValues(seed, { environ });
    const registry = link(app, { name, environ });
    tighten(root(environ), ROOT_MODE);
    tighten(file, FILE_MODE);
    return {
        ok: true,
        provisioned: !existed,
        adopted: existed,
        linked: Boolean(registry.linked),
        path: file,
        keys: keyNames(environ),
        apps: registry.apps || [],
    };
}

/** Everything a diagnostic needs, and no secrets. Safe to print or log. */
export function status(environ = process.env) {
    const file = envPath(environ);
    const reason = containerHomeReason(environ);
    const exists = fs.existsSync(file);
    const active = workspace(environ);
    return {
        spec_version: SPEC_VERSION,
        root: root(environ),
        path: file,
        workspace: active,
        workspaces: workspaces(environ),
        stores: scopedPaths(environ),
        writes_to: targetPath('', environ),
        inherits_machine_store: !active || workspaceInherits(active, environ),
        exists,
        keys: exists ? keyNames(environ) : [],
        apps: participants(environ).map((entry) => entry.id),
        home_is_container: Boolean(reason),
        detail: reason || (exists ? 'Shared hive env is in place.' : 'No shared hive env on this machine yet.'),
    };
}

/** One line for a doctor or a first-run screen. */
export function describe(environ = process.env) {
    const state = status(environ);
    if (state.home_is_container) return `hive env unreachable — ${state.detail}`;
    if (!state.exists) return `no hive env yet at ${state.path}`;
    return `${state.keys.length} keys at ${state.path} (${state.apps.join(', ') || 'no apps registered'})`;
}
