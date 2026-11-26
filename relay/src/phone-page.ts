// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//
// The page a phone opens to answer PassBook: GET /phone.
//
// It is one file with no dependencies, so what it does can be read in one sitting. It makes two key
// pairs in the phone's browser (WebCrypto, P-256, the private halves not extractable), joins the
// link whose code is in the address after `#` (which browsers never send to a server), then shows
// what is waiting and signs the answer.
//
// THE LIMIT, said plainly: this page is served by the relay. The protocol keeps a relay that only
// stores and forwards from reading a question or forging an answer, and that covers a stolen
// database or a curious operator. It does not cover a relay that has been changed to serve a
// different page, because that page would hold the phone's key. If that matters to you, run your
// own relay; and whatever relay you use, every answer a phone gives is written to PassBook's
// Activity record on the machine that asked, where a wrong one can be seen.

const SCRIPT = String.raw`
(function () {
  "use strict";
  var enc = new TextEncoder(), dec = new TextDecoder();
  var main = document.getElementById("main");
  var links = [], shown = {}, busy = {}, note = "";

  function b64(bytes) {
    var s = "", b = new Uint8Array(bytes);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function unb64(text) {
    var p = text.replace(/-/g, "+").replace(/_/g, "/"); while (p.length % 4) p += "=";
    var s = atob(p), out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function hex(bytes) { var b = new Uint8Array(bytes), s = ""; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16); return s; }
  function sha256hex(text) { return crypto.subtle.digest("SHA-256", enc.encode(text)).then(hex); }
  function esc(text) { return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]; }); }

  // The keys live in IndexedDB as CryptoKey objects. The private halves were made not extractable,
  // so this page can use them and nothing, this page included, can read them out.
  function db() {
    return new Promise(function (resolve, reject) {
      var open = indexedDB.open("passbook-phone", 1);
      open.onupgradeneeded = function () { open.result.createObjectStore("links", { keyPath: "id" }); };
      open.onsuccess = function () { resolve(open.result); };
      open.onerror = function () { reject(open.error); };
    });
  }
  function store(mode, work) {
    return db().then(function (d) {
      return new Promise(function (resolve, reject) {
        var tx = d.transaction("links", mode), result = work(tx.objectStore("links"));
        tx.oncomplete = function () { resolve(result && result.result); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }

  function signed(link, method, path, body) {
    var seconds = String(Math.floor(Date.now() / 1000));
    return sha256hex(body || "").then(function (digest) {
      var message = "passbook-phone:v1\n" + method + "\n" + path + "\n" + seconds + "\n" + digest;
      return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, link.sign.privateKey, enc.encode(message));
    }).then(function (signature) {
      var headers = { "X-PassBook-Phone": link.id + " " + seconds + " " + b64(signature) };
      if (body) headers["Content-Type"] = "application/json";
      return fetch(path, { method: method, headers: headers, body: body || undefined, cache: "no-store" });
    }).then(function (response) { return response.json().then(function (data) { data.http = response.status; return data; }); });
  }

  function join(code) {
    var parts = code.split(".");
    if (parts.length < 4 || parts[0] !== "pbp1") throw new Error("That link is not a PassBook phone link.");
    var id = parts[1], secret = unb64(parts[2]), owner = dec.decode(unb64(parts[3]));
    var name = parts[4] ? dec.decode(unb64(parts[4])) : "PassBook";
    var made = {};
    return Promise.all([
      crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]),
      crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
    ]).then(function (pairs) {
      made.sign = pairs[0]; made.seal = pairs[1];
      return Promise.all([crypto.subtle.exportKey("raw", made.sign.publicKey), crypto.subtle.exportKey("raw", made.seal.publicKey)]);
    }).then(function (raws) {
      made.signKey = b64(raws[0]); made.sealKey = b64(raws[1]);
      return crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    }).then(function (key) {
      // PassBook checks this. It is how PassBook knows the keys it was handed are the keys of the
      // phone that read its code, and not keys the relay put in their place.
      return crypto.subtle.sign("HMAC", key, enc.encode("passbook-phone-join:v1\n" + id + "\n" + made.signKey + "\n" + made.sealKey));
    }).then(function (mac) {
      var label = /iPhone/.test(navigator.userAgent) ? "iPhone" : /iPad/.test(navigator.userAgent) ? "iPad" : /Android/.test(navigator.userAgent) ? "Android phone" : "Browser";
      return fetch("/api/passbook/phones/" + id + "/join", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signKey: made.signKey, sealKey: made.sealKey, mac: b64(mac), label: label }) });
    }).then(function (response) { return response.json(); }).then(function (answer) {
      if (!answer.ok) throw new Error(answer.error || "That link could not be joined.");
      var link = { id: id, owner: owner, name: name, sign: made.sign, seal: made.seal, sealKey: made.sealKey, status: "joined", added: Date.now() };
      return store("readwrite", function (s) { return s.put(link); }).then(function () { return link; });
    });
  }

  function open(link, sealed) {
    var parts = sealed.split(".");
    if (parts.length !== 4 || parts[0] !== "pbps1") return Promise.reject(new Error("unreadable"));
    var from = unb64(parts[1]), nonce = unb64(parts[2]), box = unb64(parts[3]);
    return crypto.subtle.importKey("raw", from, { name: "ECDH", namedCurve: "P-256" }, false, []).then(function (theirs) {
      return crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, link.seal.privateKey, 256);
    }).then(function (shared) {
      return crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    }).then(function (material) {
      var mine = unb64(link.sealKey), tag = enc.encode("passbook-phone-seal:v1");
      var info = new Uint8Array(tag.length + from.length + mine.length);
      info.set(tag, 0); info.set(from, tag.length); info.set(mine, tag.length + from.length);
      return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: info }, material,
        { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    }).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, box);
    }).then(function (plain) {
      var text = dec.decode(plain), ask = JSON.parse(text);
      // A question that does not name the PassBook this phone is linked to is not one of its questions.
      if (ask.owner !== link.owner) throw new Error("not ours");
      ask.text = text;
      return ask;
    });
  }

  function answer(link, request, decision, remember) {
    if (busy[request.id]) return;
    busy[request.id] = true; paint();
    var at = Math.floor(Date.now() / 1000), ask = request.ask;
    sha256hex(ask.text).then(function (digest) {
      var message = ["passbook-approval:v1", link.owner, ask.rid, digest, decision, String(remember), String(at)].join("\n");
      return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, link.sign.privateKey, enc.encode(message)).then(function (signature) {
        var body = JSON.stringify({ answer: JSON.stringify({ v: 1, rid: ask.rid, digest: digest, decision: decision, remember: remember, at: at, signature: b64(signature) }) });
        return signed(link, "POST", "/api/passbook/approvals/" + request.id + "/decision", body);
      });
    }).then(function (result) {
      delete busy[request.id];
      if (!result.ok) { note = result.error || "That answer did not go through."; }
      else { note = decision === "allow" ? "Allowed." : "Denied."; shown[request.id] = "done"; }
      link.requests = (link.requests || []).filter(function (r) { return r.id !== request.id; });
      paint();
    }).catch(function () { delete busy[request.id]; note = "That answer did not go through. Check the connection."; paint(); });
  }

  function check(link) {
    return signed(link, "GET", "/api/passbook/phones/" + link.id + "/requests", "").then(function (data) {
      if (data.http === 401) { link.status = "gone"; return; }
      if (!data.ok) return;
      link.status = data.status;
      return Promise.all((data.requests || []).map(function (r) {
        return open(link, r.sealed).then(function (ask) { return { id: r.id, expiresAt: r.expiresAt, ask: ask }; }).catch(function () { return null; });
      })).then(function (list) { link.requests = list.filter(Boolean); });
    }).catch(function () { link.offline = true; });
  }

  function refresh() {
    if (document.hidden) return Promise.resolve();
    return Promise.all(links.map(function (l) { l.offline = false; return check(l); })).then(paint);
  }

  function forget(id) {
    store("readwrite", function (s) { return s.delete(id); }).then(function () {
      links = links.filter(function (l) { return l.id !== id; }); note = "Removed from this phone. Unlink it in PassBook too."; paint();
    });
  }

  function paint() {
    var html = "";
    if (note) html += '<p class="note" role="status">' + esc(note) + "</p>";
    if (!links.length) {
      html += '<section class="card"><h2>No PassBook is linked to this phone</h2><p>In PassBook on your computer, open Settings, choose Approve from your phone, and open the link it shows on this phone.</p></section>';
    }
    links.forEach(function (link) {
      html += '<section class="card"><header><h2>' + esc(link.name) + "</h2>";
      html += '<button class="quiet" data-forget="' + esc(link.id) + '">Remove</button></header>';
      if (link.status === "gone") html += "<p>This phone was unlinked in PassBook. Remove it here, or link it again from PassBook.</p>";
      else if (link.status === "joined") html += '<p class="wait">Waiting for PassBook to confirm this phone. Keep PassBook open on your computer.</p>';
      else if (link.offline) html += "<p>Cannot reach the relay. Check the connection.</p>";
      else if (!(link.requests || []).length) html += '<p class="quietp">Nothing is waiting. Leave this page open, or come back when PassBook tells you something is.</p>';
      (link.requests || []).forEach(function (request) {
        var ask = request.ask, keys = (ask.keys || []).map(function (k) { return "<code>" + esc(k) + "</code>"; }).join(" ");
        var verb = ask.kind === "read" ? "wants to use" : ask.kind === "add" ? "wants to add" : ask.kind === "modify" ? "wants to change" : ask.kind === "delete" ? "wants to delete" : "asks about";
        html += '<article class="ask"><p class="who"><strong>' + esc(ask.app || "An app") + "</strong> " + verb + "</p>";
        html += '<p class="keys">' + (keys || "a key") + "</p>";
        if (ask.reason) html += '<p class="why">' + esc(ask.reason) + "</p>";
        html += '<p class="where">On ' + esc(ask.machine || "your computer") + (ask.workspace ? ", workspace " + esc(ask.workspace) : "") + "</p>";
        var off = busy[request.id] ? " disabled" : "";
        html += '<div class="acts"><button class="deny" data-id="' + esc(request.id) + '" data-link="' + esc(link.id) + '" data-do="deny" data-for="0"' + off + ">Deny</button>";
        html += '<button data-id="' + esc(request.id) + '" data-link="' + esc(link.id) + '" data-do="allow" data-for="0"' + off + ">Allow once</button>";
        html += '<button class="go" data-id="' + esc(request.id) + '" data-link="' + esc(link.id) + '" data-do="allow" data-for="3600"' + off + ">Allow for 1 hour</button></div></article>";
      });
      html += "</section>";
    });
    main.innerHTML = html;
    Array.prototype.forEach.call(main.querySelectorAll("[data-do]"), function (button) {
      button.onclick = function () {
        var link = links.filter(function (l) { return l.id === button.getAttribute("data-link"); })[0];
        var request = link && (link.requests || []).filter(function (r) { return r.id === button.getAttribute("data-id"); })[0];
        if (request) answer(link, request, button.getAttribute("data-do"), Number(button.getAttribute("data-for")));
      };
    });
    Array.prototype.forEach.call(main.querySelectorAll("[data-forget]"), function (button) {
      button.onclick = function () { forget(button.getAttribute("data-forget")); };
    });
  }

  function start() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      main.innerHTML = '<section class="card"><h2>This browser cannot do this</h2><p>It is missing the cryptography this page needs. Try Safari or Chrome, not in private browsing.</p></section>';
      return;
    }
    var code = location.hash.replace(/^#/, "");
    // The code is a secret for its fifteen minutes. It leaves the address bar as soon as it is read.
    if (code) history.replaceState(null, "", location.pathname);
    store("readonly", function (s) { return s.getAll(); }).then(function (saved) {
      links = saved || [];
      if (!code) return;
      var already = links.filter(function (l) { return l.id === code.split(".")[1]; })[0];
      if (already) return;
      return join(code).then(function (link) { links.push(link); note = "Joined. Now confirm it in PassBook on your computer."; })
        .catch(function (error) { note = error && error.message ? error.message : "That link could not be joined."; });
    }).then(function () { paint(); return refresh(); }).then(function () {
      setInterval(refresh, 3000);
      document.addEventListener("visibilitychange", refresh);
    }).catch(function () {
      main.innerHTML = '<section class="card"><h2>This browser will not keep the key</h2><p>Private browsing does not let a page keep anything. Open this link in a normal tab.</p></section>';
    });
  }
  start();
})();
`;

const STYLE = `
:root { color-scheme: light dark; --bg: #f5f5f7; --card: #fff; --ink: #1d1d1f; --ink2: #6e6e73; --line: #e3e3e8; --accent: #0060ee; --deny: #b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f0f10; --card: #1c1c1e; --ink: #f5f5f7; --ink2: #a1a1a6; --line: #2f2f33; --accent: #4c9bff; --deny: #ff6b61; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; -webkit-text-size-adjust: 100%; }
.wrap { max-width: 520px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 16px; letter-spacing: -0.01em; }
h2 { font-size: 17px; margin: 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin: 0 0 14px; }
.card header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
p { margin: 8px 0 0; }
.quietp, .where, .wait { color: var(--ink2); }
.note { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; margin: 0 0 14px; }
.ask { border-top: 1px solid var(--line); margin-top: 14px; padding-top: 14px; }
.who { margin: 0; }
.keys code { display: inline-block; font: 14px/1.3 ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 3px 6px; margin: 2px 2px 2px 0; word-break: break-all; }
.why { border-left: 0; background: var(--bg); border-radius: 8px; padding: 8px 10px; }
.acts { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
button { font: inherit; font-weight: 600; min-height: 44px; padding: 0 14px; border-radius: 10px; border: 1px solid var(--line); background: var(--card); color: var(--ink); flex: 1 1 auto; }
button.go { background: var(--accent); border-color: var(--accent); color: #fff; }
button.deny { color: var(--deny); }
button.quiet { flex: 0 0 auto; min-height: 32px; font-weight: 500; color: var(--ink2); }
button:disabled { opacity: 0.5; }
footer { color: var(--ink2); font-size: 13px; margin-top: 18px; }
`;

export function phonePage(): Response {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex">
<title>PassBook on your phone</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
<div class="wrap">
<h1>PassBook</h1>
<div id="main"><section class="card"><p>Opening…</p></section></div>
<footer>This page keeps a key in this browser and uses it to sign your answers. It never sees a credential.</footer>
</div>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}
