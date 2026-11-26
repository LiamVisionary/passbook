// SPDX-License-Identifier: Apache-2.0
// Adding a computer: choose what it gets, run one line on it, watch it arrive. Names only on this
// sheet. The invite line is a secret for its fifteen minutes (anyone holding it can join, once), so it
// is shown and copied, never stored here; the keys themselves are sealed by the CLI to the machine
// that joins. "Advanced" holds the limits PassBook enforces where the keys land, and says plainly
// that a spending limit is not one of them.
window.createPassbookAddDevice = function ({ invoke, container, esc, repaint, onJoined }) {
  const TABS = [["everything", "Everything"], ["groups", "Groups"], ["projects", "Projects"], ["keys", "Keys"]];
  let open = false, step = "what", tab = "everything", choices = null, busy = false, error = "";
  let picked = fresh(), search = "", advancedOpen = false;
  let adv = { days: 30, live: true, hosts: "", commands: "", apps: "" };
  let invite = null, joined = null, poll = null, copied = false;

  function fresh() { return { all: false, groups: new Set(), projects: new Set(), umbrellas: new Set(), keys: new Set() }; }
  const words = (text) => String(text || "").split(/[\s,]+/).map((w) => w.trim()).filter(Boolean);
  const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

  /** What the picks mean right now, the way the CLI will resolve them: lendable keys go, the rest stay. */
  function preview() {
    if (!choices) return { going: [], staying: [] };
    const leaves = new Map(choices.keys.map((row) => [row.name, row.leaves]));
    const wanted = new Set();
    if (picked.all) choices.keys.forEach((row) => wanted.add(row.name));
    for (const [kind, rows] of [["groups", choices.groups], ["projects", choices.projects], ["umbrellas", choices.umbrellas]]) {
      rows.filter((row) => picked[kind].has(row.name)).forEach((row) => row.keys.forEach((k) => wanted.add(k)));
    }
    picked.keys.forEach((k) => wanted.add(k));
    const going = [...wanted].filter((k) => leaves.get(k)).sort();
    const staying = [...wanted].filter((k) => leaves.has(k) && !leaves.get(k)).sort();
    return { going, staying };
  }

  function stopPolling() { if (poll) { clearInterval(poll); poll = null; } }
  function close() {
    stopPolling(); open = false; step = "what"; invite = null; joined = null; error = ""; busy = false;
    picked = fresh(); search = ""; copied = false; advancedOpen = false;
    adv = { days: 30, live: true, hosts: "", commands: "", apps: "" };
    delete container.dataset.adddevice; container.hidden = true; repaint();
  }

  async function start() {
    open = true; step = "what"; error = ""; busy = true; paint(true);
    try { choices = await invoke("link_choices"); }
    catch (caught) { error = String(caught?.message ?? caught).replace(/^Error:\s*/, ""); }
    finally { busy = false; paint(true); }
  }

  function rowsFor(kind) {
    if (!choices) return [];
    if (kind === "groups") return [...choices.groups.map((r) => ({ ...r, kind: "groups" })),
                                   ...choices.umbrellas.map((r) => ({ ...r, kind: "umbrellas", note: "umbrella" }))];
    if (kind === "projects") return choices.projects.map((r) => ({ ...r, kind: "projects" }));
    const needle = search.trim().toLowerCase();
    return choices.keys.filter((r) => !needle || r.name.toLowerCase().includes(needle)).map((r) => ({ ...r, kind: "keys" }));
  }

  function listHtml() {
    if (tab === "everything") {
      const going = choices ? choices.keys.filter((r) => r.leaves).length : 0;
      return `<label class="drow"><input type="checkbox" data-dev-all ${picked.all ? "checked" : ""}>
        <span class="grow"><b>Everything that may leave this machine</b><span class="dsub">${plural(going, "key")} today, and any you add later. Right for another computer of your own.</span></span></label>`;
    }
    const rows = rowsFor(tab);
    if (!rows.length) {
      const empty = { groups: "No groups yet. Keys are grouped on the Keys page.",
                      projects: "No key is limited to a project yet. Set one on a key's page under Projects.",
                      keys: search ? "No key matches." : "This store has no keys yet." }[tab];
      return `<p class="dsub dempty">${esc(empty)}</p>`;
    }
    return rows.map((row) => {
      const on = picked[row.kind].has(row.name);
      const stays = row.kind === "keys" && !row.leaves;
      const sub = row.kind === "keys" ? (stays ? "stays on this machine: its reach is not lendable" : "")
        : `${plural(row.keys.length, "key")}${row.note ? ` · ${row.note}` : ""}`;
      return `<label class="drow ${stays ? "dmuted" : ""}"><input type="checkbox" data-dev-pick="${esc(row.kind)}" value="${esc(row.name)}" ${on ? "checked" : ""} ${stays ? "disabled" : ""}>
        <span class="grow"><span class="${row.kind === "keys" ? "mono" : ""}">${esc(row.label || row.name)}</span>${sub ? `<span class="dsub">${esc(sub)}</span>` : ""}</span></label>`;
    }).join("");
  }

  function summaryHtml() {
    const { going, staying } = preview();
    if (!going.length && !staying.length) return `<p class="dsub">Nothing chosen yet.</p>`;
    return `<p class="dsummary"><b>${plural(going.length, "key")}</b> will go${adv.live ? ", and stay up to date" : ""}.${
      staying.length ? ` ${plural(staying.length, "key")} you chose ${staying.length === 1 ? "stays" : "stay"} here: ${esc(staying.slice(0, 4).join(", "))}${staying.length > 4 ? "…" : ""}.` : ""}</p>`;
  }

  function advancedHtml() {
    if (!advancedOpen) return "";
    const days = [7, 30, 90, 365];
    return `<div class="dadv">
      <div class="akey"><label class="aplain" for="dev-days">How long before it has to be renewed</label>
        <select id="dev-days">${days.map((d) => `<option value="${d}" ${adv.days === d ? "selected" : ""}>${d === 365 ? "1 year" : `${d} days`}</option>`).join("")}</select></div>
      <label class="drow"><input type="checkbox" id="dev-live" ${adv.live ? "checked" : ""}>
        <span class="grow">Keep it up to date<span class="dsub">${adv.live
          ? "Changes here reach it, and the grant renews while this machine's vault is open."
          : "It gets these keys as they are now, and they are removed from it when the grant ends."}</span></span></label>
      <div class="akey"><label class="aplain" for="dev-hosts">Only send them to these hosts</label>
        <input id="dev-hosts" placeholder="api.openai.com, api.anthropic.com" value="${esc(adv.hosts)}">
        <span class="ahint">On that machine, a request to any other host is refused.</span></div>
      <div class="akey"><label class="aplain" for="dev-commands">Only give them to these commands</label>
        <input id="dev-commands" placeholder="node, wrangler" value="${esc(adv.commands)}"></div>
      <div class="akey"><label class="aplain" for="dev-apps">Only these apps may read them</label>
        <input id="dev-apps" placeholder="codex, claude-code" value="${esc(adv.apps)}"></div>
      <p class="anote">A spending limit is not something PassBook can enforce on a key. Set one at the provider (most have a monthly cap), and the Balances page shows what is left.</p>
    </div>`;
  }

  function paintWhat() {
    const { going } = preview();
    return `<div class="awrap"><div class="acard"><div class="ahead"><h1>Add a device</h1>
      <p class="aorigin">Choose what it gets. Then you run one line on it, and the keys arrive sealed to that machine.</p></div>
      ${choices ? `<div class="dtabs" role="tablist">${TABS.map(([id, name]) =>
        `<button role="tab" aria-selected="${tab === id}" data-dev-tab="${id}">${name}</button>`).join("")}</div>
      ${tab === "keys" ? `<div class="akey"><input id="dev-search" placeholder="Find a key" value="${esc(search)}" autocomplete="off"></div>` : ""}
      <div class="dlist" id="dev-list">${listHtml()}</div>
      <div id="dev-summary">${summaryHtml()}</div>
      <button class="alink" data-dev-advanced>${advancedOpen ? "Hide advanced" : "Advanced: duration, hosts, apps"}</button>
      ${advancedHtml()}` : `<p class="aorigin">${busy ? "Reading what this machine holds…" : ""}</p>`}
      ${error ? `<p class="aerr" role="alert">${esc(error)}</p>` : ""}
      <div class="arow"><button class="aghost" data-dev-close ${busy ? "disabled" : ""}>Cancel</button>
        <button class="aprimary" data-dev-make ${busy || !going.length ? "disabled" : ""}>${busy && choices ? "Making invite…" : "Make invite"}</button></div>
    </div></div>`;
  }

  function paintInvite() {
    return `<div class="awrap"><div class="acard"><div class="ahead"><h1>Run this on the new machine</h1>
      <p class="aorigin">It gets <b>${plural(invite.keys.length, "key")}</b>${adv.live ? " and stays up to date" : ""}. The line works once, for 15 minutes.</p></div>
      <div class="dcmd"><code class="mono">${esc(invite.command)}</code>
        <button class="iconbtn ${copied ? "done" : ""}" data-dev-copy title="${copied ? "Copied" : "Copy"}" aria-label="Copy the command">${copied ? "Copied" : "Copy"}</button></div>
      <p class="anote">Anyone with this line can join during those 15 minutes, so paste it only into that machine.
        No PassBook there yet? Install it first: <code class="mono">uv tool install git+https://github.com/LiamVisionary/passbook</code></p>
      <p class="dwait"><span class="dspin" aria-hidden="true"></span> Waiting for it to join. Keep PassBook open here.</p>
      ${error ? `<p class="aerr" role="alert">${esc(error)}</p>` : ""}
      <div class="arow"><button class="aghost" data-dev-cancel ${busy ? "disabled" : ""}>Cancel invite</button>
        <button class="aprimary" data-dev-hide>Hide</button></div>
    </div></div>`;
  }

  function paintDone() {
    return `<div class="awrap"><div class="acard"><div class="adone"><h1>${esc(joined.label)} joined</h1>
      <p class="aorigin">It has ${plural(joined.keys.length, "key")}${adv.live ? " and stays up to date while this machine's vault is open" : ""}.
        It checks for changes every ten minutes. You can unlink it from Devices at any time.</p>
      <p class="aorigin">Its code: <b class="mono">${esc(joined.fingerprint)}</b></p></div>
      <div class="arow"><span></span><button class="aprimary" data-dev-done>Done</button></div></div></div>`;
  }

  function refreshList() {
    const list = container.querySelector("#dev-list"), summary = container.querySelector("#dev-summary");
    if (list) { list.innerHTML = listHtml(); wireList(); }
    if (summary) summary.innerHTML = summaryHtml();
    const make = container.querySelector("[data-dev-make]");
    if (make) make.disabled = busy || !preview().going.length;
  }

  function wireList() {
    container.querySelectorAll("[data-dev-pick]").forEach((box) => box.onchange = () => {
      const set = picked[box.dataset.devPick];
      box.checked ? set.add(box.value) : set.delete(box.value);
      refreshList();
    });
    const all = container.querySelector("[data-dev-all]");
    if (all) all.onchange = () => { picked.all = all.checked; refreshList(); };
  }

  function readAdvanced() {
    const value = (id) => container.querySelector(`#${id}`)?.value ?? "";
    if (!container.querySelector("#dev-days")) return;
    adv = { days: Number(value("dev-days")) || 30, live: Boolean(container.querySelector("#dev-live")?.checked),
            hosts: value("dev-hosts"), commands: value("dev-commands"), apps: value("dev-apps") };
  }

  async function make() {
    readAdvanced();
    busy = true; error = ""; paint(true);
    try {
      invite = await invoke("link_invite", {
        selection: { all: picked.all, keys: [...picked.keys], groups: [...picked.groups], projects: [...picked.projects], umbrellas: [...picked.umbrellas] },
        advanced: { days: adv.days, fixed: !adv.live, hosts: words(adv.hosts), commands: words(adv.commands), apps: words(adv.apps) },
      });
      step = "invite"; copied = false;
      stopPolling();
      poll = setInterval(check, 2500);
    } catch (caught) { error = String(caught?.message ?? caught).replace(/^Error:\s*/, ""); }
    finally { busy = false; paint(true); }
  }

  let checking = false;
  async function check() {
    if (!invite || checking) return;
    checking = true;
    try {
      const rows = await invoke("link_complete");
      const row = (rows || []).find((r) => r.id === invite.id);
      if (!row || row.status === "waiting") return;
      stopPolling();
      if (row.status === "joined") { joined = row; step = "done"; open = true; onJoined?.(); }
      else { error = row.detail || "The invite ran out before a machine joined. Make a new one."; step = "what"; invite = null; open = true; }
      paint(true); repaint();
    } catch { /* the relay or the CLI hiccuped; the next tick asks again */ }
    finally { checking = false; }
  }

  function paint(force = false) {
    if (!open) return false;
    const id = `${step}-${tab}-${busy}-${advancedOpen}-${Boolean(choices)}-${copied}-${error}`;
    if (!force && container.dataset.adddevice === id) return true;
    container.dataset.adddevice = id;
    container.hidden = false;
    container.innerHTML = step === "invite" ? paintInvite() : step === "done" ? paintDone() : paintWhat();
    const on = (selector, handler) => { const el = container.querySelector(selector); if (el) el.onclick = handler; };
    on("[data-dev-close]", close);
    on("[data-dev-done]", close);
    on("[data-dev-hide]", () => { open = false; delete container.dataset.adddevice; container.hidden = true; repaint(); });
    on("[data-dev-make]", () => void make());
    on("[data-dev-advanced]", () => { readAdvanced(); advancedOpen = !advancedOpen; paint(true); });
    on("[data-dev-copy]", async () => {
      try { await navigator.clipboard.writeText(invite.command); copied = true; paint(true); }
      catch { error = "Could not copy. Select the line and copy it by hand."; paint(true); }
    });
    on("[data-dev-cancel]", async () => {
      busy = true; paint(true);
      try { await invoke("link_cancel", { id: invite.id }); } catch { /* already gone */ }
      busy = false; close();
    });
    container.querySelectorAll("[data-dev-tab]").forEach((b) => b.onclick = () => { readAdvanced(); tab = b.dataset.devTab; paint(true); });
    const searchBox = container.querySelector("#dev-search");
    if (searchBox) {
      searchBox.oninput = () => { search = searchBox.value; refreshList(); };
      if (tab === "keys") searchBox.focus();
    }
    const live = container.querySelector("#dev-live");
    if (live) live.onchange = () => { readAdvanced(); paint(true); };
    wireList();
    return true;
  }

  return {
    start,
    paint,
    /** An invite is still out: Devices says so, and pressing it brings the sheet back. */
    waiting: () => Boolean(invite && step === "invite"),
    resume: () => { if (invite) { open = true; paint(true); } },
  };
};
