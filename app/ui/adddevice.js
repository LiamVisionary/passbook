// SPDX-License-Identifier: Apache-2.0
// Adding a computer: choose what it gets, run one line on it, watch it arrive. Names only on this
// sheet. The invite line is a secret for its fifteen minutes (anyone holding it can join, once), so it
// is shown and copied, never stored here; the keys themselves are sealed by the CLI to the machine
// that joins. "Advanced" holds the limits PassBook enforces where the keys land, and says plainly
// that a spending limit is not one of them.
//
// `mode: "person"` is the same sheet for sharing with somebody else: it asks who they are and whether
// they may see the keys or only use them, and makes the invite with `team_invite`. Choosing what goes,
// the one line, and waiting for the join are the same code either way. `plans` is how a refusal by the
// plan (too many computers, no seat left) gets the button that fixes it beside the sentence.
window.createPassbookAddDevice = function ({ invoke, container, esc, repaint, onJoined, mode = "device", plans = null }) {
  const TABS = [["everything", "Everything"], ["groups", "Groups"], ["projects", "Projects"], ["keys", "Keys"]];
  const person = mode === "person";
  const ROLES = [["use", "Use them"], ["read", "Use and see them"]];
  let open = false, step = "what", tab = "everything", choices = null, busy = false, error = "";
  // Whether `error` is the plan saying no, which is the one kind of error with something to press.
  let refused = false;
  let who = { name: "", role: "use" };
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
  const said = (caught) => String(caught?.message ?? caught).replace(/^Error:\s*/, "");
  function fail(sentence, code = "") { error = sentence; refused = Boolean(sentence && plans?.refused?.(sentence, code)); }
  /** The sentence that went wrong and, when the plan is why, the button that opens the plans. */
  function errorHtml() {
    if (!error) return "";
    const offer = refused ? plans?.offer?.() : "";
    return `<div class="aoffer"><p class="aerr" role="alert">${esc(error)}</p>${
      offer ? `<button class="act primary" data-dev-plan>${esc(offer)}</button>` : ""}</div>`;
  }

  function close() {
    stopPolling(); open = false; step = "what"; invite = null; joined = null; fail(""); busy = false;
    picked = fresh(); search = ""; copied = false; advancedOpen = false; who = { name: "", role: "use" };
    adv = { days: 30, live: true, hosts: "", commands: "", apps: "" };
    delete container.dataset.adddevice; container.hidden = true; repaint();
  }

  async function start() {
    open = true; step = "what"; fail(""); busy = true; paint(true);
    try { choices = await invoke("link_choices"); }
    catch (caught) { fail(said(caught)); }
    finally { busy = false; paint(true); container.querySelector("#dev-name")?.focus(); }
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
        <span class="grow"><b>Everything that may leave this machine</b><span class="dsub">${plural(going, "key")} today, and any you add later. ${person
          ? "Only for someone you would hand every key to." : "Right for another computer of your own."}</span></span></label>`;
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

  /** Who the invite is for, and whether PassBook ever shows them a key. Only when sharing with a person. */
  function whoHtml() {
    if (!person) return "";
    return `<div class="akey"><label class="aplain" for="dev-name">Their name</label>
        <input id="dev-name" maxlength="60" autocomplete="off" spellcheck="false" value="${esc(who.name)}"></div>
      <div class="akey"><label class="aplain" id="dev-role-label">What they can do with the keys</label>
        <div class="dtabs two" role="radiogroup" aria-labelledby="dev-role-label">${ROLES.map(([id, name]) =>
          `<button role="radio" aria-checked="${who.role === id}" data-dev-role="${id}">${name}</button>`).join("")}</div>
        <span class="ahint">${who.role === "use"
          ? "Their apps can use the keys. PassBook never shows the keys to them."
          : "Their apps can use the keys, and they can also see them."}</span></div>`;
  }
  const ready = () => preview().going.length > 0 && (!person || who.name.trim().length > 0);

  function paintWhat() {
    return `<div class="awrap"><div class="acard"><div class="ahead"><h1>${person ? "Share with a person" : "Add a device"}</h1>
      <p class="aorigin">${person
        ? "Choose what they get. Then they run one line on their computer, and the keys arrive sealed to it."
        : "Choose what it gets. Then you run one line on it, and the keys arrive sealed to that machine."}</p></div>
      ${choices ? `${whoHtml()}<div class="dtabs" role="tablist">${TABS.map(([id, name]) =>
        `<button role="tab" aria-selected="${tab === id}" data-dev-tab="${id}">${name}</button>`).join("")}</div>
      ${tab === "keys" ? `<div class="akey"><input id="dev-search" placeholder="Find a key" value="${esc(search)}" autocomplete="off"></div>` : ""}
      <div class="dlist" id="dev-list">${listHtml()}</div>
      <div id="dev-summary">${summaryHtml()}</div>
      <button class="alink" data-dev-advanced>${advancedOpen ? "Hide advanced" : "Advanced: duration, hosts, apps"}</button>
      ${advancedHtml()}` : `<p class="aorigin">${busy ? "Reading what this machine holds…" : ""}</p>`}
      ${errorHtml()}
      <div class="arow"><button class="aghost" data-dev-close ${busy ? "disabled" : ""}>Cancel</button>
        <button class="aprimary" data-dev-make ${busy || !ready() ? "disabled" : ""}>${busy && choices ? "Making invite…" : "Make invite"}</button></div>
    </div></div>`;
  }

  function paintInvite() {
    const install = `<code class="mono">uv tool install git+https://github.com/LiamVisionary/passbook</code>`;
    return `<div class="awrap"><div class="acard"><div class="ahead"><h1>${person ? `Send this line to ${esc(who.name.trim())}` : "Run this on the new machine"}</h1>
      <p class="aorigin">${person ? "They get" : "It gets"} <b>${plural(invite.keys.length, "key")}</b>${adv.live ? (person ? " and stay up to date" : " and stays up to date") : ""}. The line works once, for 15 minutes.</p></div>
      <div class="dcmd"><code class="mono">${esc(invite.command)}</code>
        <button class="iconbtn ${copied ? "done" : ""}" data-dev-copy title="${copied ? "Copied" : "Copy"}" aria-label="Copy the command">${copied ? "Copied" : "Copy"}</button></div>
      <p class="anote">${person
        ? `They run it on their own computer. Anyone with this line can join during those 15 minutes, so send it only to them, somewhere private.
        They need PassBook first: ${install}`
        : `Anyone with this line can join during those 15 minutes, so paste it only into that machine.
        No PassBook there yet? Install it first: ${install}`}</p>
      <p class="dwait"><span class="dspin" aria-hidden="true"></span> Waiting for ${person ? "them" : "it"} to join. Keep PassBook open here.</p>
      ${errorHtml()}
      <div class="arow"><button class="aghost" data-dev-cancel ${busy ? "disabled" : ""}>Cancel invite</button>
        <button class="aprimary" data-dev-hide>Hide</button></div>
    </div></div>`;
  }

  function paintDone() {
    const kept = adv.live ? " while this machine's vault is open" : "";
    return `<div class="awrap"><div class="acard"><div class="adone"><h1>${esc(person ? who.name.trim() || joined.label : joined.label)} joined</h1>
      ${person
        ? `<p class="aorigin">${esc(joined.label)} has ${plural(joined.keys.length, "key")}${adv.live ? ` and stays up to date${kept}` : ""}.
            ${who.role === "use" ? "Their apps can use the keys, and PassBook never shows the keys to them." : "They can use the keys and see them."}
            You can stop sharing with them from Devices at any time.</p>`
        : `<p class="aorigin">It has ${plural(joined.keys.length, "key")}${adv.live ? ` and stays up to date${kept}` : ""}.
            It checks for changes every ten minutes. You can unlink it from Devices at any time.</p>`}
      <p class="aorigin">${person ? "Their computer's code" : "Its code"}: <b class="mono">${esc(joined.fingerprint)}</b></p></div>
      <div class="arow"><span></span><button class="aprimary" data-dev-done>Done</button></div></div></div>`;
  }

  function refreshList() {
    const list = container.querySelector("#dev-list"), summary = container.querySelector("#dev-summary");
    if (list) { list.innerHTML = listHtml(); wireList(); }
    if (summary) summary.innerHTML = summaryHtml();
    refreshMake();
  }
  function refreshMake() {
    const make = container.querySelector("[data-dev-make]");
    if (make) make.disabled = busy || !ready();
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
    busy = true; fail(""); paint(true);
    try {
      const chosen = {
        selection: { all: picked.all, keys: [...picked.keys], groups: [...picked.groups], projects: [...picked.projects], umbrellas: [...picked.umbrellas] },
        advanced: { days: adv.days, fixed: !adv.live, hosts: words(adv.hosts), commands: words(adv.commands), apps: words(adv.apps) },
      };
      invite = person
        ? await invoke("team_invite", { name: who.name.trim(), role: who.role, ...chosen })
        : await invoke("link_invite", chosen);
      step = "invite"; copied = false;
      stopPolling();
      poll = setInterval(check, 2500);
    } catch (caught) { fail(said(caught)); }
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
      else {
        // A plan that has no room left says so here, with `code` naming which limit it was.
        fail(row.detail || `The invite ran out before ${person ? "they" : "a machine"} joined. Make a new one.`, row.code || "");
        step = "what"; invite = null; open = true;
      }
      paint(true); repaint();
    } catch { /* the relay or the CLI hiccuped; the next tick asks again */ }
    finally { checking = false; }
  }

  function paint(force = false) {
    if (!open) return false;
    const id = `${mode}-${step}-${tab}-${busy}-${advancedOpen}-${Boolean(choices)}-${copied}-${who.role}-${error}`;
    if (!force && container.dataset.adddevice === id) return true;
    container.dataset.adddevice = id;
    container.hidden = false;
    container.innerHTML = step === "invite" ? paintInvite() : step === "done" ? paintDone() : paintWhat();
    const on = (selector, handler) => { const el = container.querySelector(selector); if (el) el.onclick = handler; };
    on("[data-dev-close]", close);
    on("[data-dev-done]", close);
    on("[data-dev-hide]", hide);
    on("[data-dev-plan]", () => { close(); plans?.open?.(); });
    on("[data-dev-make]", () => void make());
    on("[data-dev-advanced]", () => { readAdvanced(); advancedOpen = !advancedOpen; paint(true); });
    on("[data-dev-copy]", async () => {
      try { await navigator.clipboard.writeText(invite.command); copied = true; paint(true); }
      catch { fail("Could not copy. Select the line and copy it by hand."); paint(true); }
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
    const name = container.querySelector("#dev-name");
    if (name) name.oninput = () => { who.name = name.value; refreshMake(); };
    container.querySelectorAll("[data-dev-role]").forEach((b) => b.onclick = () => {
      readAdvanced(); who.role = b.dataset.devRole; paint(true);
      container.querySelector(`[data-dev-role="${who.role}"]`)?.focus();
    });
    wireList();
    return true;
  }

  /** Put the sheet away with the invite still out; Devices says one is waiting and brings it back. */
  function hide() { open = false; delete container.dataset.adddevice; container.hidden = true; repaint(); }

  // Escape leaves: it cancels a choice not made yet, and only hides an invite that is already out.
  // Not while the press is inside something else (the palette is drawn above this sheet).
  document.addEventListener("keydown", (event) => {
    if (!open || busy || event.key !== "Escape" || event.defaultPrevented) return;
    if (!container.contains(event.target) && event.target !== document.body) return;
    event.preventDefault();
    if (step === "invite") hide(); else close();
  });

  return {
    start,
    paint,
    /** An invite is still out: Devices says so, and pressing it brings the sheet back. */
    waiting: () => Boolean(invite && step === "invite"),
    resume: () => { if (invite) { open = true; paint(true); } },
  };
};
