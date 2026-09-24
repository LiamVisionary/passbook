// SPDX-License-Identifier: Apache-2.0
// HivemindOS on the web asking to link a browser to a workspace (passbook://link). Names only on
// this sheet: the password goes to the native decision command, and keys are sealed by the CLI to
// the browser. The code check is the link protocol's second factor, so it is its own tick box.
window.createPassbookWebLink = function ({ invoke, container, esc, repaint }) {
  let current = null, choice = "", matched = false, busy = false, error = "", done = null, failure = null;
  let needsReload = false, generation = 0;
  const close = () => { current = null; done = null; failure = null; delete container.dataset.weblinkId; container.hidden = true; repaint(); };
  function paint(force = false) {
    if (!current && !done && !failure) return false;
    const paintedId = failure ? `failure-${failure.id}` : done ? `done-${done.linked.did}` : current.request.id;
    if (!force && container.dataset.weblinkId === paintedId) return true;
    container.dataset.weblinkId = paintedId;
    container.hidden = false;
    if (failure) {
      container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>Browser link unavailable</h1><p class="aerr" role="alert">${esc(failure.error)}</p></div><div class="arow"><button class="aprimary" data-link-close>Close</button></div></div></div>`;
      container.querySelector("[data-link-close]").onclick = async () => { try { await invoke("dismiss_web_link", { id: failure.id }); } catch { /* already gone */ } close(); };
      return true;
    }
    if (done) {
      container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>Browser linked</h1>
        <p class="aorigin">${esc(done.linked.label)} now has the ${esc(String(done.linked.keys))} keys in ${esc(done.linked.workspace)}, and stays up to date while PassBook is open.</p>
        <p class="aorigin">The browser shows this code for PassBook: <b>${esc(done.issuerFingerprint)}</b></p></div>
        <div class="arow"><button class="aprimary" data-link-done>Done</button></div></div></div>`;
      container.querySelector("[data-link-done]").onclick = close;
      return true;
    }
    const request = current.request;
    container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>Link ${esc(request.label)}?</h1>
      <p class="aorigin">${esc(request.site)} wants the keys in one of your workspaces. The browser gets every key in the workspace you choose, and stays up to date while PassBook is open here.</p>
      <p class="aorigin">The browser shows a code. It must be exactly <b>${esc(request.code)}</b></p></div>
      <form class="akeys" id="weblink-form">
        <label class="aorigin"><input id="weblink-matched" type="checkbox" ${matched ? "checked" : ""} ${busy ? "disabled" : ""}> The browser shows this code</label>
        <div class="akey"><label class="aplain" for="weblink-workspace">Workspace</label><select id="weblink-workspace" ${busy ? "disabled" : ""}>
          ${current.workspaces.map((row) => `<option value="${esc(row.id)}" ${choice === row.id ? "selected" : ""} ${row.hasProfile === false ? "disabled" : ""}>${esc(row.name)}${row.hasProfile === false ? " (no password)" : ""}</option>`).join("")}
        </select></div>
        <div class="akey"><label class="aplain" for="weblink-password">PassBook password for this workspace</label>
          <input id="weblink-password" type="password" autocomplete="current-password" maxlength="4096" required ${busy ? "disabled" : ""}></div>
        <p class="aorigin">Only continue if you started this from HivemindOS just now. Unlinking later stops new keys reaching the browser, not the ones it already has.</p>
        ${choice ? "" : `<p class="aerr" role="alert">None of your workspaces has a password yet, so none can be linked. Set a password on one, then start again from HivemindOS.</p>`}
        ${error ? `<p class="aerr" role="alert">${esc(error)}</p>` : ""}
        <div class="arow"><button class="aghost" type="button" data-link-deny ${busy ? "disabled" : ""}>Decline</button>
          <button class="aprimary" type="submit" ${busy || !matched || !choice ? "disabled" : ""}>${busy ? "Linking…" : "Link browser"}</button></div>
      </form><button class="alink" data-link-later ${busy ? "disabled" : ""}>Close and decide later</button></div></div>`;
    container.querySelector("#weblink-workspace").onchange = (event) => { choice = event.target.value; error = ""; };
    container.querySelector("#weblink-matched").onchange = (event) => { matched = event.target.checked; container.querySelector('[type="submit"]').disabled = !matched || !choice; };
    container.querySelector("#weblink-password").oninput = () => { error = ""; container.querySelector('[role="alert"]')?.remove(); };
    container.querySelector("[data-link-deny]").onclick = () => decide("deny", "");
    container.querySelector("[data-link-later]").onclick = async () => {
      try { await invoke("dismiss_web_link", { id: request.id }); close(); } catch (caught) { error = String(caught); paint(true); }
    };
    container.querySelector("#weblink-form").onsubmit = (event) => {
      event.preventDefault();
      void decide("allow", container.querySelector("#weblink-password").value);
    };
    return true;
  }
  async function decide(decision, password) {
    if (!current || busy) return;
    const id = current.request.id;
    busy = true; error = ""; paint(true);
    try {
      // The code sent back is the one the owner just ticked as matching; the CLI checks it again.
      const answer = await invoke("decide_web_link", { id, decision, workspace: choice, code: matched ? current.request.code : "", password });
      if (decision === "deny") { busy = false; close(); return; }
      done = answer; current = null;
    } catch (caught) { error = String(caught); }
    finally { password = ""; busy = false; paint(true); if (needsReload) { needsReload = false; void load(); } }
  }
  async function load() {
    if (busy) { needsReload = true; return; }
    const loading = ++generation;
    try {
      const next = await invoke("pending_web_link");
      if (loading !== generation) return;
      if (next?.ok === false) { failure = next; current = null; done = null; repaint(); paint(true); return; }
      if (!next || current?.request.id === next.request.id) return;
      current = next; done = null; failure = null; error = ""; matched = false;
      // Only a workspace with a password can be linked: the password is how linking is confirmed.
      const linkable = next.workspaces.filter((row) => row.hasProfile !== false);
      choice = linkable.some((row) => row.id === "hivemindos") ? "hivemindos" : linkable[0]?.id || "";
      repaint(); paint(true); container.querySelector("input")?.focus();
    } catch (caught) {
      if (current) { error = String(caught); paint(true); }
    }
  }
  return { active: () => Boolean(current || done || failure), paint, load };
};
