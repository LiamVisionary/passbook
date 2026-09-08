// SPDX-License-Identifier: Apache-2.0
// This sheet uses names-only broker metadata. Passwords go only to the native
// decision command; the requesting application receives a signed status poll.
window.createPassbookAuthorization = function ({ invoke, container, esc, repaint }) {
  let current = null, choice = "", background = false, consent = false;
  let busy = false, error = "", done = null, failure = null, needsReload = false, generation = 0;
  const freshName = (rows) => {
    let name = "hivemindos", suffix = 1;
    while (rows.some((row) => row.id === name)) name = `hivemindos-${++suffix}`;
    return name;
  };
  const selected = () => current?.workspaces.find((row) => row.id === choice);
  const creating = () => choice === "new" || !selected()?.hasProfile;
  function paint(force = false) {
    if (!current && !done && !failure) return false;
    const paintedId = failure ? `failure-${failure.id}` : done ? `done-${done.request.id}` : current.request.id;
    if (!force && container.dataset.authorizationId === paintedId) return true;
    container.dataset.authorizationId = paintedId;
    container.hidden = false;
    if (failure) {
      container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>App authorization unavailable</h1><p class="aerr" role="alert">${esc(failure.error)}</p></div><div class="arow"><button class="aprimary" data-auth-close>Close</button></div></div></div>`;
      container.querySelector("[data-auth-close]").onclick = async () => { await invoke("dismiss_authorization", { id: failure.id }); failure = null; delete container.dataset.authorizationId; container.hidden = true; repaint(); };
      return true;
    }
    if (done) {
      const allowed = done.request.status === "approved";
      container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>${allowed ? "HivemindOS authorized" : "Authorization declined"}</h1>
        <p class="aorigin">${allowed ? "Return to HivemindOS to continue. Each agent still needs permission for its work." : "This request did not grant access."}</p></div>
        ${done.backgroundService?.ok === false ? '<p class="aerr">Connected, but background startup needs attention. Reopen the connection in HivemindOS to retry.</p>' : ""}
        <div class="arow"><button class="aprimary" data-auth-done>Done</button></div></div></div>`;
      container.querySelector("[data-auth-done]").onclick = () => { done = null; delete container.dataset.authorizationId; container.hidden = true; repaint(); };
      return true;
    }
    const rows = current.workspaces;
    container.innerHTML = `<div class="awrap"><div class="acard"><div class="ahead"><h1>Authorize HivemindOS?</h1>
      <p class="aorigin">Allow this application to use a workspace for connected services and individually approved agent tasks.</p>
      <p class="aorigin">Match this code with HivemindOS: <b>${esc(current.request.code)}</b></p></div>
      <form class="akeys" id="authorize-form">
        <div class="akey"><label class="aplain" for="authorize-workspace">Workspace</label><select id="authorize-workspace" ${busy || current.workspace ? "disabled" : ""}>
          ${rows.map((row) => `<option value="${esc(row.id)}" ${choice === row.id ? "selected" : ""}>${esc(row.id === "main" && !row.hasProfile ? "HivemindOS (your existing keys)" : row.name)}</option>`).join("")}
          ${!current.workspace ? `<option value="new" ${choice === "new" ? "selected" : ""}>Create a HivemindOS workspace</option>` : ""}
        </select></div>
        <div class="akey"><label class="aplain" for="authorize-password">${creating() ? "Create a PassBook password" : "PassBook password"}</label>
          <input id="authorize-password" type="password" autocomplete="${creating() ? "new-password" : "current-password"}" maxlength="4096" ${creating() ? 'minlength="8"' : ""} required ${busy ? "disabled" : ""}></div>
        ${creating() ? '<div class="akey"><label class="aplain" for="authorize-confirm">Confirm password</label><input id="authorize-confirm" type="password" autocomplete="new-password" maxlength="4096" required></div>' : ""}
        <label class="aorigin"><input id="authorize-background" type="checkbox" ${background ? "checked" : ""} ${busy || !current.backgroundAvailable ? "disabled" : ""}> Keep approved tasks running while I am away</label>
        ${!current.backgroundAvailable ? '<p class="aorigin">Background access is unavailable on this device. Approved tasks can use keys while PassBook is open.</p>' : ""}
        <label class="aorigin"><input id="authorize-consent" type="checkbox" ${consent ? "checked" : ""} ${busy ? "disabled" : ""}> I approve this workspace and background choice for HivemindOS</label>
        <p class="aorigin">Only continue if you started this request. The code matches the requesting installation; it does not verify the app publisher.</p>
        ${error ? `<p class="aerr" role="alert">${esc(error)}</p>` : ""}
        <div class="arow"><button class="aghost" type="button" data-auth-deny ${busy ? "disabled" : ""}>Decline</button>
          <button class="aprimary" type="submit" ${busy || !consent ? "disabled" : ""}>${busy ? "Authorizing…" : "Authorize HivemindOS"}</button></div>
      </form><button class="alink" data-auth-later ${busy ? "disabled" : ""}>Close and decide later</button></div></div>`;
    container.querySelector("#authorize-workspace").onchange = (event) => { choice = event.target.value; consent = false; error = ""; paint(true); };
    container.querySelector("#authorize-background").onchange = (event) => { background = event.target.checked; };
    container.querySelector("#authorize-consent").onchange = (event) => { consent = event.target.checked; container.querySelector('[type="submit"]').disabled = !consent; };
    container.querySelector("#authorize-password").oninput = () => { error = ""; container.querySelector('[role="alert"]')?.remove(); };
    container.querySelector("[data-auth-deny]").onclick = () => decide("deny", "");
    container.querySelector("[data-auth-later]").onclick = async () => {
      try { await invoke("dismiss_authorization", { id: current.request.id }); current = null; delete container.dataset.authorizationId; container.hidden = true; repaint(); }
      catch (caught) { error = String(caught); paint(true); }
    };
    container.querySelector("#authorize-form").onsubmit = (event) => {
      event.preventDefault();
      const password = container.querySelector("#authorize-password").value;
      if (creating() && password !== container.querySelector("#authorize-confirm").value) {
        error = "The passwords do not match."; paint(true); return;
      }
      void decide("allow", password);
    };
    return true;
  }
  async function decide(decision, password) {
    if (!current || busy) return;
    const id = current.request.id;
    busy = true; error = ""; paint(true);
    try {
      done = await invoke("decide_authorization", { id, decision, workspace: choice === "new" ? freshName(current.workspaces) : choice,
        createWorkspace: creating(), background, consent, password });
      current = null;
    } catch (caught) { error = String(caught); }
    finally { password = ""; busy = false; paint(true); if (needsReload) { needsReload = false; void load(); } }
  }
  async function load() {
    if (busy) { needsReload = true; return; }
    const loading = ++generation;
    try {
      const next = await invoke("pending_authorization");
      if (loading !== generation) return;
      if (next?.ok === false) { failure = next; current = null; done = null; repaint(); paint(true); return; }
      if (!next || current?.request.id === next.request.id) return;
      current = next; done = null; failure = null; error = ""; consent = false;
      choice = next.workspace || (next.workspaces.some((row) => row.id === "main" && !row.hasProfile) ? "main" : "new");
      background = next.backgroundAvailable;
      repaint(); paint(true); container.querySelector("input")?.focus();
    } catch (caught) {
      // A failed lookup is not an authorization request. Preserve any current
      // reviewed request and show the failure without inventing a connection.
      if (current) { error = String(caught); paint(true); }
    }
  }
  return { active: () => Boolean(current || done || failure), paint, load };
};
