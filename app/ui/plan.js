// SPDX-License-Identifier: Apache-2.0
// The plan this PassBook is on, and the three things a paid plan adds: a backup kept on the relay,
// answering requests from a phone, and sharing keys with other people. Four sheets, drawn into the
// same container as Add a device.
//
// Nothing here opens an address. Paying and billing happen in the person's browser, which the CLI
// opens; this window is told that it did and then asks, every few seconds, whether the plan changed.
// A passphrase goes from its field to the app and on to the CLI's stdin, and is not kept here past
// the step that needs it. The two things shown once (a backup's code, the link a phone opens) are
// text on screen, copied with the same copy the pairing code uses.
//
// A relay somebody runs themselves has no billing at all (`billing` is null), and a hosted one can
// say plans are not on sale yet (`onSale` false). `canBuy` is the one question both answer, and no
// button that spends money is drawn or acted on without it.
window.createPassbookPlan = function ({ invoke, container, esc, repaint, copy, onStoreChanged, invitePerson }) {
  const PLAN_NAME = { free: "PassBook Free", sync: "PassBook Sync", teams: "PassBook Teams", "self-hosted": "Your own relay" };
  const LIMIT_CODES = new Set(["machine_limit", "seat_limit", "not_included"]);
  const ROLE = { use: "Can use", read: "Can use and see" };
  const said = (caught) => String(caught?.message ?? caught ?? "").replace(/^Error:\s*/, "");
  const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
  const money = (n) => (Number.isInteger(Number(n)) ? `$${Number(n)}` : `$${Number(n).toFixed(2)}`);
  const day = (iso) => {
    const then = Date.parse(iso);
    return Number.isFinite(then) ? new Date(then).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : "";
  };
  const size = (bytes) => {
    const n = Number(bytes) || 0;
    return n < 1024 ? `${n} bytes` : n < 1024 * 1024 ? `${Math.round(n / 1024)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
  };
  const list = (parts) => (parts.length < 2 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`);

  // ── what is known about the plan ─────────────────────────────────────────
  let status = null, statusError = "", checking = false, loading = null;
  let team = null, events = [];

  // ── the sheet on screen ──────────────────────────────────────────────────
  let sheet = "", step = "home", busy = "", error = "", errorRefused = false, note = "", confirming = "";
  let timer = null, asking = false, copied = false, copiedTimer = null;
  // Plan: which offer is showing, how it is paid, for how many people, and what the plan was before a
  // payment page was opened (so "it changed" can be told from "still waiting").
  let offer = "sync", yearly = false, seats = 0, seatsTouched = false, teamsOpen = false, before = "", lastOrder = null;
  // Backup: the list, the backup just made (its code is shown once), and a restore in progress.
  let backups = null, backupAllowed = null, made = null, saved = false;
  // The passphrase for a backup being made: one PassBook generated (the default, shown once, held
  // only until the backup is stored), or the person's own when they ask for that instead.
  let phrase = { made: "", own: false, kept: false, failed: "" };
  let restoring = { id: "", label: "", code: "", passphrase: "", preview: null, result: null };
  // Phone: the list, and the phone that has been given a link but is not confirmed yet.
  let phones = null, pending = null;
  // People: who was just removed, with the keys worth replacing.
  let removed = null;

  const limit = (name) => { const n = Number(status?.limits?.[name]); return Number.isFinite(n) && n > 0 ? n : 0; };
  const used = (name) => Number(status?.used?.[name]) || 0;
  const planName = () => PLAN_NAME[status?.plan] || "PassBook";
  /** Whether anything can be bought here: a relay with billing, that says plans are on sale. */
  const canBuy = () => Boolean(status?.billing && status.billing.onSale);
  /** Whether this plan is paid for here, so there is a card, a renewal and something to cancel. */
  const paidHere = () => status?.billing?.source === "stripe" && status.plan !== "free";
  const prices = () => status?.billing?.prices || {};
  const seatBounds = () => ({ least: Number(prices().teams?.minSeats) || 2, most: Number(prices().teams?.maxSeats) || 50 });
  const signature = (s) => JSON.stringify([s?.plan, s?.billing?.interval, s?.billing?.seats, s?.billing?.status, s?.billing?.renews, s?.billing?.paidUntil]);

  /** Whether a sentence or a row's code is the plan saying no, rather than something going wrong. */
  function refused(sentence, code = "") {
    return LIMIT_CODES.has(code) || /not included|PassBook (Sync|Teams)/i.test(String(sentence || ""));
  }

  /** What the button beside a refusal says, or nothing when there is nothing to buy here. */
  function offerLabel(code = "") {
    if (!canBuy()) return "";
    if (code === "seat_limit") return status.plan === "teams" ? (paidHere() ? "Add a seat" : "") : "Get PassBook Teams";
    return status.plan === "free" ? "Get PassBook Sync" : "Manage plan";
  }

  /** How many people the stepper shows: what the plan has, until somebody presses it. */
  function seatsFromPlan() {
    const { least, most } = seatBounds();
    seats = Math.min(most, Math.max(least, Number(status?.billing?.seats) || least));
    seatsTouched = false;
  }

  function adopt(answer) {
    if (!answer || typeof answer !== "object" || !answer.plan) return;
    status = answer; statusError = "";
    if (!seatsTouched) seatsFromPlan();
  }

  async function loadTeam() {
    if (!status || (!limit("seats") && !used("members"))) { team = null; events = []; return; }
    try { team = await invoke("team_list"); }
    catch { /* the plan line already says what is known; a list that would not load stays as it was */ }
    if (team?.members?.length) {
      try { events = (await invoke("team_activity"))?.events || []; } catch { /* as above */ }
    } else events = [];
  }

  /** Ask for the plan, then for the people on it. Never throws: the pages say "could not check". */
  function load() {
    if (loading) return loading;
    checking = true;
    loading = (async () => {
      try { adopt(await invoke("plan_status")); }
      catch (caught) { statusError = said(caught) || "PassBook did not answer."; }
      checking = false;
      repaint();
      await loadTeam();
    })().finally(() => { loading = null; repaint(); refreshSheet(); });
    repaint();
    return loading;
  }

  /** Redraw an open sheet after news arrived, unless somebody is typing into it. */
  function refreshSheet() {
    if (sheet && !busy && !container.querySelector("input:not([type=checkbox])")) paint(true);
  }

  // ── opening and closing ──────────────────────────────────────────────────
  function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }
  function clearSaid() { error = ""; errorRefused = false; note = ""; }
  function fail(caught) { error = said(caught); errorRefused = refused(error); }
  function forget() {
    restoring.passphrase = "";
    restoring = { id: "", label: "", code: "", passphrase: "", preview: null, result: null };
    made = null; saved = false; pending = null; removed = null; copied = false; clearTimeout(copiedTimer);
    phrase = { made: "", own: false, kept: false, failed: "" };
  }

  function close() {
    // A phone that was given a link and never confirmed is turned away, not left half linked.
    if (pending?.id) invoke("phone_remove", { id: pending.id }).catch(() => {});
    stopTimer(); forget(); clearSaid();
    sheet = ""; step = "home"; busy = ""; confirming = "";
    delete container.dataset.plansheet; container.hidden = true; repaint();
  }

  function open(which, options = {}) {
    stopTimer(); forget(); clearSaid();
    sheet = which; step = "home"; busy = ""; confirming = "";
    if (which === "plan") {
      seatsFromPlan();
      yearly = false;
      offer = options.want === "teams" ? "teams" : "sync";
      teamsOpen = options.want === "teams";
      if (!status && !loading) void load();
      // A payment page opened earlier may still be waiting to be finished.
      if (status?.billing?.checkoutOpen && canBuy()) { step = "paying"; before = signature(status); startPaidCheck(); }
    }
    if (which === "backup") void loadBackups();
    if (which === "phone") void loadPhones();
    if (which === "people") {
      if (options.remove) confirming = `member:${options.remove}`;
      if (!team) void loadTeam().then(() => { if (sheet === "people") paint(true); });
    }
    // A question that is already open (Remove, pressed on Devices) starts on Cancel, never on the yes.
    repaint(); paint(true, confirming ? "[data-plan-no]" : "");
  }

  // ── pieces every sheet uses ──────────────────────────────────────────────
  /** What went wrong and, when the plan is why, the button that opens the plans right here. */
  function errorHtml(code = "") {
    if (!error) return "";
    const label = errorRefused && sheet !== "plan" ? offerLabel(code) : "";
    return `<div class="aoffer"><p class="aerr" role="alert">${esc(error)}</p>${
      label ? `<button class="act primary" data-plan-goto="${code === "seat_limit" ? "teams" : "sync"}">${esc(label)}</button>` : ""}</div>`;
  }
  const noteHtml = () => (note ? `<p class="pgood" role="status">${esc(note)}</p>` : "");
  /** Say what is wrong with what was typed, without redrawing the form and emptying it. */
  function complain(words, field) {
    const slot = container.querySelector("[data-plan-says]");
    if (!slot) { error = words; errorRefused = false; paint(true, field); return; }
    container.querySelector(".aoffer")?.remove();
    slot.textContent = words; slot.hidden = false;
    container.querySelector(field)?.focus();
  }
  const waitHtml = (words) => `<p class="dwait" role="status"><span class="dspin" aria-hidden="true"></span> ${esc(words)}</p>`;
  const one = (label, attr) => `<div class="arow" style="grid-template-columns: 1fr;"><button class="aprimary" ${attr}>${label}</button></div>`;
  /** Something that is part of a paid plan, said once, with the button that gets it. */
  function partOf(sentence, code) {
    const label = offerLabel(code);
    return `<div class="aoffer"><p class="anote">${esc(sentence)}</p>${
      label ? `<button class="act primary" data-plan-goto="${code === "seat_limit" ? "teams" : "sync"}">${esc(label)}</button>` : ""}</div>`;
  }
  /** The question a press asks before it acts, under the row that asked it. Cancel is first. A
   *  question about removing something wears the warning color; one about paying does not. */
  function confirmHtml(id, sentence, yes, removes = true) {
    if (confirming !== id) return "";
    return `<div class="confirmstrip ${removes ? "" : "calm"}" role="group" aria-label="${esc(yes)}?"><span class="grow">${esc(sentence)}</span>
      <button class="act" data-plan-no>Cancel</button>
      <button class="act ${removes ? "destructive" : "primary"}" data-plan-yes="${esc(id)}" ${busy ? "disabled" : ""}>${esc(yes)}</button></div>`;
  }
  const copyHtml = (text, label) => `<div class="dcmd"><code class="mono">${esc(text)}</code>
    <button class="iconbtn ${copied ? "done" : ""}" data-plan-copy title="${copied ? "Copied" : "Copy"}" aria-label="${esc(label)}">${copied ? "Copied" : "Copy"}</button></div>`;

  // ── Plan ─────────────────────────────────────────────────────────────────
  function priceLine() {
    const b = status.billing, p = prices();
    if (status.plan === "sync" && p.sync) {
      return b.interval === "year" ? `${money(p.sync.year)} a year` : b.interval === "month" ? `${money(p.sync.month)} a month` : "";
    }
    if (status.plan === "teams" && p.teams && b.seats) {
      return `${plural(b.seats, "person", "people")}, ${money(b.seats * p.teams.seatMonth)} a month`;
    }
    return "";
  }

  /** Where the plan stands, in one or two sentences: who pays, how much, and until when. */
  function standing() {
    const b = status.billing;
    if (!b) {
      return status.plan === "self-hosted" ? "This relay is one you run yourself. There is nothing to buy or renew here."
        : "This relay does not sell plans.";
    }
    if (b.source === "hivemindos") return "Included with your HivemindOS plan. There is nothing to pay or cancel here.";
    if (b.source === "lender") return "Covered by the PassBook that lends keys to this one. There is nothing to pay or cancel here.";
    if (status.plan === "free") return "You are on the free plan.";
    if (b.status === "past_due") return "The last payment did not go through. Update your card to keep this plan.";
    const until = day(b.paidUntil);
    if (b.renews === false) return until ? `Ends on ${until}. Until then nothing changes.` : "This plan will not renew.";
    const parts = [priceLine(), until ? `Renews on ${until}` : ""].filter(Boolean);
    return parts.length ? `${parts.join(". ")}.` : "";
  }

  /** What the plan includes and how much of it is used: the same four lines whatever the plan. */
  function factsHtml() {
    const machines = limit("machines"), people = Number(team?.seats?.limit) || limit("seats");
    const rows = [["Computers", machines ? `${used("machines")} of ${machines}` : String(used("machines")), machines && used("machines") >= machines]];
    rows.push(["People you share with", people ? `${Number(team?.seats?.used ?? used("members")) || 0} of ${people}` : null, false]);
    rows.push(["Backup on the relay", status.limits?.backup ? (used("backups") ? `${plural(used("backups"), "backup")} kept` : "Included") : null, false]);
    rows.push(["Approve from your phone", status.limits?.approvals ? (used("phones") ? `${plural(used("phones"), "phone")} linked` : "Included") : null, false]);
    return `<dl class="pfacts">${rows.map(([name, value, full]) =>
      `<div class="pfact"><dt>${name}</dt><dd class="${value === null ? "pno" : full ? "pfull" : ""}">${value === null ? "Not included" : esc(value)}</dd></div>`).join("")}</dl>`;
  }

  function stepperHtml() {
    const { least, most } = seatBounds();
    return `<div class="pstep" role="group" aria-label="How many people">
      <button data-plan-seat="-1" aria-label="One person fewer" ${busy || seats <= least ? "disabled" : ""}>\u2212</button>
      <output aria-live="polite">${plural(seats, "person", "people")}</output>
      <button data-plan-seat="1" aria-label="One person more" ${busy || seats >= most ? "disabled" : ""}>+</button></div>`;
  }

  /** What is being bought right now, as the app command takes it. */
  function order() {
    const which = status.plan === "free" ? offer : "teams";
    return which === "sync" ? { plan: "sync", yearly, seats: null } : { plan: "teams", yearly: false, seats };
  }
  function orderPrice() {
    const p = prices(), o = order();
    if (o.plan === "sync") return p.sync ? (yearly ? `${money(p.sync.year)} a year` : `${money(p.sync.month)} a month`) : "";
    return p.teams ? `${money(seats * p.teams.seatMonth)} a month` : "";
  }

  /** The plans for sale. Only ever called behind `canBuy()`. */
  function offersHtml() {
    const p = prices(), fresh = status.plan === "free", which = order().plan;
    const tabs = fresh ? `<div class="dtabs two" role="tablist">${[["sync", "PassBook Sync"], ["teams", "PassBook Teams"]].map(([id, name]) =>
      `<button role="tab" aria-selected="${offer === id}" data-plan-offer="${id}">${name}</button>`).join("")}</div>` : "";
    const sync = `<p class="aorigin">Up to 50 computers, an encrypted backup kept on the relay, and approving requests from your phone.</p>
      ${p.sync ? `<div class="apick" role="radiogroup" aria-label="How to pay">
        <button role="radio" aria-checked="${!yearly}" aria-pressed="${!yearly}" data-plan-yearly="0">Pay each month <span class="pprice">${money(p.sync.month)} a month</span></button>
        <button role="radio" aria-checked="${yearly}" aria-pressed="${yearly}" data-plan-yearly="1">Pay each year <span class="pprice">${money(p.sync.year)} a year</span></button></div>` : ""}`;
    const teams = `<p class="aorigin">Everything in PassBook Sync, and sharing keys with other people. Each person gets only the keys you choose.</p>
      <div class="pline"><span class="grow">People, you included</span>${stepperHtml()}</div>
      ${p.teams ? `<p class="dsub">${money(p.teams.seatMonth)} for each person each month. ${plural(seats, "person", "people")} is <b>${money(seats * p.teams.seatMonth)} a month</b>.</p>` : ""}`;
    const price = orderPrice();
    const body = `${tabs}${which === "sync" ? sync : teams}`;
    if (fresh) return `<div class="poffer">${body}</div>`;
    // A plan that is already paid for changes in place, with no payment page to be the second look.
    return teamsOpen ? `<div class="poffer"><h2>PassBook Teams</h2>${body}
        ${confirmHtml("move", `Your plan changes to PassBook Teams right away${price ? `, at ${price}` : ""}, and your next bill changes with it.`, "Change plan", false)}</div>`
      : `<button class="alink" data-plan-teams>Share keys with other people: PassBook Teams</button>`;
  }

  /** The one button that starts a payment. Only ever called behind `canBuy()`. */
  function buyHtml() {
    const price = orderPrice();
    const press = status.plan === "free" ? `Subscribe${price ? ` for ${price}` : ""}` : "Move to PassBook Teams";
    return `<button class="aprimary" data-plan-subscribe ${busy || confirming === "move" ? "disabled" : ""}>${
      busy === "subscribe" ? (status.plan === "free" ? "Opening your browser\u2026" : "Changing\u2026") : esc(press)}</button>`;
  }

  /** A plan paid for here: its card and invoices, how many people, and stopping or keeping it. */
  function manageHtml() {
    const b = status.billing, p = prices(), until = day(b.paidUntil);
    const changed = status.plan === "teams" && Number(b.seats) && seats !== Number(b.seats);
    const people = status.plan === "teams" ? `<div class="pline"><span class="grow">People, you included</span>${stepperHtml()}</div>
      ${changed ? `<div class="pline"><span class="grow dsub">${p.teams ? `${plural(seats, "person", "people")} is ${money(seats * p.teams.seatMonth)} a month. Your next bill changes with it.` : ""}</span>
        <button class="act primary" data-plan-seats ${busy ? "disabled" : ""}>${busy === "seats" ? "Changing\u2026" : `Change to ${plural(seats, "person", "people")}`}</button></div>` : ""}` : "";
    const ends = b.renews === false
      ? `<button class="act" data-plan-resume ${busy ? "disabled" : ""}>${busy === "resume" ? "Keeping\u2026" : "Keep my plan"}</button>`
      : `<button class="act danger" data-plan-cancel ${busy ? "disabled" : ""}>Stop renewing</button>`;
    return `${people}
      <div class="pacts"><button class="act" data-plan-billing ${busy ? "disabled" : ""}>${busy === "billing" ? "Opening your browser\u2026" : "Card and invoices"}</button>${ends}</div>
      ${confirmHtml("cancel", `Stop renewing ${planName()}? ${until ? `You keep it until ${until}, and then this goes back to the free plan.` : "It goes back to the free plan when the time already paid for ends."}`, "Stop renewing")}`;
  }

  function planHome() {
    if (!status) {
      return `<div class="ahead"><h1>Plan</h1></div>
        ${checking || loading ? waitHtml("Checking your plan.")
          : `<div class="aoffer"><p class="aerr" role="alert">PassBook could not check your plan. ${esc(statusError)}</p>
              <button class="act" data-plan-retry>Try again</button></div>`}
        ${one("Close", "data-plan-close")}`;
    }
    const b = status.billing;
    const late = b?.status === "past_due";
    // Whether a plan is offered at all. Without billing, or before plans are on sale, nothing below
    // draws a button that spends money.
    const selling = canBuy() && status.plan !== "teams";
    return `<div class="ahead"><h1>${esc(planName())}</h1>
        <p class="${late ? "aerr" : "aorigin"}">${esc(standing())}</p></div>
      ${factsHtml()}
      ${/* The relay's own sentence about what comes next. On the free plan it is written to follow a
           refusal ("...lifts this"), and the choices below already say it, so it is left out there. */
        status.more && status.plan !== "free" ? `<p class="anote">${esc(status.more)}</p>` : ""}
      ${paidHere() ? manageHtml() : ""}
      ${selling ? offersHtml() : b && !b.onSale && status.plan === "free" ? `<p class="anote">Paid plans are not on sale yet.</p>` : ""}
      ${noteHtml()}${errorHtml()}
      ${selling && (status.plan === "free" || teamsOpen)
        ? `<div class="arow"><button class="aghost" data-plan-close>Not now</button>${buyHtml()}</div>`
        : one("Done", "data-plan-close")}`;
  }

  function planPaying() {
    return `<div class="ahead"><h1>Finish paying in your browser</h1>
        <p class="aorigin">The payment page is open in your browser. This closes by itself when the payment goes through.</p></div>
      ${waitHtml("Waiting for the payment.")}
      ${lastOrder ? `<button class="alink" data-plan-again ${busy ? "disabled" : ""}>Open the payment page again</button>` : ""}
      ${errorHtml()}
      <div class="arow"><button class="aghost" data-plan-back>Choose a different plan</button>
        <button class="aprimary" data-plan-close>Close</button></div>`;
  }

  function planChanged() {
    const parts = [];
    if (limit("machines")) parts.push(`links up to ${plural(limit("machines"), "computer")}`);
    if (status.limits?.backup) parts.push("keeps an encrypted backup on the relay");
    if (status.limits?.approvals) parts.push("lets your phone approve requests");
    if (limit("seats")) parts.push("shares keys with other people");
    return `<div class="adone"><h1>You are on ${esc(planName())}</h1>
        <p class="aorigin">${parts.length ? `It ${esc(list(parts))}.` : ""} ${esc(standing())}</p></div>
      ${one("Done", "data-plan-close")}`;
  }

  async function subscribe() {
    // The guard the whole sheet rests on: nothing is bought where nothing is for sale.
    if (!canBuy() || busy) return;
    const wanted = order();
    if (status.plan !== "free" && confirming !== "move:yes") { confirming = "move"; paint(true, "[data-plan-no]"); return; }
    confirming = ""; busy = "subscribe"; clearSaid(); before = signature(status); paint(true);
    try {
      const answer = await invoke("plan_subscribe", wanted);
      lastOrder = wanted;
      if (answer?.changed) { adopt(answer); step = "changed"; void load(); }
      else { step = "paying"; startPaidCheck(); }
    } catch (caught) { fail(caught); }
    finally { busy = ""; paint(true); }
  }

  function startPaidCheck() { stopTimer(); timer = setInterval(checkPaid, 3000); }
  async function checkPaid() {
    if (asking) return;
    asking = true;
    try {
      const next = await invoke("plan_status");
      if (sheet !== "plan" || step !== "paying") return;
      adopt(next);
      if (signature(next) === before) return;
      stopTimer(); step = "changed"; void load(); paint(true);
    } catch { /* the relay or the CLI hiccuped; the next tick asks again */ }
    finally { asking = false; }
  }

  /** One plan command that answers with the plan as it now is. */
  async function change(name, command, args, done) {
    if (busy) return;
    confirming = ""; busy = name; clearSaid(); paint(true);
    try { seatsTouched = false; adopt(await invoke(command, args)); note = done(); void loadTeam().then(repaint); }
    catch (caught) { fail(caught); }
    finally { busy = ""; repaint(); paint(true); }
  }

  async function openBilling() {
    if (busy) return;
    busy = "billing"; clearSaid(); paint(true);
    try { await invoke("plan_billing"); note = "The page with your card and invoices is open in your browser."; }
    catch (caught) { fail(caught); }
    finally { busy = ""; paint(true); }
  }

  // ── Backup ───────────────────────────────────────────────────────────────
  async function loadBackups() {
    busy = "list"; paint(true);
    try {
      const answer = await invoke("backup_list");
      backups = answer?.backups || []; backupAllowed = answer?.allowed !== false;
    } catch (caught) { backups = backups || []; fail(caught); }
    finally { busy = ""; if (sheet === "backup" && step === "home") paint(true); }
  }

  function backupHome() {
    const allowed = backupAllowed ?? (status ? Boolean(status.limits?.backup) : true);
    const rows = (backups || []).map((row) => `<div class="prow"><span class="grow"><b>${esc(row.label || "A backup")}</b>
        <span class="dsub">${esc([day(row.at), size(row.bytes)].filter(Boolean).join(" \u00b7 "))}</span></span>
        <button class="act" data-backup-restore="${esc(row.id)}" ${busy ? "disabled" : ""}>Restore</button>
        <button class="act danger" data-backup-remove="${esc(row.id)}" ${busy ? "disabled" : ""}>Remove</button></div>
      ${confirmHtml(`backup:${row.id}`, "Remove this backup from the relay? It cannot be restored afterwards.", "Remove")}`).join("");
    return `<div class="ahead"><h1>Backup on the relay</h1>
        <p class="aorigin">An encrypted copy of your keys, kept on the relay. Only the passphrase you choose opens it.</p></div>
      ${backups === null ? waitHtml("Asking the relay what it keeps.")
        : `${allowed || errorRefused ? "" : partOf(status?.billing ? "Keeping a backup on the relay is part of PassBook Sync." : "This relay does not keep backups.", "not_included")}
           ${rows ? `<div class="plist">${rows}</div>` : allowed ? `<p class="dsub dempty">No backup yet.</p>` : ""}`}
      ${noteHtml()}${errorHtml("not_included")}
      <button class="alink" data-backup-code ${busy ? "disabled" : ""}>Restore from a code</button>
      <div class="arow"><button class="aghost" data-plan-close>Close</button>
        <button class="aprimary" data-backup-new ${busy || backups === null || !allowed ? "disabled" : ""}>Back up now</button></div>`;
  }

  /** Ask PassBook for a passphrase when the step opens. Asked once; the person may ask for another. */
  async function makePhrase() {
    phrase = { made: "", own: false, kept: false, failed: "" };
    paint(true);
    try {
      const answer = await invoke("backup_passphrase");
      phrase.made = String(answer?.passphrase || "");
      if (!phrase.made) phrase.failed = "PassBook could not make a passphrase.";
    } catch (caught) { phrase.failed = String(caught || "").replace(/^Error:\s*/, "") || "PassBook could not make a passphrase."; }
    if (sheet === "backup" && step === "store") paint(true, phrase.made ? "[data-plan-copy]" : "[data-phrase-own]");
  }

  function backupStore() {
    const why = `It encrypts the backup before it leaves this computer, so the relay holds something it cannot open.
      Nobody can reset it. If it is lost, so is the backup.`;
    if (phrase.own) {
      return `<div class="ahead"><h1>Use your own passphrase</h1>
          <p class="aorigin">${why}</p></div>
        <form class="akeys" id="pb-store">
          <div class="akey"><label class="aplain" for="pb-pass">Passphrase</label>
            <input id="pb-pass" type="password" autocomplete="new-password" maxlength="4096" ${busy ? "disabled" : ""}>
            <span class="ahint">At least 16 characters. Five random words is a good one. A short one can be guessed by anyone who gets a copy of the backup.</span></div>
          <div class="akey"><label class="aplain" for="pb-pass2">The same passphrase again</label>
            <input id="pb-pass2" type="password" autocomplete="new-password" maxlength="4096" ${busy ? "disabled" : ""}></div>
          <p class="aerr" role="alert" data-plan-says hidden></p>${errorHtml("not_included")}
          <button class="alink" type="button" data-phrase-made ${busy ? "disabled" : ""}>Let PassBook make one instead</button>
          <div class="arow"><button class="aghost" type="button" data-plan-home ${busy ? "disabled" : ""}>Back</button>
            <button class="aprimary" type="submit" ${busy ? "disabled" : ""}>${busy ? "Backing up\u2026" : "Back up"}</button></div>
        </form>`;
    }
    return `<div class="ahead"><h1>Save this passphrase</h1>
        <p class="aorigin">PassBook made it for this backup. Put it in your password manager now: it is shown once.</p></div>
      ${phrase.made ? copyHtml(phrase.made, "Copy the passphrase")
        : phrase.failed ? `<p class="aerr" role="alert">${esc(phrase.failed)}</p>` : waitHtml("Making a passphrase.")}
      <p class="anote">${why}</p>
      ${phrase.made ? `<label class="drow"><input type="checkbox" data-phrase-kept ${phrase.kept ? "checked" : ""} ${busy ? "disabled" : ""}><span class="grow">I have saved this passphrase</span></label>` : ""}
      ${errorHtml("not_included")}
      <button class="alink" type="button" data-phrase-own ${busy ? "disabled" : ""}>Use my own passphrase instead</button>
      <div class="arow"><button class="aghost" type="button" data-plan-home ${busy ? "disabled" : ""}>Back</button>
        <button class="aprimary" type="button" data-phrase-store ${busy || !phrase.made || !phrase.kept ? "disabled" : ""}>${busy ? "Backing up\u2026" : "Back up now"}</button></div>`;
  }

  function backupCode() {
    return `<div class="ahead"><h1>Save this code</h1>
        <p class="aorigin">${made.count === undefined ? "Your keys are" : `${plural(Number(made.count) || 0, "key")} ${Number(made.count) === 1 ? "is" : "are"}`} backed up. This code is shown once.</p></div>
      ${copyHtml(made.code, "Copy the backup code")}
      <p class="anote">Keep it somewhere other than the passphrase. The code fetches the backup and the passphrase opens it: a computer that has nothing needs both, and PassBook keeps neither.</p>
      <label class="drow"><input type="checkbox" data-backup-saved ${saved ? "checked" : ""}><span class="grow">I have saved this code</span></label>
      ${errorHtml()}
      ${one("Done", `data-backup-done ${saved ? "" : "disabled"}`)}`;
  }

  function backupRestore() {
    const from = restoring.id;
    return `<div class="ahead"><h1>Restore a backup</h1>
        <p class="aorigin">${from ? `From <b>${esc(restoring.label || "this backup")}</b>. ` : ""}Keys you already have stay as they are. First you see what it would add.</p></div>
      <form class="akeys" id="pb-restore">
        ${from ? "" : `<div class="akey"><label class="aplain" for="pb-code">Backup code</label>
          <input id="pb-code" class="mono" autocomplete="off" spellcheck="false" autocapitalize="off" maxlength="400" value="${esc(restoring.code)}" ${busy ? "disabled" : ""}>
          <span class="ahint">The code shown when the backup was made. It starts with pbb1.</span></div>`}
        <div class="akey"><label class="aplain" for="pb-rpass">Passphrase</label>
          <input id="pb-rpass" type="password" autocomplete="off" maxlength="4096" ${busy ? "disabled" : ""}></div>
        <p class="aerr" role="alert" data-plan-says hidden></p>${errorHtml("not_included")}
        <div class="arow"><button class="aghost" type="button" data-plan-home ${busy ? "disabled" : ""}>Back</button>
          <button class="aprimary" type="submit" ${busy ? "disabled" : ""}>${busy ? "Opening it\u2026" : "See what it holds"}</button></div>
      </form>`;
  }

  const names = (rows, most = 30) => `<div class="chips inline">${rows.slice(0, most).map((k) =>
    `<span class="chip mono">${esc(k)}</span>`).join("")}${rows.length > most ? `<span class="dsub">and ${rows.length - most} more</span>` : ""}</div>`;

  function backupPreview() {
    const added = restoring.preview?.added || [], kept = restoring.preview?.kept || [];
    if (!added.length) {
      return `<div class="ahead"><h1>Nothing to restore</h1>
          <p class="aorigin">${kept.length ? `All ${plural(kept.length, "key")} in this backup ${kept.length === 1 ? "is" : "are"} already here.` : "This backup holds no keys."}</p></div>
        ${one("Done", "data-plan-home")}`;
    }
    return `<div class="ahead"><h1>This backup adds ${plural(added.length, "key")}</h1>
        <p class="aorigin">${kept.length ? `${plural(kept.length, "key")} you already have ${kept.length === 1 ? "stays" : "stay"} as ${kept.length === 1 ? "it is" : "they are"}.` : "Nothing you have now is changed."}</p></div>
      ${names(added)}
      ${errorHtml()}
      <div class="arow"><button class="aghost" data-plan-home ${busy ? "disabled" : ""}>Cancel</button>
        <button class="aprimary" data-backup-apply ${busy ? "disabled" : ""}>${busy ? "Restoring\u2026" : `Restore ${plural(added.length, "key")}`}</button></div>`;
  }

  function backupRestored() {
    const added = restoring.result?.added || [];
    return `<div class="adone"><h1>${plural(added.length, "key")} restored</h1>
        <p class="aorigin">${added.length === 1 ? "It is" : "They are"} in this store now, on the Keys page.</p></div>
      ${names(added, 12)}
      ${one("Done", "data-plan-close")}`;
  }

  async function storeBackup(first, second) {
    if (busy) return;
    if (phrase.own) {
      if (first.length < 16) { complain("A passphrase of your own needs at least 16 characters, or let PassBook make one.", "#pb-pass"); return; }
      if (first !== second) { complain("The two passphrases are not the same.", "#pb-pass2"); return; }
    } else if (!first || !phrase.kept) return;
    clearSaid(); busy = "store"; paint(true);
    try {
      made = await invoke("backup_store", { passphrase: first });
      // Stored: the passphrase has done its work here and is not kept a moment longer.
      phrase = { made: "", own: false, kept: false, failed: "" };
      saved = false; copied = false; step = "code"; void load();
    } catch (caught) { fail(caught); }
    finally { busy = ""; paint(true, step === "code" ? "[data-plan-copy]" : phrase.own ? "#pb-pass" : "[data-phrase-store]"); }
  }

  /** Read a backup: first only to say what it would add, then (pressed again) for real. */
  async function restore(dryRun) {
    if (busy) return;
    busy = "restore"; clearSaid(); paint(true);
    try {
      const answer = await invoke("backup_restore", { code: restoring.id || restoring.code.trim(), passphrase: restoring.passphrase, dryRun });
      if (dryRun) { restoring.preview = answer; step = "preview"; }
      else { restoring.result = answer; restoring.passphrase = ""; step = "restored"; onStoreChanged?.(); }
    } catch (caught) {
      fail(caught);
      // A passphrase that did not open it is typed again, not kept.
      if (dryRun) restoring.passphrase = "";
    } finally { busy = ""; paint(true, step === "restore" ? "#pb-rpass" : ""); }
  }

  async function removeBackup(id) {
    confirming = ""; busy = "remove"; clearSaid(); paint(true);
    try { await invoke("backup_remove", { id }); backups = (backups || []).filter((row) => row.id !== id); note = "That backup is gone from the relay."; void load(); }
    catch (caught) { fail(caught); }
    finally { busy = ""; paint(true); }
  }

  // ── Phone ────────────────────────────────────────────────────────────────
  async function loadPhones() {
    busy = "list"; paint(true);
    try { phones = (await invoke("phone_list"))?.phones || []; }
    catch (caught) { phones = phones || []; fail(caught); }
    finally { busy = ""; if (sheet === "phone" && step === "home") paint(true); }
  }

  function phoneHome() {
    const allowed = status ? Boolean(status.limits?.approvals) : true;
    const rows = (phones || []).map((row) => `<div class="prow"><span class="grow"><b>${esc(row.label || "A phone")}</b>
        <span class="dsub">${esc([row.linkedAt ? `Linked ${day(row.linkedAt)}` : "", row.seenAt ? `last seen ${day(row.seenAt)}` : ""].filter(Boolean).join(" \u00b7 "))}</span></span>
        <button class="act danger" data-phone-remove="${esc(row.id)}" ${busy ? "disabled" : ""}>Unlink</button></div>
      ${confirmHtml(`phone:${row.id}`, `Unlink ${row.label || "this phone"}? It can no longer answer requests.`, "Unlink")}`).join("");
    return `<div class="ahead"><h1>Approve from your phone</h1>
        <p class="aorigin">When something asks to use a key, your phone can say yes. A phone can only allow a request to use a key. It can never add, change or delete one.</p></div>
      ${phones === null ? waitHtml("Asking the relay which phones are linked.")
        : `${allowed || errorRefused ? "" : partOf(status?.billing ? "Approving from your phone is part of PassBook Sync." : "This relay does not include approving from a phone.", "not_included")}
           ${rows ? `<div class="plist">${rows}</div>` : allowed ? `<p class="dsub dempty">No phone linked yet.</p>` : ""}`}
      ${noteHtml()}${errorHtml("not_included")}
      <div class="arow"><button class="aghost" data-plan-close>Close</button>
        <button class="aprimary" data-phone-add ${busy || phones === null || !allowed ? "disabled" : ""}>${busy === "add" ? "Making a link\u2026" : "Add a phone"}</button></div>`;
  }

  function phoneLink() {
    return `<div class="ahead"><h1>Open this link on your phone</h1>
        <p class="aorigin">Send it to yourself and open it on the phone within 15 minutes.</p></div>
      ${copyHtml(pending.url, "Copy the link")}
      <p class="anote">Until a phone opens it, this link is a secret: whichever phone opens it first is the one PassBook asks you about. Send it only to yourself.</p>
      ${waitHtml("Waiting for the phone to open it. Keep PassBook open here.")}
      ${errorHtml()}
      <div class="arow" style="grid-template-columns: 1fr;"><button class="aghost" data-phone-cancel ${busy ? "disabled" : ""}>Cancel</button></div>`;
  }

  function phoneAsk() {
    return `<div class="ahead"><h1>Is this your phone?</h1>
        <p class="aorigin"><b>${esc(pending.label || "A phone")}</b> opened the link. Confirm only if that is the phone in your hand right now.</p></div>
      <p class="anote">If you do not recognize it, press Cancel and it is turned away.</p>
      ${errorHtml()}
      <div class="arow"><button class="aghost" data-phone-cancel ${busy ? "disabled" : ""}>Cancel</button>
        <button class="aprimary" data-phone-confirm ${busy ? "disabled" : ""}>${busy === "confirm" ? "Confirming\u2026" : "Confirm"}</button></div>`;
  }

  function phoneLinked() {
    return `<div class="adone"><h1>${esc(pending?.label || "Your phone")} can answer requests</h1>
        <p class="aorigin">When something asks to use a key, it asks there too. You can unlink it here at any time.</p></div>
      ${one("Done", "data-phone-done")}`;
  }

  async function addPhone() {
    if (busy) return;
    busy = "add"; clearSaid(); paint(true);
    try {
      pending = { ...await invoke("phone_add"), label: "" };
      step = "link"; copied = false;
      stopTimer(); timer = setInterval(checkPhone, 2500);
    } catch (caught) { fail(caught); }
    finally { busy = ""; paint(true, step === "link" ? "[data-plan-copy]" : ""); }
  }

  /** Has a phone opened the link? This only ever moves to the question; the yes is the person's. */
  async function checkPhone() {
    if (asking || !pending || step !== "link") return;
    asking = true;
    const id = pending.id;
    try {
      const seen = await invoke("phone_check", { id });
      if (!pending || pending.id !== id || step !== "link" || seen?.status === "waiting") return;
      stopTimer();
      if (seen?.status === "joined") { pending.label = seen.label || "A phone"; step = "ask"; paint(true, "[data-phone-cancel]"); return; }
      pending = null; step = "home";
      error = seen?.status === "refused" ? "The phone turned the link down. Add it again if that was a mistake."
        : "The link ran out before a phone opened it. Add the phone again.";
      paint(true);
    } catch { /* the next tick asks again */ }
    finally { asking = false; }
  }

  /** Accept the phone that opened the link. Reached only from the Confirm button. */
  async function confirmPhone() {
    if (busy || !pending || step !== "ask") return;
    busy = "confirm"; clearSaid(); paint(true);
    try {
      const answer = await invoke("phone_confirm", { id: pending.id });
      pending = { id: "", label: answer?.phone?.label || pending.label };
      step = "linked"; void load();
    } catch (caught) { fail(caught); }
    finally { busy = ""; paint(true); }
  }

  /** Turn away a phone that has a link or opened one, and go back to the list. */
  async function cancelPhone() {
    if (busy) return;
    stopTimer();
    const id = pending?.id;
    busy = "cancel"; paint(true);
    if (id) { try { await invoke("phone_remove", { id }); } catch { /* already gone */ } }
    pending = null; busy = ""; step = "home"; clearSaid();
    void loadPhones();
  }

  async function removePhone(id) {
    confirming = ""; busy = "remove"; clearSaid(); paint(true);
    try { await invoke("phone_remove", { id }); phones = (phones || []).filter((row) => row.id !== id); note = "That phone is unlinked."; void load(); }
    catch (caught) { fail(caught); }
    finally { busy = ""; paint(true); }
  }

  // ── People ───────────────────────────────────────────────────────────────
  /** Whether one more person can be invited, and if not, the sentence and the button that fixes it. */
  function sharing() {
    const total = Number(team?.seats?.limit) || limit("seats"), taken = Number(team?.seats?.used ?? used("members")) || 0;
    if (!total) {
      return { can: false, total, taken, offer: offerLabel("seat_limit"),
               why: status?.billing ? "Sharing keys with other people is part of PassBook Teams." : "This relay does not include sharing keys with other people." };
    }
    if (taken >= total) return { can: false, total, taken, why: `All ${plural(total, "seat")} are in use.`, offer: offerLabel("seat_limit") };
    return { can: true, total, taken, why: "", offer: "" };
  }

  function peopleHome() {
    const share = sharing(), members = team?.members || [];
    const rows = members.map((row) => `<div class="prow"><span class="grow"><b>${esc(row.name || "Someone")}</b>
        <span class="dsub">${esc([ROLE[row.role] || "", plural((row.keys || []).length, "key"), row.expires ? `until ${day(row.expires)}` : ""].filter(Boolean).join(" \u00b7 "))}</span></span>
        <button class="act danger" data-member-remove="${esc(row.did)}" ${busy ? "disabled" : ""}>Remove</button></div>
      ${confirmHtml(`member:${row.did}`, `Stop sharing with ${row.name || "this person"}? Their computer stops getting your keys.`, "Stop sharing")}`).join("");
    return `<div class="ahead"><h1>People you share with</h1>
        <p class="aorigin">${share.total ? `${share.taken} of ${plural(share.total, "seat")} in use. ` : ""}Each person runs PassBook on their own computer and gets only the keys you chose.</p></div>
      ${rows ? `<div class="plist">${rows}</div>` : `<p class="dsub dempty">${team || !limit("seats") ? "You are not sharing with anyone yet." : "Asking the relay who you share with\u2026"}</p>`}
      ${share.can ? "" : `<div class="aoffer"><p class="anote">${esc(share.why)}</p>${
        share.offer ? `<button class="act primary" data-plan-goto="teams">${esc(share.offer)}</button>` : ""}</div>`}
      ${noteHtml()}${errorHtml("seat_limit")}
      <div class="arow"><button class="aghost" data-plan-close>Close</button>
        <button class="aprimary" data-member-invite ${busy || !share.can ? "disabled" : ""}>Share with a person</button></div>`;
  }

  function peopleRemoved() {
    const rotate = removed.rotate || [];
    return `<div class="ahead"><h1>${esc(removed.name || "They")} no longer ${removed.name ? "gets" : "get"} your keys</h1>
        ${removed.detail ? `<p class="aorigin">${esc(removed.detail)}</p>` : ""}</div>
      ${rotate.length ? `<p class="anote">They had ${rotate.length === 1 ? "this key" : "these keys"}. To be sure ${rotate.length === 1 ? "it stops" : "they stop"} working for them, replace ${rotate.length === 1 ? "it where it was" : "each one where it was"} made.</p>${names(rotate, 60)}` : ""}
      ${one("Done", "data-plan-close")}`;
  }

  async function removeMember(did) {
    const row = (team?.members || []).find((member) => member.did === did);
    confirming = ""; busy = "remove"; clearSaid(); paint(true);
    try {
      const answer = await invoke("team_remove", { did });
      removed = { name: row?.name || "", detail: answer?.detail || "", rotate: answer?.rotate || [] };
      if (team) team = { ...team, members: team.members.filter((member) => member.did !== did) };
      step = "removed"; void load();
    } catch (caught) { fail(caught); }
    finally { busy = ""; repaint(); paint(true); }
  }

  // ── drawing and wiring ───────────────────────────────────────────────────
  const VIEWS = {
    plan: { home: planHome, paying: planPaying, changed: planChanged },
    backup: { home: backupHome, store: backupStore, code: backupCode, restore: backupRestore, preview: backupPreview, restored: backupRestored },
    phone: { home: phoneHome, link: phoneLink, ask: phoneAsk, linked: phoneLinked },
    people: { home: peopleHome, removed: peopleRemoved },
  };

  /** What had the keyboard, so a redraw can hand it back to the same control. */
  function heldFocus() {
    const el = document.activeElement;
    if (!el || !container.contains(el)) return "";
    if (el.id) return `#${el.id}`;
    const attr = [...el.attributes].find((a) => a.name.startsWith("data-"));
    return attr ? `[${attr.name}="${attr.value.replace(/["\\]/g, "\\$&")}"]` : "";
  }

  function paint(force = false, focus = "") {
    if (!sheet) return false;
    if (!force && container.dataset.plansheet === sheet) return true;
    const view = (VIEWS[sheet] || {})[step] || (VIEWS[sheet] || {}).home;
    if (!view) { sheet = ""; return false; }
    const inside = container.contains(document.activeElement) || document.activeElement === document.body;
    const held = focus || heldFocus();
    container.dataset.plansheet = sheet;
    container.hidden = false;
    container.innerHTML = `<div class="awrap" tabindex="-1"><div class="acard">${view()}</div></div>`;
    wire();
    if (inside) {
      const next = (held && container.querySelector(held)) || container.querySelector("input:not([type=checkbox]):not([disabled])");
      (next && !next.disabled ? next : container.querySelector(".awrap"))?.focus({ preventScroll: true });
    }
    return true;
  }

  function goHome() {
    stopTimer(); forget(); clearSaid(); step = "home"; confirming = "";
    paint(true);
    if (sheet === "backup") void loadBackups();
  }

  function wire() {
    const on = (selector, handler) => container.querySelectorAll(selector).forEach((el) => { el.onclick = handler; });
    on("[data-plan-close]", close);
    on("[data-plan-home]", goHome);
    on("[data-plan-retry]", () => { void load(); paint(true); });
    on("[data-plan-goto]", (event) => open("plan", { want: event.currentTarget.dataset.planGoto }));
    on("[data-plan-no]", () => { confirming = ""; paint(true); });
    on("[data-plan-yes]", (event) => {
      const [kind, ...rest] = event.currentTarget.dataset.planYes.split(":"), id = rest.join(":");
      if (kind === "move") { confirming = "move:yes"; void subscribe(); }
      else if (kind === "cancel") void change("cancel", "plan_cancel", {}, () => "Your plan will not renew.");
      else if (kind === "backup") void removeBackup(id);
      else if (kind === "phone") void removePhone(id);
      else if (kind === "member") void removeMember(id);
    });
    on("[data-plan-copy]", async () => {
      const text = sheet === "backup" ? (step === "store" ? phrase.made : made?.code) : pending?.url;
      if (!text) return;
      try {
        await copy(text); copied = true; paint(true);
        clearTimeout(copiedTimer);
        copiedTimer = setTimeout(() => { copied = false; if (sheet && (step === "code" || step === "link" || step === "store")) paint(true); }, 1400);
      } catch { error = "Could not copy. Select it and copy it by hand."; errorRefused = false; paint(true); }
    });

    // Plan
    on("[data-plan-offer]", (event) => { offer = event.currentTarget.dataset.planOffer; clearSaid(); paint(true); });
    on("[data-plan-yearly]", (event) => { yearly = event.currentTarget.dataset.planYearly === "1"; paint(true); });
    on("[data-plan-seat]", (event) => {
      const { least, most } = seatBounds();
      seats = Math.min(most, Math.max(least, seats + Number(event.currentTarget.dataset.planSeat)));
      seatsTouched = true; confirming = ""; paint(true);
    });
    on("[data-plan-teams]", () => { teamsOpen = true; paint(true, "[data-plan-subscribe]"); });
    on("[data-plan-subscribe]", () => void subscribe());
    on("[data-plan-again]", async () => {
      if (!canBuy() || !lastOrder || busy) return;
      busy = "again"; clearSaid(); paint(true);
      try { await invoke("plan_subscribe", lastOrder); } catch (caught) { fail(caught); }
      finally { busy = ""; paint(true); }
    });
    on("[data-plan-back]", () => { stopTimer(); step = "home"; clearSaid(); paint(true); });
    on("[data-plan-seats]", () => void change("seats", "plan_seats", { seats }, () => `Your plan now covers ${plural(seats, "person", "people")}.`));
    on("[data-plan-cancel]", () => { confirming = "cancel"; paint(true, "[data-plan-no]"); });
    on("[data-plan-resume]", () => void change("resume", "plan_resume", {}, () => "Your plan will renew as before."));
    on("[data-plan-billing]", () => void openBilling());

    // Backup
    on("[data-backup-new]", () => { clearSaid(); step = "store"; copied = false; void makePhrase(); });
    on("[data-phrase-own]", () => { clearSaid(); phrase = { made: "", own: true, kept: false, failed: "" }; copied = false; paint(true, "#pb-pass"); });
    on("[data-phrase-made]", () => { clearSaid(); copied = false; void makePhrase(); });
    on("[data-phrase-store]", () => void storeBackup(phrase.made, phrase.made));
    const keptBox = container.querySelector("[data-phrase-kept]");
    if (keptBox) keptBox.onchange = () => {
      phrase.kept = keptBox.checked;
      const go = container.querySelector("[data-phrase-store]");
      if (go) go.disabled = !phrase.kept || !phrase.made;
    };
    on("[data-backup-code]", () => { clearSaid(); forget(); step = "restore"; paint(true, "#pb-code"); });
    on("[data-backup-restore]", (event) => {
      const id = event.currentTarget.dataset.backupRestore, row = (backups || []).find((item) => item.id === id);
      clearSaid(); forget(); restoring.id = id; restoring.label = row?.label || ""; step = "restore"; paint(true, "#pb-rpass");
    });
    on("[data-backup-remove]", (event) => { confirming = `backup:${event.currentTarget.dataset.backupRemove}`; paint(true, "[data-plan-no]"); });
    on("[data-backup-apply]", () => void restore(false));
    on("[data-backup-done]", goHome);
    const savedBox = container.querySelector("[data-backup-saved]");
    if (savedBox) savedBox.onchange = () => {
      saved = savedBox.checked;
      const done = container.querySelector("[data-backup-done]");
      if (done) done.disabled = !saved;
    };
    const storeForm = container.querySelector("#pb-store");
    if (storeForm) storeForm.onsubmit = (event) => {
      event.preventDefault();
      void storeBackup(container.querySelector("#pb-pass").value, container.querySelector("#pb-pass2").value);
    };
    const restoreForm = container.querySelector("#pb-restore");
    if (restoreForm) restoreForm.onsubmit = (event) => {
      event.preventDefault();
      restoring.code = container.querySelector("#pb-code")?.value || restoring.code;
      restoring.passphrase = container.querySelector("#pb-rpass").value;
      if (!restoring.id && !restoring.code.trim()) { complain("Paste the backup code first.", "#pb-code"); return; }
      if (!restoring.passphrase) { complain("Enter the passphrase this backup was made with.", "#pb-rpass"); return; }
      void restore(true);
    };

    // Phone
    on("[data-phone-add]", () => void addPhone());
    on("[data-phone-cancel]", () => void cancelPhone());
    on("[data-phone-confirm]", () => void confirmPhone());
    on("[data-phone-done]", () => { pending = null; step = "home"; clearSaid(); void loadPhones(); });
    on("[data-phone-remove]", (event) => { confirming = `phone:${event.currentTarget.dataset.phoneRemove}`; paint(true, "[data-plan-no]"); });

    // People
    on("[data-member-remove]", (event) => { confirming = `member:${event.currentTarget.dataset.memberRemove}`; paint(true, "[data-plan-no]"); });
    on("[data-member-invite]", () => { close(); invitePerson?.(); });
  }

  // Escape steps back: out of a question first, and otherwise out of the sheet. It never answers yes,
  // it leaves the one-time code alone, and it is not taken from the palette drawn above the sheet.
  document.addEventListener("keydown", (event) => {
    if (!sheet || event.key !== "Escape" || event.defaultPrevented) return;
    if (!container.contains(event.target) && event.target !== document.body) return;
    event.preventDefault();
    if (busy) return;
    if (confirming) { confirming = ""; paint(true); return; }
    if (sheet === "backup" && step === "code") return;
    if (sheet === "phone" && (step === "link" || step === "ask")) { void cancelPhone(); return; }
    if (sheet === "backup" && (step === "store" || step === "restore" || step === "preview")) { goHome(); return; }
    close();
  });

  return {
    load, open, paint,
    active: () => Boolean(sheet),
    refused,
    /** What the button beside a refusal says ("Get PassBook Sync"), or "" when nothing is for sale. */
    offer: offerLabel,
    /** The plan line on Devices: still asking, could not ask, or the plan and how full it is. */
    line() {
      if (!status) return { state: checking || loading ? "checking" : statusError ? "failed" : "checking" };
      const machines = limit("machines"), have = used("machines");
      return {
        state: "ok", name: planName(), full: Boolean(machines) && have >= machines,
        usage: machines ? `${have} of ${plural(machines, "computer")}` : plural(have, "computer"),
        action: status.plan === "free" && canBuy() ? "Get PassBook Sync" : paidHere() ? "Manage plan" : "Plan details",
      };
    },
    /** The people keys are shared with, and whether one more can be invited. Null until the plan is known. */
    people: () => (status ? { members: team?.members || [], ...sharing() } : null),
    /** What those people did with the keys: names and times. */
    events: () => events,
  };
};
