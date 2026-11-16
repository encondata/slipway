/* Slipway front-end: small, dependency-free progressive enhancement.
 *
 * Declarative hooks used by the templates:
 *   <button data-api="POST /api/v1/..." data-confirm="..." data-then="reload|redirect:/x|redirect:/x/{id}">
 *   <form data-form="POST /api/v1/..." data-then="...">   (fields → JSON; see serialize())
 *   <form data-omit-unchanged="field ...">                 (leave those fields out of the body unless the user changed them)
 *   <button data-open="dialog-id">, <button data-close>
 *   <pre data-deploy-log="/api/v1/deployments/<id>">       (live build log)
 *   <div data-load="/api/v1/..." data-render="containers|unmanaged|logs|readme">
 *   <button data-claim="<n>"> in the unmanaged list opens #claim-dialog filled from that group
 *   <button data-copy="text"> / data-copy-target="#el"
 *   <select data-fill> with <option data-fill-<field>="value">   (picking an option fills untouched fields)
 *
 * Data safety (spec §15.6):
 *   <input data-must-equal="name">                         (the form's submit button stays disabled until it matches)
 *   <button data-open="id" data-fill='{"k": v}'>           (fills [name=k], [data-slot=k], [data-show-if=k]; "action" sets data-form)
 *   <input name="a.b">                                     (nested in the JSON body: {a: {b: ...}}); data-no-send: never sent
 *   <div data-optional-group="first_admin">                (left out of the body when its text inputs are all empty)
 *   <input data-repeat-of="name">, data-required-when="field=value"
 *   <form data-upload="/api/v1/snapshots/upload">          (raw file upload with progress)
 *   <button data-generate-passphrase="#a, #b">, <section data-poll-reload="5000">
 */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const csrf = () => ($('meta[name="csrf-token"]') || {}).content || "";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ---------------------------------------------------------------- API
  async function api(method, url, body) {
    const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf();
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (!res.ok) {
      // A 401 from the login endpoint is a wrong password, not an expired session; other 401s mean "sign in again".
      if (res.status === 401 && !/^\/api\/v1\/auth\/login(?:[?#]|$)/.test(url) && location.pathname !== "/login") {
        location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
      }
      throw new Error(errorText(data) || res.statusText || "Request failed");
    }
    return data;
  }

  function errorText(data) {
    if (!data || data.detail === undefined) return "";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) {
      return data.detail.map((d) => {
        const field = (d.loc || []).filter((x) => x !== "body").join(".");
        return (field ? field + ": " : "") + (d.msg || "").replace(/^Value error, /, "");
      }).join("\n");
    }
    return JSON.stringify(data.detail);
  }

  // -------------------------------------------------------------- toasts
  function toast(message, kind = "success") {
    const box = $("#toasts");
    if (!box) return alert(message);
    const el = document.createElement("div");
    el.className = "toast " + kind;
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), kind === "error" ? 8000 : 3500);
  }

  function flashAfterReload(message, kind = "success") {
    try { sessionStorage.setItem("slipway-flash", JSON.stringify({ message, kind })); } catch (e) { /* ignore */ }
  }

  // Resolve like the browser does (it strips tabs/newlines, so "/\t/evil" means "//evil") and stay on this origin.
  function sameOrigin(url) {
    try {
      const target = new URL(url, location.href);
      return target.origin === location.origin ? target.href : "/";
    } catch (e) {
      return "/";
    }
  }

  // "{id}" or "{deployment.id}" from the response.
  const pick = (data, path) => path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), data);

  function then(spec, data) {
    if (!spec) return;
    if (spec === "reload") return location.reload();
    if (spec === "download") {
      // A snapshot export: the one-time link streams the file (same origin only).
      if (!data || !data.url) return;
      toast(`Download started (${humanBytes(data.bytes)})`);
      return location.assign(sameOrigin(data.url));
    }
    if (spec.startsWith("redirect:")) {
      const url = spec.slice(9).replace(/\{([\w.]+)\}/g, (_, k) => encodeURIComponent(pick(data, k) || ""));
      location.href = sameOrigin(url);
    }
  }

  // 812 MiB, 1.9 GiB, 20 GiB: binary units, one decimal, as services.data.human_bytes writes them.
  function humanBytes(n) {
    if (n === null || n === undefined) return "an unknown size";
    const units = [["TiB", 1024 ** 4], ["GiB", 1024 ** 3], ["MiB", 1024 ** 2], ["KiB", 1024]];
    for (const [unit, scale] of units) {
      if (n >= scale) return (n / scale).toFixed(1).replace(/\.0$/, "") + " " + unit;
    }
    return n + " bytes";
  }

  function setLoading(btn, on) {
    if (!btn) return;
    btn.classList.toggle("loading", on);
    btn.disabled = on;
  }

  // ------------------------------------------------------ data-api buttons
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-api]");
    if (!btn) return;
    ev.preventDefault();
    if (btn.dataset.confirm && !confirm(btn.dataset.confirm)) return;
    const [method, url] = btn.dataset.api.split(" ");
    const body = btn.dataset.body ? JSON.parse(btn.dataset.body) : undefined;
    setLoading(btn, true);
    try {
      const data = await api(method, url, body);
      if (btn.dataset.success) {
        btn.dataset.then === "reload" ? flashAfterReload(btn.dataset.success) : toast(btn.dataset.success);
      }
      if (btn.dataset.successField && data && data[btn.dataset.successField]) toast(data[btn.dataset.successField]);
      // e.g. DELETE /instances/{id} returns {ok, warning} when files had to be left on the host.
      if (data && data.warning) {
        btn.dataset.then ? flashAfterReload(data.warning, "warning") : toast(data.warning, "warning");
      }
      if (btn.dataset.output && data && data.output !== undefined) {
        const target = $(btn.dataset.output);
        if (target) target.textContent = data.output || "(no output)";
      }
      then(btn.dataset.then, data);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  });

  // ------------------------------------------------------------ forms
  function coerce(input) {
    if (input.type === "checkbox") return input.checked;
    if (input.type === "number") return input.value === "" ? null : Number(input.value);
    if (input.dataset.type === "json") return input.value ? JSON.parse(input.value) : null;
    return input.value;
  }

  // "first_admin.fields.email" puts the value at out.first_admin.fields.email.
  function put(out, name, v) {
    if (!name.includes(".")) { out[name] = v; return; }
    const parts = name.split(".");
    let o = out;
    parts.slice(0, -1).forEach((p) => { o = o[p] = o[p] && typeof o[p] === "object" ? o[p] : {}; });
    o[parts[parts.length - 1]] = v;
  }

  function serialize(form) {
    const out = {};
    $$("[name]", form).forEach((el) => {
      if (el.tagName === "BUTTON" || el.disabled || el.closest("[data-repeater]") || el.closest("[hidden]")) return;
      if (el.dataset.noSend !== undefined) return; // only steers the form (show-when)
      if (el.type === "radio" && !el.checked) return;
      if (el.dataset.array !== undefined) {
        out[el.name] = out[el.name] || [];
        if (el.checked) out[el.name].push(el.value);
        return;
      }
      const v = coerce(el);
      if ((v === "" || v === null) && el.dataset.keepEmpty === undefined) return;
      put(out, el.name, v);
    });
    // An optional group the user left empty (such as a first admin when starting from a snapshot) isn't sent.
    $$("[data-optional-group]", form).forEach((group) => {
      const typed = $$("input, textarea", group).filter((i) => i.tagName === "TEXTAREA" || ["text", "email", "password"].includes(i.type));
      if (typed.every((i) => !i.value.trim())) delete out[group.dataset.optionalGroup];
    });
    $$("[data-repeater]", form).forEach((rep) => {
      if (rep.closest("[hidden]")) return;
      const rows = $$(".repeater-row", rep);
      if (rep.dataset.kind === "map") {
        const obj = {};
        rows.forEach((r) => {
          const k = $("[data-k]", r).value.trim();
          if (k) obj[k] = $("[data-v]", r).value;
        });
        out[rep.dataset.repeater] = obj;
      } else {
        out[rep.dataset.repeater] = rows.map((r) => {
          const item = {};
          $$("[data-f]", r).forEach((el) => {
            const v = coerce(el);
            if (v !== "" && v !== null) item[el.dataset.f] = v;
          });
          return item;
        }).filter((item) => Object.keys(item).length > (rep.dataset.minKeys ? Number(rep.dataset.minKeys) - 1 : 0));
      }
    });
    return out;
  }

  // Compares with the page as rendered, so e.g. a role saved without touching its boxes doesn't re-grant them.
  function changed(el) {
    if (el.type === "checkbox" || el.type === "radio") return el.checked !== el.defaultChecked;
    return el.value !== el.defaultValue;
  }

  function omitUnchanged(form, body) {
    (form.dataset.omitUnchanged || "").split(/\s+/).filter(Boolean).forEach((name) => {
      if (!$$(`[name="${name}"]`, form).some(changed)) delete body[name];
    });
  }

  document.addEventListener("submit", async (ev) => {
    const form = ev.target.closest("form[data-form]");
    if (!form) return;
    ev.preventDefault();
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) return;
    const [method, url] = form.dataset.form.split(" ");
    const submit = ev.submitter || $('[type="submit"]', form);
    let body;
    try { body = serialize(form); } catch (err) { return toast("Invalid input: " + err.message, "error"); }
    omitUnchanged(form, body);
    if (submit && submit.name) body[submit.name] = submit.value === "true" ? true : submit.value === "false" ? false : submit.value;
    setLoading(submit, true);
    formError(form, "");
    try {
      const data = await api(method, url, body);
      form.dispatchEvent(new CustomEvent("slipway:success", { detail: data, bubbles: true }));
      if (form.dataset.resultField && data) {
        const target = $(form.dataset.resultTarget);
        if (target) {
          target.textContent = data[form.dataset.resultField];
          const box = target.closest("[data-result]");
          if (box) box.hidden = false;
        }
        if (submit) submit.hidden = true;
      }
      const leaving = (form.dataset.then || "").startsWith("redirect") || form.dataset.then === "reload";
      if (form.dataset.success) leaving ? flashAfterReload(form.dataset.success) : toast(form.dataset.success);
      if (data && data.warning) leaving ? flashAfterReload(data.warning, "warning") : toast(data.warning, "warning");
      then(form.dataset.then, data);
    } catch (err) {
      if (!formError(form, err.message)) toast(err.message, "error");
    } finally {
      setLoading(submit, false);
    }
  });

  // A modal dialog covers the toasts, so a form in one shows its error inside the dialog.
  // Returns whether it did.
  function formError(form, message) {
    const dlg = form.closest("dialog");
    let box = $("[data-form-error]", form);
    if (!message) {
      if (box) box.remove();
      return false;
    }
    if (!dlg || !dlg.open) return false;
    if (!box) {
      box = document.createElement("div");
      box.className = "callout error";
      box.setAttribute("role", "alert");
      box.dataset.formError = "";
      const body = $(".modal-body", form) || form;
      body.prepend(box);
    }
    box.textContent = message;
    box.style.whiteSpace = "pre-line";
    box.scrollIntoView({ block: "nearest" });
    return true;
  }

  // --------------------------------------------------------- repeaters
  document.addEventListener("click", (ev) => {
    const add = ev.target.closest("[data-add-row]");
    if (add) {
      const rep = $(add.dataset.addRow);
      const tpl = $("template", rep);
      rep.insertBefore(tpl.content.cloneNode(true), tpl);
      const rows = $$(".repeater-row", rep);
      const first = rows[rows.length - 1] && $("input", rows[rows.length - 1]);
      if (first) first.focus();
      rep.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    const remove = ev.target.closest("[data-remove-row]");
    if (remove) {
      const rep = remove.closest("[data-repeater]");
      remove.closest(".repeater-row").remove();
      if (rep) rep.dispatchEvent(new Event("input", { bubbles: true }));
    }
    const reveal = ev.target.closest("[data-reveal]");
    if (reveal) {
      const input = reveal.closest(".repeater-row").querySelector("[data-v]");
      input.type = input.type === "password" ? "text" : "password";
    }
  });

  // ----------------------------------------------------------- dialogs
  // A required field inside a hidden block would stop the browser from submitting: it is required only while shown.
  function syncRequired(root) {
    $$("[required], [data-req]", root).forEach((el) => {
      if (el.dataset.requiredWhen !== undefined) return; // wireShowWhen decides those
      const off = Boolean(el.closest("[hidden]"));
      if (off && el.dataset.req === undefined) el.dataset.req = "";
      if (el.dataset.req !== undefined) el.required = !off;
    });
  }

  // The typed-name check: the form's submit button stays disabled until every [data-must-equal] matches exactly.
  function checkMustEqual(form) {
    const inputs = $$("[data-must-equal]", form);
    if (!inputs.length) return;
    const ok = inputs.every((i) => i.closest("[hidden]") || i.value === i.dataset.mustEqual);
    $$('[type="submit"]', form).forEach((b) => { b.disabled = !ok; });
  }

  // data-fill: {"k": v} sets [name=k] (a checkbox is ticked by a true v), [data-slot=k] text, and shows
  // [data-show-if=k] only for a truthy v; "action" replaces the form's data-form ("POST /api/v1/...").
  function fill(dlg, values) {
    const form = $("form", dlg);
    Object.keys(values).forEach((k) => {
      const v = values[k];
      if (k === "action") { if (form) form.dataset.form = String(v); return; }
      $$(`[name="${k}"]`, dlg).forEach((el) => {
        if (el.type === "checkbox") el.checked = Boolean(v);
        else if (el.type === "radio") el.checked = el.value === String(v);
        else el.value = v === null || v === undefined ? "" : String(v);
      });
      $$(`[data-slot="${k}"]`, dlg).forEach((el) => { el.textContent = v === null || v === undefined ? "" : String(v); });
      $$(`[data-show-if="${k}"]`, dlg).forEach((el) => { el.hidden = !v; });
    });
  }

  function openDialog(dlg, values) {
    $$("[data-form-error]", dlg).forEach((el) => el.remove());
    if (values) fill(dlg, values);
    $$("[data-must-equal]", dlg).forEach((i) => { i.value = ""; }); // the name is typed again for each action
    $$("form", dlg).forEach((form) => { form.dispatchEvent(new Event("change")); syncRequired(form); checkMustEqual(form); });
    dlg.showModal();
    const f = $("input:not([type=hidden]), textarea, select", dlg);
    if (f) f.focus();
  }

  document.addEventListener("input", (ev) => {
    const el = ev.target;
    if (!el || !el.dataset || !el.closest) return;
    const form = el.closest("form");
    if (!form) return;
    if (el.dataset.mustEqual !== undefined) checkMustEqual(form);
    // A repeated password or passphrase must equal the field it repeats.
    const repeat = el.dataset.repeatOf !== undefined ? el : $$("[data-repeat-of]", form).find((r) => r.dataset.repeatOf === el.name);
    if (repeat && repeat.setCustomValidity) {
      const first = $(`[name="${repeat.dataset.repeatOf}"]`, form);
      repeat.setCustomValidity(first && repeat.value !== first.value ? "This doesn't match" : "");
    }
  });

  document.addEventListener("click", (ev) => {
    const opener = ev.target.closest("[data-open]");
    if (opener) {
      const dlg = document.getElementById(opener.dataset.open);
      if (dlg) {
        let values = null;
        try { values = opener.dataset.fill ? JSON.parse(opener.dataset.fill) : null; } catch (e) { values = null; }
        openDialog(dlg, values);
      }
    }
    const closer = ev.target.closest("[data-close]");
    if (closer) closer.closest("dialog").close();
    if (ev.target.closest("[data-reload-page]")) location.reload();
  });

  // ---------------------------------------------------------- copy
  // navigator.clipboard only exists on HTTPS and localhost; plain-HTTP installs fall back to execCommand.
  function legacyCopy(text, btn) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    (btn.closest("dialog") || document.body).appendChild(ta); // outside an open modal everything is inert
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { /* unsupported */ }
    ta.remove();
    btn.focus();
    return ok;
  }

  async function copyText(text, btn) {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* fall back */ }
    }
    return legacyCopy(text, btn);
  }

  function selectContents(el) {
    if (!el || !window.getSelection) return false;
    const range = document.createRange();
    range.selectNodeContents(el);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    return true;
  }

  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-copy], [data-copy-target]");
    if (!btn) return;
    const target = btn.dataset.copyTarget ? $(btn.dataset.copyTarget) : null;
    const text = (btn.dataset.copy || (target && (target.tagName === "INPUT" ? target.value : target.textContent)) || "").trim();
    if (await copyText(text, btn)) return toast("Copied to clipboard");
    toast(selectContents(target) ? "Couldn't copy automatically. Press Ctrl+C (⌘C on Mac) to copy the selected text."
      : "Couldn't copy to the clipboard. Select the text and copy it by hand.", "error");
  });

  // ------------------------------------------------------- theme
  document.addEventListener("click", (ev) => {
    if (!ev.target.closest("[data-theme-toggle]")) return;
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("slipway-theme", next); } catch (e) { /* ignore */ }
  });

  // ---------------------------------------------------- menus / nav
  document.addEventListener("click", (ev) => {
    $$("details.usermenu[open]").forEach((d) => { if (!d.contains(ev.target)) d.open = false; });
    if (ev.target.closest(".menu-toggle")) $("#sidebar").classList.toggle("open");
    else if (!ev.target.closest("#sidebar")) { const s = $("#sidebar"); if (s) s.classList.remove("open"); }
  });

  document.addEventListener("keydown", (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === "k") {
      const input = $(".search input");
      if (input) { ev.preventDefault(); input.focus(); input.select(); }
    }
  });

  // -------------------------------------------------- live deploy log
  const STATUS = {
    queued: ["Queued", "spin"], running: ["Building", "warning spin"], succeeded: ["Deployed", "success"],
    failed: ["Failed", "error"], cancelled: ["Cancelled", ""],
  };
  // What a running job of each kind is doing (the badge macro in _macros.html says the same).
  const RUNNING = {
    deploy: "Building", restore: "Restoring", reset: "Resetting", rollback: "Rolling back", backup: "Backing up",
    snapshot: "Taking snapshot", admin: "Creating admin", content: "Adding content",
  };
  function statusBadge(status, kind) {
    const known = STATUS[status];
    if (!known) return null;
    let label = known[0];
    if (status === "running" && kind) label = RUNNING[kind] || label;
    if (status === "succeeded" && kind && kind !== "deploy") label = "Done";
    return [label, known[1]];
  }

  const STEP_BADGE = { succeeded: "success", failed: "error", running: "warning spin", warning: "warning", skipped: "plain" };
  function renderSteps(steps, active) {
    const list = $("[data-steps]");
    if (!list || !steps || !steps.length) return;
    list.innerHTML = steps.map((st) => {
      const label = st.status === "pending" && !active ? "Not run" : st.status.charAt(0).toUpperCase() + st.status.slice(1);
      return `<li class="step-${esc(st.status)}"><span class="badge ${STEP_BADGE[st.status] || ""}">${esc(label)}</span> ` +
        `<strong>${esc(st.name)}</strong>${st.note ? ` <span class="subtle">${esc(st.note)}</span>` : ""}</li>`;
    }).join("");
  }

  function streamLog(pre) {
    let offset = 0;
    const url = pre.dataset.deployLog;
    const badge = $("[data-deploy-status]");
    const follow = () => { pre.scrollTop = pre.scrollHeight; };
    async function tick() {
      try {
        const d = await api("GET", url + "?log_offset=" + offset);
        if (d.log) {
          const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
          pre.textContent += d.log;
          if (atBottom) follow();
        }
        offset = d.log_offset;
        renderSteps(d.steps, d.status === "queued" || d.status === "running");
        const shown = statusBadge(d.status, d.kind || (badge && badge.dataset.kind));
        if (badge && shown) {
          badge.className = "badge " + shown[1];
          badge.textContent = shown[0];
        }
        if (d.status === "queued" || d.status === "running") setTimeout(tick, 1500);
        else if (pre.dataset.reloadOnFinish !== undefined && pre.dataset.initialStatus !== d.status) location.reload();
      } catch (err) {
        setTimeout(tick, 5000);
      }
    }
    tick();
  }

  // ----------------------------------------------------- lazy loaders
  const renderers = {
    containers(el, rows) {
      if (!rows.length) { el.innerHTML = '<p class="muted">No containers found on the host.</p>'; return; }
      el.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Container</th><th>Image</th><th>State</th><th>Status</th><th>Ports</th></tr></thead><tbody>' +
        rows.map((r) => {
          const cls = r.State === "running" ? "success" : r.State === "exited" ? "error" : "";
          return `<tr><td><strong>${esc(r.Names)}</strong></td><td class="mono subtle">${esc(r.Image)}</td><td><span class="badge ${cls}">${esc(r.State)}</span></td><td class="muted">${esc(r.Status)}</td><td class="mono subtle">${esc(r.Ports)}</td></tr>`;
        }).join("") + "</tbody></table></div>";
    },
    unmanaged(el, groups) {
      el._groups = groups;
      if (!groups.length) { el.innerHTML = '<p class="muted">Every container on this host is managed by Slipway.</p>'; return; }
      const canClaim = el.dataset.canClaim !== undefined;
      const ports = (g) => g.ports.filter((p) => p.host).map((p) => `${p.service ? p.service + " " : ""}${p.host} → ${p.container}/${p.protocol}`);
      const mounts = (g) => g.mounts.map((m) => `${m.type === "volume" && m.anonymous ? "anonymous volume" : m.source} → ${m.target}`);
      const chips = (items) => items.map((t) => `<span class="chip mono">${esc(t)}</span>`).join(" ") || '<span class="muted">None</span>';
      el.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Image</th><th>State</th><th>Ports</th><th>Mounts</th><th></th></tr></thead><tbody>' +
        groups.map((g, i) => {
          const cls = g.state === "running" ? "success" : g.state === "partial" ? "warning" : g.state === "exited" ? "error" : "";
          const kind = g.kind === "compose"
            ? `<span class="subtle">compose · ${g.containers.length} container(s)${g.working_dir ? ` · <span class="mono">${esc(g.working_dir)}</span>` : ""}</span>`
            : '<span class="subtle">container</span>';
          const warn = g.warnings.length ? ` <span class="badge warning plain" title="${esc(g.warnings.join("\n"))}">${g.warnings.length} note(s)</span>` : "";
          const claimable = canClaim && !(g.kind === "compose" && !/^[a-z0-9][a-z0-9_-]*$/.test(g.name));
          return `<tr><td><strong>${esc(g.name)}</strong>${warn}<br>${kind}</td><td class="mono subtle">${esc(g.images.join(", "))}</td>` +
            `<td><span class="badge ${cls}">${esc(g.state)}</span></td><td>${chips(ports(g))}</td><td>${chips(mounts(g))}</td>` +
            `<td class="actions-cell">${claimable ? `<button class="btn btn-sm" type="button" data-claim="${i}">Claim</button>` : ""}</td></tr>`;
        }).join("") + "</tbody></table></div>";
    },
    logs(el, data) { el.textContent = (data && data.output) || "No log output yet."; el.scrollTop = el.scrollHeight; },
    // GET /instances/{id}/backups?check=true. The rows match the server-rendered ones (pages.backup_present).
    backups(el, data) {
      const ds = el.dataset;
      const labels = { files: ds.filesLabel || "Files", identity: ds.identityLabel || "identity keys" };
      let shas = {};
      try { shas = JSON.parse(ds.jobShas || "{}") || {}; } catch (e) { shas = {}; }
      const ctx = {
        labels, shas, host: ds.host || "the host", busy: ds.busy !== undefined,
        canRestore: ds.canRestore !== undefined, canReset: ds.canReset !== undefined,
        revisionCheck: ds.revisionCheck !== undefined,
      };
      const rows = (data && data.backups) || [];
      const parts = [];
      if (data && data.warning) parts.push(`<div class="card-body"><div class="callout warning">${esc(data.warning)}</div></div>`);
      if (!rows.length) {
        parts.push(`<div class="card-body"><p class="muted">${esc(ds.empty || "No backups yet.")}</p></div>`);
        el.innerHTML = parts.join("");
        return;
      }
      parts.push('<div class="table-wrap"><table class="table backups"><thead><tr><th>Taken</th><th>Why</th><th>Data</th>' +
        '<th>Size</th><th>On host</th><th></th></tr></thead><tbody>' + rows.map((b) => backupRow(b, ds.instance, ctx)).join("") +
        "</tbody></table></div>");
      const notes = [];
      if (ds.hasFilesCap !== undefined) {
        notes.push(`Backups before a deploy or a restore hold the database; those before a reset, and Back up now when you tick it, also hold the ${esc(labels.files.toLowerCase())}.`);
      }
      const other = data && data.other_files;
      if (other) notes.push(`${other} other file${other === 1 ? " in backups/ wasn't" : "s in backups/ weren't"} made by Slipway and ${other === 1 ? "isn't" : "aren't"} listed.`);
      if (notes.length) parts.push(`<div class="card-foot backups-foot">${notes.map((n) => `<span class="subtle">${n}</span>`).join("")}</div>`);
      el.innerHTML = parts.join("");
    },
    readme(el, data) { el.textContent = (data && data.content) || "This repository has no README."; },
  };

  const BACKUP_WHY = {
    pre_deploy: "Before deploy", pre_retry: "Before retry", pre_restore: "Before restore", pre_reset: "Before reset",
    pre_rollback: "Before roll back (for diagnosis)", manual: "Back up now",
  };
  const ON_HOST = { pending: ["Being taken", "warning spin"], missing: ["Missing", "error"], changed: ["Changed", "error"], unverified: ["Unverified", "warning"] };
  const utc = (iso) => { const d = new Date(iso); return isNaN(d) ? String(iso || "") : d.toISOString().slice(0, 16).replace("T", " ") + " UTC"; };
  const sha7 = (sha) => (sha || "").slice(0, 7);

  // One backup's row; the Restore button opens #restore-backup filled from it (_data_dialogs.html).
  function backupRow(b, instanceId, ctx) {
    let why = BACKUP_WHY[b.reason] || b.reason;
    if (b.reason === "pre_deploy" && ctx.shas[b.deployment_id]) why += " " + ctx.shas[b.deployment_id];
    if (b.reason === "manual" && b.created_by) why += " · " + b.created_by;
    const chips = [];
    if (b.has_files) chips.push(["with files", ctx.labels.files]);
    const pinned = b.pinned_reason || "";
    if (pinned.includes("roll back point")) chips.push(["Roll back point", pinned]);
    else if (pinned.includes("kept for undoing")) chips.push(["Kept for undo", pinned]);
    if (b.dirty_note) chips.push([b.dirty_note.replace("Holds data changed by failed ", "after failed ").replace(/ \(.*\)$/, ""), b.dirty_note]);
    let size = b.db_bytes === null || b.db_bytes === undefined ? "—" : humanBytes(b.db_bytes);
    if (b.has_files && b.files_bytes !== null && b.files_bytes !== undefined) size += ` + ${humanBytes(b.files_bytes)} ${ctx.labels.files.toLowerCase()}`;
    const onHost = b.status === "ready" ? (b.checked_at ? ["On host", "success"] : ["Not checked", ""]) : (ON_HOST[b.status] || [b.status, ""]);
    const dataText = [sha7(b.commit_sha), b.revision_short || ""].filter(Boolean).join(" · ") || "—";
    const fillValues = {
      backup_id: b.id, name: b.name, taken: utc(b.taken_at), why, release: sha7(b.commit_sha) || "—",
      revision: b.revision_short || "—", size, has_files: Boolean(b.has_files), files: false,
      identity_note: b.identity_note || "", needs_identity: Boolean(b.needs_reset_perm), restore_identity: false,
      dirty_note: b.dirty_note || "", no_revision_check: !(ctx.revisionCheck && b.revision_short),
    };
    let actions = "";
    if (ctx.canRestore) {
      if (!b.restorable) actions += `<span class="subtle">${esc(b.reason_text)}</span>`;
      else if (b.needs_reset_perm && !ctx.canReset) actions += `<span class="subtle">Restoring it puts back old ${esc(ctx.labels.identity)}; that needs data:reset</span>`;
      else {
        const off = ctx.busy ? ' disabled title="A job is running for this instance; wait for it to finish"' : "";
        actions += `<button class="btn btn-sm" type="button" data-open="restore-backup" data-fill="${esc(JSON.stringify(fillValues))}"${off}>Restore…</button>`;
      }
    }
    if (ctx.canReset) {
      const forget = b.status === "missing";
      const confirmText = forget ? `Forget backup ${b.name}? Its files aren't on ${ctx.host} any more.` : `Delete backup ${b.name} from ${ctx.host}? This can't be undone.`;
      const off = b.pinned ? ` disabled title="${esc("This backup is pinned: " + pinned)}"` : (b.status === "pending" || ctx.busy) ? ' disabled title="Wait for the running job to finish"' : "";
      actions += ` <button class="btn btn-sm btn-danger" type="button" data-api="DELETE /api/v1/instances/${esc(instanceId)}/backups/${esc(b.id)}" data-then="reload" data-confirm="${esc(confirmText)}"${off}>${forget ? "Forget" : "Delete"}</button>`;
    }
    const taken = new Date(b.taken_at);
    return `<tr><td class="nowrap" title="${esc(isNaN(taken) ? "" : taken.toLocaleString())}">${esc(utc(b.taken_at))}</td>` +
      `<td>${esc(why)}${chips.map(([t, title]) => ` <span class="chip" title="${esc(title)}">${esc(t)}</span>`).join("")}${b.note ? `<div class="subtle">${esc(b.note)}</div>` : ""}</td>` +
      `<td class="mono subtle">${esc(dataText)}</td><td class="nowrap">${esc(size)}</td>` +
      `<td><span class="badge ${onHost[1]}">${esc(onHost[0])}</span></td><td class="actions-cell">${actions}</td></tr>`;
  }

  async function load(el) {
    try {
      const data = await api("GET", el.dataset.load);
      renderers[el.dataset.render](el, data);
    } catch (err) {
      el.innerHTML = `<p class="callout error">${esc(err.message)}</p>`;
    }
  }
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-reload-target]");
    if (btn) { const el = $(btn.dataset.reloadTarget); if (el) load(el); }
  });

  // --------------------------------------------------------- claim dialog
  function fillRows(rep, rows) {
    $$(".repeater-row", rep).forEach((r) => r.remove());
    const tpl = $("template", rep);
    rows.forEach((row) => {
      const frag = tpl.content.cloneNode(true);
      $$("[data-f]", frag).forEach((input) => { if (row[input.dataset.f] !== undefined) input.value = row[input.dataset.f]; });
      rep.insertBefore(frag, tpl);
    });
    if (!rows.length) rep.insertBefore(tpl.content.cloneNode(true), tpl);
  }

  function openClaim(group) {
    const dlg = $("#claim-dialog");
    const form = dlg && $("form", dlg);
    if (!form) return;
    const compose = group.kind === "compose";
    const field = (name) => $(`[name="${name}"]`, form);
    const text = (key, value) => $$(`[data-claim-text="${key}"]`, form).forEach((n) => { n.textContent = value || ""; });
    form.reset();
    field("group").value = JSON.stringify({ kind: group.kind, project: group.project, container_id: group.container_id });
    field("build_source").value = compose ? "compose" : "dockerfile";
    field("name").value = group.name;
    field("compose_file").value = group.compose_file || "docker-compose.yml";
    text("name", group.name);
    text("project", group.project);
    text("working_dir", group.working_dir || "(unknown)");
    text("config_files", (group.config_files || []).join(", ") || "(unknown)");
    text("env_files", (group.env_files || []).join(", "));
    $("[data-claim-env-files]", form).hidden = !(group.env_files || []).length;
    text("summary", compose
      ? `Compose project with ${group.containers.length} container(s): ${group.containers.map((c) => c.name).join(", ")}.`
      : `Standalone container running ${group.images.join(", ")}.`);
    $('[data-claim-text="warnings"]', form).innerHTML = group.warnings.map((w) => `<li>${esc(w)}</li>`).join("");
    $("[data-claim-warnings]", form).hidden = !group.warnings.length;
    const ports = group.ports.filter((p) => p.host && (p.protocol === "tcp" || p.protocol === "udp"));
    const unique = ports.filter((p, i) => ports.findIndex((o) => o.host === p.host && o.protocol === p.protocol) === i);
    fillRows($("#claim-port-rep", form), compose ? [] : unique.map((p) => ({ host: p.host, container: p.container, protocol: p.protocol })));
    fillRows($("#claim-vol-rep", form), compose ? [] : group.mounts
      .filter((m) => (m.type === "volume" || m.type === "bind") && !m.source.includes(":"))
      .map((m) => ({ source: m.source, target: m.target })));
    // Pick the repository named like the project or container, if there is one.
    const repo = field("repository_id");
    const match = Array.from(repo.options).find((o) => o.dataset.name === group.name.toLowerCase());
    if (match) repo.value = match.value;
    if (!repo.dataset.branches) { repo.dataset.branches = repo.dataset.branchesTarget; wireBranches(repo); }
    else repo.dispatchEvent(new Event("change"));
    form.dispatchEvent(new Event("change"));
    dlg.showModal();
    field("name").focus();
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-claim]");
    if (!btn) return;
    const list = btn.closest("[data-render=unmanaged]");
    const group = list && list._groups && list._groups[Number(btn.dataset.claim)];
    if (group) openClaim(group);
  });

  // ------------------------------------------------------- snapshot upload
  // The raw file is the request body (no multipart): ?name&notes in the URL, the CSRF token in a header.
  function progressText(loaded, total) {
    const [unit, scale] = total >= 1024 ** 3 ? ["GB", 1024 ** 3] : ["MB", 1024 ** 2];
    return `Uploading ${(loaded / scale).toFixed(1)} of ${(total / scale).toFixed(1)} ${unit}… keep this page open`;
  }

  let uploading = 0;
  if (window.addEventListener) {
    window.addEventListener("beforeunload", (ev) => { if (uploading) { ev.preventDefault(); ev.returnValue = ""; } });
  }

  document.addEventListener("submit", (ev) => {
    const form = ev.target.closest("form[data-upload]");
    if (!form) return;
    ev.preventDefault();
    const input = $("[data-upload-file]", form);
    const file = input && input.files && input.files[0];
    formError(form, "");
    if (!file) { if (!formError(form, "Choose a file to upload")) toast("Choose a file to upload", "error"); return; }
    const body = serialize(form);
    const url = form.dataset.upload + "?name=" + encodeURIComponent(body.name || "") + (body.notes ? "&notes=" + encodeURIComponent(body.notes) : "");
    const submit = ev.submitter || $('[type="submit"]', form);
    const box = $("[data-upload-progress]", form), bar = $("progress", form), status = $("[data-upload-status]", form);
    if (box) box.hidden = false;
    if (status) status.textContent = progressText(0, file.size);
    setLoading(submit, true);
    uploading++;
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", csrf());
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      if (bar) bar.value = Math.round((e.loaded * 100) / e.total);
      if (status) status.textContent = progressText(e.loaded, e.total);
    };
    const finish = () => { uploading--; setLoading(submit, false); if (box) box.hidden = true; };
    xhr.onload = () => {
      finish();
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* non-JSON */ }
      if (xhr.status === 201) {
        if (data && data.status === "locked") {
          // An encrypted file: ask for its passphrase now.
          const dlg = form.closest("dialog");
          if (dlg) dlg.close();
          const unlock = document.getElementById("unlock-snapshot");
          if (unlock) { openDialog(unlock, { action: `POST /api/v1/snapshots/${data.id}/unlock`, name: data.name, passphrase: "" }); return; }
        }
        flashAfterReload(data && data.status === "locked" ? "Uploaded: unlock it with its passphrase" : "Snapshot uploaded");
        location.reload();
        return;
      }
      if (xhr.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); return; }
      const message = errorText(data) || xhr.statusText || "The upload failed";
      if (!formError(form, message)) toast(message, "error");
    };
    xhr.onerror = () => {
      finish();
      const message = "The upload stopped before the end of the file";
      if (!formError(form, message)) toast(message, "error");
    };
    xhr.send(file);
  });

  // Picking a file: say whether it is encrypted (it then asks for a passphrase once it has arrived), and
  // suggest a name from the file name.
  document.addEventListener("change", (ev) => {
    const input = ev.target;
    if (!input || !input.dataset || input.dataset.uploadFile === undefined) return;
    const form = input.closest("form");
    const file = input.files && input.files[0];
    const note = form && $("[data-upload-encrypted]", form);
    const name = form && $('[name="name"]', form);
    if (!file) { if (note) note.hidden = true; return; }
    if (name && !name.value) {
      name.value = file.name.replace(/\.(slipway-snapshot|tar\.gz|tgz|tar)$/i, "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 64);
    }
    if (note && file.slice) {
      file.slice(0, 8).arrayBuffer().then((buf) => {
        note.hidden = String.fromCharCode.apply(null, Array.from(new Uint8Array(buf))) !== "SLWSNAP1";
      }).catch(() => { note.hidden = true; });
    }
  });

  // ------------------------------------------------------- passphrases
  // 24 base32 characters (120 bits) from crypto.getRandomValues, in groups of four.
  const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function newPassphrase() {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => BASE32[b & 31]).join("").match(/.{4}/g).join("-");
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-generate-passphrase]");
    if (!btn) return;
    const value = newPassphrase();
    $$(btn.dataset.generatePassphrase).forEach((input) => {
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const form = btn.closest("form");
    if (form) $$("[data-passphrase-copy]", form).forEach((c) => { c.hidden = false; });
  });

  // ---------------------------------------------------- branch picker
  async function loadBranches(repoSelect) {
    const target = $(repoSelect.dataset.branches);
    if (!target) return;
    const opt = repoSelect.selectedOptions[0];
    // An empty default means the repository's default branch can't be used: make the user pick one.
    const current = target.dataset.current || (opt && opt.dataset.default) || "";
    const placeholder = '<option value="" selected disabled>Choose a branch</option>';
    target.innerHTML = current ? `<option>${esc(current)}</option>` : placeholder;
    if (!repoSelect.value) return;
    try {
      const names = await api("GET", `/api/v1/repositories/${repoSelect.value}/branches`);
      if (current) {
        const list = names.includes(current) ? names : [current, ...names];
        target.innerHTML = list.map((n) => `<option ${n === current ? "selected" : ""}>${esc(n)}</option>`).join("");
      } else {
        target.innerHTML = placeholder + names.map((n) => `<option>${esc(n)}</option>`).join("");
      }
    } catch (err) {
      target.title = err.message; // keep the default branch so the form still works
    }
    target.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function wireBranches(sel) {
    sel.addEventListener("change", () => { $(sel.dataset.branches).dataset.current = ""; loadBranches(sel); });
    loadBranches(sel);
  }

  // ----------------------------- option defaults: <select data-fill> + <option data-fill-<field>="value">
  function fillFromOption(sel) {
    const opt = sel.selectedOptions[0];
    if (!opt || !sel.form) return;
    Array.from(opt.attributes).forEach((attr) => {
      if (!attr.name.startsWith("data-fill-")) return;
      const fields = $$(`[name="${attr.name.slice(10)}"]`, sel.form);
      if (fields.some((f) => f.dataset.edited !== undefined)) return; // keep what the user typed or picked
      fields.forEach((f) => { if (f.type === "radio") f.checked = f.value === attr.value; else f.value = attr.value; });
    });
  }

  function wireFill(sel) {
    sel.form.addEventListener("input", (ev) => { if (ev.isTrusted && ev.target !== sel) ev.target.dataset.edited = ""; });
    sel.addEventListener("change", () => fillFromOption(sel)); // runs before the form's preview/show-when listeners
  }

  // ------------------------------------------------ instance form preview
  function wirePreview(form) {
    // Fields that are fixed once deployed are disabled, and serialize() leaves those out (so they stay out of the
    // PATCH body); the preview reads them from the page instead.
    const field = (name) => $(`[name="${name}"]`, form);
    const update = () => {
      const data = serialize(form);
      const repo = field("repository_id");
      const host = $('[name="host_id"]:checked', form);
      const source = $('[name="build_source"]:checked', form);
      const dockerfile = field("dockerfile_path"), composeFile = field("compose_file");
      const set = (key, value) => $$(`[data-preview="${key}"]`).forEach((n) => { n.textContent = value || "—"; });
      const compose = (source && source.value) === "compose";
      const app = (source && source.value) === "app";
      set("repository", repo && repo.selectedOptions[0] ? repo.selectedOptions[0].textContent.trim() : "");
      set("branch", data.branch);
      const manifestFile = field("manifest_file");
      set("source", app ? `App (${(manifestFile && manifestFile.value) || "slipway.yml"})`
        : compose ? `docker compose (${(composeFile && composeFile.value) || "docker-compose.yml"})`
        : `Dockerfile (${(dockerfile && dockerfile.value) || "Dockerfile"})`);
      set("host", host ? host.dataset.label : "");
      set("name", data.name);
      const dirInput = field("deploy_dir");
      if (dirInput) {
        // The default folder is <deploy root>/<slug>; a saved instance keeps its slug when renamed.
        const slug = dirInput.dataset.slug || (data.name || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);
        const root = host && host.dataset.root ? host.dataset.root.replace(/\/+$/, "") : "";
        const fallback = root ? `${root}/${slug || "<name>"}` : "";
        if (!dirInput.dataset.slug || !dirInput.placeholder) {
          dirInput.placeholder = fallback;
          $$("[data-folder-default]", form).forEach((n) => { n.textContent = fallback || "the host's deploy root / instance name"; });
        }
        const folder = dirInput.value.trim() || dirInput.placeholder;
        set("folder", folder);
        const inRam = Boolean(host && host.dataset.unraid && folder && !/^\/(mnt|boot)(\/|$)/.test(folder));
        $$("[data-unraid-warning]", form).forEach((n) => { n.hidden = !inRam; });
      }
      set("env", Object.keys(data.env || {}).length + " variable(s)");
      const overrides = (data.port_overrides || []).map((o) => `${o.service} ${o.host} → ${o.container}`);
      set("ports", app ? (overrides.length ? `From slipway.yml, with ${overrides.join(", ")}` : "From slipway.yml") : compose ? (overrides.length ? `Compose file, with ${overrides.join(", ")}` : "Defined by compose file") : (data.ports || []).map((p) => `${p.host} → ${p.container} (${(p.protocol || "tcp").toUpperCase()})`).join(", ") || "None");
      const routes = (data.routes || []).map((r) => `${r.hostname} → ${r.service ? r.service + ":" : ""}${r.container || "?"}`);
      set("hostnames", app ? ["From slipway.yml", ...routes].join(", ") : routes.join(", ") || "None");
      set("volumes", app ? "Defined by the app" : compose ? "Defined by compose file" : (data.volumes || []).map((v) => `${v.source} → ${v.target}`).join(", ") || "None");
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  }

  // ------------------------------------------ app instances: the Data fieldset (spec §15.4)
  function adminFieldsHtml(fa) {
    const fields = (fa.fields || []).map((f) => `<div class="field"><label for="adm-${esc(f.name)}">${esc(f.label)}</label>
      <input class="input" id="adm-${esc(f.name)}" name="first_admin.fields.${esc(f.name)}" type="${f.kind === "email" ? "email" : "text"}"
             maxlength="${Number(f.max) || 200}" autocomplete="off" spellcheck="false" data-admin-input>
      ${f.help ? `<span class="help">${esc(f.help)}</span>` : ""}</div>`).join("");
    const mode = fa.password && fa.invite
      ? `<div class="row wrap" style="gap: 8px 20px"><label class="check"><input type="radio" name="first_admin.mode" value="password" checked><span>Set a password</span></label>` +
        `<label class="check"><input type="radio" name="first_admin.mode" value="invite"><span>${esc(fa.invite.label)}</span></label></div>`
      : `<input type="hidden" name="first_admin.mode" value="${fa.password ? "password" : "invite"}">`;
    const min = Math.max(8, (fa.password && fa.password.min_length) || 8);
    const password = fa.password ? `<div class="form-grid" data-admin-password>
      <div class="field"><label for="adm-password">Password</label><input class="input" id="adm-password" name="first_admin.password" type="password" minlength="${min}" maxlength="1024" autocomplete="new-password" data-admin-input></div>
      <div class="field"><label for="adm-repeat">Repeat it</label><input class="input" id="adm-repeat" type="password" data-repeat-of="first_admin.password" maxlength="1024" autocomplete="new-password"></div>
      <span class="help span-2">At least ${min} characters. It is passed to the app once and then forgotten.</span></div>` : "";
    return `<span class="label-text">First admin</span>${fa.help ? `<p class="help" style="margin: 0">${esc(fa.help)}</p>` : ""}` +
      `<p class="help" style="margin: 0" data-admin-optional hidden>Only needed if the snapshot has no account you can sign in with.</p>` +
      `<div class="form-grid">${fields}</div>${mode}${password}`;
  }

  function appData(fs, form) {
    const parse = (v) => { try { return JSON.parse(v); } catch (e) { return null; } };
    const snaps = parse(fs.dataset.snapshots) || [];
    const saved = fs.dataset.savedSnapshot || "";
    const neverLive = fs.dataset.neverLive !== undefined, editing = fs.dataset.editing !== undefined;
    const canSeed = fs.dataset.canSeed !== undefined, canDownload = fs.dataset.canDownload !== undefined;
    const start = $("[data-app-start]", fs), select = $("[data-app-snapshot]", fs);
    const idInput = $('[name="seed_snapshot_id"]', fs), note = $("[data-app-snapshot-note]", fs);
    const adminBox = $("[data-app-admin]", fs), seedBox = $("[data-app-seed]", fs);
    const radio = (v) => $(`[name="seed_from"][value="${v}"]`, fs);
    // touched: the user picked Empty, A snapshot or another snapshot here. An edit sends seed_snapshot_id only
    // then (changing it needs data:reset), so a save that leaves the choice alone never answers 403 (§10.7).
    let man = null, first = true, touched = false;
    const repoName = () => {
      const repo = $('[name="repository_id"]', form);
      const opt = repo && repo.selectedOptions[0];
      return opt ? opt.dataset.fullName || "" : "";
    };
    const chosen = () => {
      const c = $('[name="seed_from"]:checked', fs);
      return start && !start.hidden && c && c.value === "snapshot" ? select.value : "";
    };
    const update = () => {
      const caps = (man && man.capabilities) || [];
      const id = chosen();
      if (select) select.hidden = !(start && !start.hidden && ($('[name="seed_from"]:checked', fs) || {}).value === "snapshot");
      if (idInput) {
        // Sent only when the user changes it (a change needs data:reset); null clears a saved one. "A snapshot"
        // with nothing selectable chooses nothing, so it isn't sent either.
        const picked = ($('[name="seed_from"]:checked', fs) || {}).value;
        idInput.value = JSON.stringify(id || null);
        idInput.disabled = !canSeed || (editing && !touched) || (id || "") === saved || (!editing && !id) ||
          (picked === "snapshot" && !id);
      }
      const snap = snaps.find((x) => x.id === id);
      if (note) {
        note.hidden = !snap;
        const labels = (man && man.data) || {};
        const files = snap && snap.has_files ? `, its ${((labels.files && labels.files.label) || "Files").toLowerCase()}` : "";
        note.textContent = !snap ? "" : snap.brief ? `The first deploy restores ${snap.name}.` :
          `The first deploy restores ${snap.name}: its database${files} and its ${labels.identity_label || "identity keys"} (${(snap.identity_keys || []).join(", ") || "none"}).` +
          (labels.identity_help ? " " + labels.identity_help : "");
      }
      if (seedBox) seedBox.hidden = !caps.includes("starter_content") || Boolean(id);
      if (adminBox) {
        $$("[data-admin-password]", adminBox).forEach((p) => {
          const mode = $('[name="first_admin.mode"]:checked', adminBox) || $('[name="first_admin.mode"]', adminBox);
          p.hidden = Boolean(mode) && mode.value !== "password";
        });
        $$("[data-admin-input]", adminBox).forEach((i) => { i.required = !id && !i.closest("[hidden]"); });
        $$("[data-admin-optional]", adminBox).forEach((n) => { n.hidden = !id; });
      }
    };
    const fillSnapshots = () => {
      const app = man && man.data && man.data.app;
      const repo = repoName();
      const list = snaps.filter((x) => app && x.app === app);
      if (select) {
        select.innerHTML = list.map((x) => {
          // brief: the saved seed shown to someone who can't change it, by its name only.
          const state = x.status && x.status !== "ready" ? ` (${esc(x.status)})` : "";
          if (x.brief) return `<option value="${esc(x.id)}"${x.id === saved ? " selected" : ""}>${esc(x.name)}${state}</option>`;
          const other = !x.repository || x.repository !== repo;
          const off = other && !canDownload;
          return `<option value="${esc(x.id)}"${x.id === saved ? " selected" : ""}${off ? " disabled" : ""}>${esc(x.name)} · ${esc(x.source || x.origin)}${state}` +
            `${other ? ` (${x.repository ? "another repository" : "an unknown repository"}${off ? ": needs snapshots:download" : ""})` : ""}</option>`;
        }).join("");
      }
      // Only a snapshot this user may seed from counts: a select of disabled options has no value.
      const snapRadio = radio("snapshot");
      const usable = list.some((x) => canDownload || (x.repository && x.repository === repo));
      // Without data:reset the saved seed can't be changed, Empty included (the PATCH would leave it as it is).
      const emptyRadio = radio("empty");
      if (emptyRadio) emptyRadio.disabled = editing && Boolean(saved) && !canSeed;
      if (snapRadio) {
        snapRadio.disabled = !canSeed || !usable;
        // A new instance falls back to Empty; an edit keeps showing the saved snapshot (read-only).
        if (snapRadio.disabled && snapRadio.checked && !saved && radio("empty")) radio("empty").checked = true;
      }
    };
    const pick = (ev) => {
      if (ev.target && (ev.target.name === "seed_from" || ev.target === select)) touched = true;
      update();
    };
    fs.addEventListener("change", pick);
    fs.addEventListener("input", pick);
    return (m) => {
      man = m;
      const caps = (m && m.capabilities) || [];
      fs.hidden = !caps.length;
      if (start) start.hidden = !(caps.includes("seed") && (neverLive || !editing));
      fillSnapshots();
      if (first && saved && radio("snapshot")) { radio("snapshot").checked = true; first = false; }
      if (adminBox) {
        const fa = !editing && m && m.first_admin;
        adminBox.innerHTML = fa ? adminFieldsHtml(fa) : "";
        adminBox.hidden = !fa;
      }
      update();
    };
  }

  // ------------------------------------------ app instances: the form reads the branch's slipway.yml
  function wireAppForm(box) {
    const form = box.closest("form");
    const repo = $(box.dataset.repoSelect), branch = $(box.dataset.branchSelect);
    const file = $('[name="manifest_file"]', box);
    const status = $("[data-app-status]", box), settingsBox = $("[data-app-settings]", box);
    const servicesField = $("[data-app-services-field]", box), servicesBox = $("[data-app-services]", box);
    const summary = $("[data-app-summary]", box);
    const settingsInput = $('[name="app_settings"]', box), servicesInput = $('[name="app_services"]', box);
    const parse = (v) => { try { return JSON.parse(v); } catch (e) { return null; } };
    const saved = parse(box.dataset.settings) || {};
    // The instance's saved choice (null: each optional service's default) and what was ticked or unticked
    // here. app_services is only sent once a box was changed, so an untouched form keeps the defaults
    // (a new optional service the repository adds then gets its default too).
    const chosen = parse(box.dataset.services);
    const toggled = {};
    let touched = false;
    const fallback = parse(box.dataset.fallback);
    const dataBox = $("[data-app-data]", box);
    const showData = dataBox ? appData(dataBox, form) : () => {};
    let manifest = null, seq = 0;

    // The hidden inputs carry what is sent; empty (not sent) while no manifest is shown.
    const sync = () => {
      if (!manifest) { settingsInput.value = ""; servicesInput.value = ""; return; }
      const values = {};
      $$("[data-app-setting]", settingsBox).forEach((i) => {
        const v = i.value.trim();
        if (v) { values[i.dataset.appSetting] = v; saved[i.dataset.appSetting] = v; } else delete saved[i.dataset.appSetting];
      });
      settingsInput.value = JSON.stringify(values);
      if (touched && manifest.services.some((s) => s.optional)) {
        servicesInput.value = JSON.stringify(
          $$("[data-app-service]", servicesBox).filter((c) => c.checked).map((c) => c.dataset.appService));
      } else servicesInput.value = "";
    };

    const show = (m, note) => {
      manifest = m;
      settingsBox.innerHTML = m.settings.map((s) => `
        <div class="field"><label for="app-${esc(s.key)}">${esc(s.label)}${s.required ? "" : ' <span class="subtle">(optional)</span>'}</label>
          <input class="input" id="app-${esc(s.key)}" data-app-setting="${esc(s.key)}" value="${esc(saved[s.key] || "")}"
                 placeholder="${esc(s.example || s.default || "")}" autocomplete="off" spellcheck="false">
          <span class="help"><code>${esc(s.key)}</code>${s.help ? " · " + esc(s.help) : ""}${s.default ? ` · default <code>${esc(s.default)}</code>` : ""}</span></div>`).join("");
      const optional = m.services.filter((s) => s.optional);
      servicesField.hidden = !optional.length;
      servicesBox.innerHTML = optional.map((s) => {
        const on = s.name in toggled ? toggled[s.name] : chosen ? chosen.includes(s.name) : s.default;
        return `<label class="check"><input type="checkbox" data-app-service="${esc(s.name)}" ${on ? "checked" : ""}><span><strong>${esc(s.name)}</strong></span></label>`;
      }).join("");
      const services = m.services.map((s) => `<span class="chip mono">${esc(s.name)}${s.port ? " " + s.port : ""}${s.hostname ? " · " + esc(s.hostname) : ""}</span>`).join(" ");
      const secrets = m.secrets.map((s) => `<code>${esc(s.key)}</code>`).join(", ");
      status.innerHTML = `<p style="margin: 0"><strong>${esc(m.name)}</strong>${note ? ` <span class="subtle">· ${esc(note)}</span>` : ""}</p>`;
      summary.innerHTML = `<dl class="kv">
        <dt>Services</dt><dd>${services || '<span class="muted">None</span>'}</dd>
        ${secrets ? `<dt>Secrets</dt><dd>${secrets} <span class="subtle">· generated on the first deploy and kept with the instance</span></dd>` : ""}
        ${m.env_file ? `<dt>Defaults</dt><dd class="mono">${esc(m.env_file)}</dd>` : ""}</dl>`;
      sync();
      showData(m);
      form.dispatchEvent(new Event("change"));
    };

    const clear = (html) => {
      manifest = null;
      settingsBox.innerHTML = ""; servicesBox.innerHTML = ""; servicesField.hidden = true; summary.innerHTML = "";
      status.innerHTML = html;
      sync();
      showData(null);
    };

    const load = async () => {
      const source = $('[name="build_source"]:checked', form);
      if (!source || source.value !== "app") return;
      if (!repo || !repo.value || !branch || !branch.value) {
        clear('<p class="muted">Choose a repository and branch to read its slipway.yml.</p>');
        return;
      }
      const mine = ++seq;
      status.innerHTML = '<p class="muted">Reading slipway.yml…</p>';
      const path = (file && file.value.trim()) || "slipway.yml";
      try {
        const d = await api("GET", `/api/v1/repositories/${repo.value}/manifest?branch=${encodeURIComponent(branch.value)}&path=${encodeURIComponent(path)}`);
        if (mine !== seq) return;
        if (d.manifest) show(d.manifest, `${path} on ${branch.value}`);
        else if (d.error) clear(`<div class="callout error">${esc(d.error)}</div>`);
        else clear(`<div class="callout warning">There is no ${esc(path)} on ${esc(branch.value)}. Add one to the repository, or choose Dockerfile or docker compose.</div>`);
      } catch (err) {
        if (mine !== seq) return;
        if (fallback) show(fallback, `as of the last deploy (GitHub: ${err.message})`);
        else clear(`<div class="callout error">${esc(err.message)}</div>`);
      }
    };

    box.addEventListener("input", (ev) => { if (ev.target.dataset && ev.target.dataset.appSetting !== undefined) sync(); });
    box.addEventListener("change", (ev) => {
      if (!ev.target.dataset || ev.target.dataset.appService === undefined) return;
      toggled[ev.target.dataset.appService] = ev.target.checked;
      touched = true;
      sync();
    });
    if (file) file.addEventListener("change", load);
    if (branch) branch.addEventListener("change", load);
    $$('[name="build_source"]', form).forEach((r) => r.addEventListener("change", load));
    load();
  }

  // ------------------------------------- conditional fields: data-show-when="field=value" (or value|value)
  function wireShowWhen(form) {
    const targets = $$("[data-show-when]", form);
    const required = $$("[data-required-when]", form);
    if (!targets.length && !required.length) return;
    const holds = (spec) => {
      const [name, values] = spec.split("=");
      const checked = $(`[name="${name}"]:checked`, form);
      const field = checked || $(`[name="${name}"]:not([type=radio])`, form);
      return Boolean(field) && values.split("|").includes(field.value);
    };
    const update = () => {
      targets.forEach((el) => { el.hidden = !holds(el.dataset.showWhen); });
      required.forEach((el) => { el.required = holds(el.dataset.requiredWhen) && !el.closest("[hidden]"); });
      if (targets.length) syncRequired(form);
    };
    form.addEventListener("change", update);
    update();
  }

  // -------------------------------------------------------------- boot
  document.addEventListener("DOMContentLoaded", () => {
    try {
      const flash = sessionStorage.getItem("slipway-flash");
      if (flash) {
        sessionStorage.removeItem("slipway-flash");
        let note = { message: flash, kind: "success" };
        try { note = JSON.parse(flash); } catch (e) { /* plain text from an older page */ }
        toast(note.message, note.kind === "warning" ? "warning" : "success");
      }
    } catch (e) { /* ignore */ }
    $$("[data-deploy-log]").forEach(streamLog);
    $$("[data-load]").forEach(load);
    $$("select[data-fill]").forEach(wireFill);
    $$("select[data-branches]").forEach(wireBranches);
    $$("form").forEach(wireShowWhen);
    $$("[data-app-form]").forEach(wireAppForm);
    $$("form[data-preview-form]").forEach(wirePreview);
    // Pages with work in progress (a snapshot being checked) reload while they are being looked at, but not
    // while a dialog is open.
    $$("[data-poll-reload]").forEach((el) => {
      const ms = Number(el.dataset.pollReload) || 5000;
      const tick = () => {
        if (document.visibilityState !== "hidden" && !$("dialog[open]")) location.reload();
        else setTimeout(tick, ms);
      };
      setTimeout(tick, ms);
    });
    const params = new URLSearchParams(location.search);
    $$("dialog[data-open-on]").forEach((dlg) => { if (params.get(dlg.dataset.openOn)) dlg.showModal(); });
    $$("[data-filter]").forEach((input) => {
      input.addEventListener("input", () => {
        const q = input.value.toLowerCase();
        $$(input.dataset.filter + " tbody tr").forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
      });
    });
  });

  window.slipway = { api, toast, serialize, humanBytes, statusBadge };
})();
