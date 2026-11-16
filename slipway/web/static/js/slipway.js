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
 *
 * Environments (phase 3 §12.6):
 *   <select data-map="route_tls" data-map-key="api.example.com">  (body.route_tls["api.example.com"] = value, when set)
 *   <div data-load=... data-lazy>                           (loaded when its dialog opens, not with the page)
 *   <div data-render="traffic_plan">                        (the Traffic card's rows, or with data-mode="list" Activate's plan)
 *   <form data-env-flow>                                    (the New environment flow, wireEnvFlow)
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
    // A map whose keys may hold dots (hostnames): <select data-map="route_tls" data-map-key="api.example.com">.
    $$("[data-map]", form).forEach((el) => {
      if (el.disabled || el.closest("[hidden]")) return;
      const map = out[el.dataset.map] = out[el.dataset.map] || {};
      if (el.value) map[el.dataset.mapKey] = el.value;
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
    $$("[data-lazy][data-load]", dlg).forEach(load); // e.g. Activate's plan, read when the dialog opens
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
    activate: "Activating", publish: "Publishing", discard: "Discarding", remove_slot: "Removing", teardown: "Deleting",
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
    // GET /environments/{id}/traffic/plan (§10.7): the Traffic card's rows, or (data-mode="list") the Activate
    // dialog's plan list, whose blockers keep the dialog's button disabled. Nothing is changed by reading it.
    traffic_plan(el, data) {
      el.innerHTML = trafficPlanHtml(data, el.dataset);
      const form = el.closest && el.closest("form");
      const submit = form && $("[data-plan-submit]", form);
      if (submit) submit.disabled = planBlockers(data).length > 0;
    },
  };

  // What each planned change shows as (traffic.Change.action for Switchyard, its status for DNS).
  const SWITCH_STATE = {
    none: ["Up to date", "success"], create: ["Will create", "primary"], update: ["Will update", "warning"],
    delete: ["Will delete", "warning"], forget: ["Will forget", ""],
  };
  const DNS_STATE = {
    ok: ["Up to date", "success"], create: ["Will create", "primary"], update: ["Will update", "warning"],
    covered: ["Covered", ""], claimable: ["Not Slipway's", "warning"], conflict: ["Blocked", "error"],
    delete: ["Will delete", "warning"], forget: ["Will forget", ""], adopt: ["Will record", "primary"],
  };

  function planBlockers(data) {
    return [].concat((data && data.switch && data.switch.blockers) || [], (data && data.dns && data.dns.blockers) || []);
  }

  function trafficPlanHtml(data, ds) {
    const routes = (data && data.routes) || [];
    const sw = data && data.switch, dns = data && data.dns;
    const env = ds.env || "", canClaim = ds.canClaim !== undefined;
    const byName = (plan) => {
      const out = {};
      ((plan && plan.changes) || []).forEach((c) => { out[c.hostname] = c; });
      return out;
    };
    const swc = byName(sw), dnsc = byName(dns);
    const blockedBy = (plan, host) => ((plan && plan.blockers) || []).filter((b) => String(b).indexOf(host) >= 0);
    const badge = (pair, title) => `<span class="badge ${pair[1]}"${title ? ` title="${esc(title)}"` : ""}>${esc(pair[0])}</span>`;
    const upstream = (c) => {
      const up = c && c.before && (c.before.upstreams || [])[0];
      return up && up.host ? `${up.host}:${up.port}` : "";
    };
    const named = [];
    const blockers = planBlockers(data);

    if (ds.mode === "list") {
      // Activate's dialog: what the switch writes, and anything that stops it.
      const items = [];
      ((sw && sw.changes) || []).filter((c) => c.action !== "none").forEach((c) => {
        items.push(`<li><span class="mono">${esc(c.hostname)}</span> ${badge(SWITCH_STATE[c.action] || [c.action, ""])} <span class="subtle">${esc(c.summary || c.upstream || "")}</span></li>`);
      });
      ((dns && dns.changes) || []).filter((c) => c.status === "create" || c.status === "update").forEach((c) => {
        items.push(`<li><span class="mono">${esc(c.hostname)}</span> ${badge(["DNS: " + DNS_STATE[c.status][0], DNS_STATE[c.status][1]])}</li>`);
      });
      blockers.forEach((b) => items.push(`<li class="blocked">${badge(["Blocked", "error"])} ${esc(b)}</li>`));
      if (!items.length) items.push('<li class="subtle">Every name already points where Activate would point it.</li>');
      return `<ul class="plan-list">${items.join("")}</ul>` +
        (blockers.length ? '<p class="error-text" style="margin: 0">Slipway changed nothing. Fix these in Switchyard or Cloudflare, then open this again.</p>' : "");
    }

    const rows = routes.map((r) => {
      const s = swc[r.hostname], d = dnsc[r.hostname];
      const sb = blockedBy(sw, r.hostname), db = blockedBy(dns, r.hostname);
      sb.concat(db).forEach((b) => { if (named.indexOf(b) < 0) named.push(b); });
      let swCell;
      if (!sw) swCell = '<span class="subtle">Not used</span>';
      else if (sb.length) swCell = `${badge(["Blocked", "error"], sb.join("\n"))} <span class="subtle">${esc(sb.join("; "))}</span>`;
      else if (s) swCell = badge(SWITCH_STATE[s.action] || [s.action, ""], s.summary);
      else swCell = '<span class="subtle">Not planned</span>';
      let dnsCell;
      if (!dns) dnsCell = '<span class="subtle">Off</span>';
      else if (db.length && !d) dnsCell = `${badge(["Blocked", "error"], db.join("\n"))} <span class="subtle">${esc(db.join("; "))}</span>`;
      else if (d) {
        const state = DNS_STATE[d.status] || [d.status || d.action, ""];
        dnsCell = badge(state, d.summary);
        if (d.status === "conflict" && d.summary) dnsCell += ` <span class="subtle">${esc(d.summary)}</span>`;
        if (d.status === "claimable" && canClaim) {
          const body = esc(JSON.stringify({ hostname: r.hostname }));
          dnsCell += ` <button class="btn btn-sm" type="button" data-api="POST /api/v1/environments/${esc(env)}/dns/claim" data-body="${body}" data-then="reload" data-success="Claimed ${esc(r.hostname)}">Claim</button>`;
        }
      } else dnsCell = '<span class="subtle">Not planned</span>';
      const scheme = r.tls_mode === "off" ? "http" : "https";
      return `<tr data-name="${esc(r.hostname)}"><td><a class="mono" href="${scheme}://${esc(r.hostname)}" target="_blank" rel="noopener">${esc(r.hostname)}</a></td>` +
        `<td>${r.follows === "server" ? "Data server" : "Live slot"}</td>` +
        `<td class="mono subtle">${esc(upstream(s) || "—")}</td><td>${swCell}</td><td>${dnsCell}</td></tr>`;
    });
    const other = blockers.filter((b) => named.indexOf(b) < 0);
    const head = other.length
      ? `<div class="card-body"><div class="callout error">${other.map((b) => esc(b)).join("<br>")}</div></div>` : "";
    if (!rows.length) return head + '<div class="card-body"><p class="muted" style="margin: 0">No public names yet: they come from slipway.yml with the first deploy.</p></div>';
    return head + '<div class="table-wrap"><table class="table traffic"><thead><tr><th>Name</th><th>Follows</th><th>Now</th>' +
      `<th>Switchyard</th><th>DNS</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  }

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

  // ------------------------------------------------- rows that open in place
  // <tr data-expand="details-id"> opens the row with that id right below it. Clicks on the row's own links and
  // buttons do what they say, except ones marked data-expand too; ctrl/cmd/shift-click still follows the link.
  // Content marked data-load-later is fetched the first time its row opens.
  function setExpanded(row, open) {
    const details = document.getElementById(row.dataset.expand);
    if (!details) return;
    details.hidden = !open;
    row.classList.toggle("selected", open);
    row.setAttribute("aria-expanded", open ? "true" : "false");
    $$(`[aria-controls="${row.dataset.expand}"]`, row).forEach((el) => el.setAttribute("aria-expanded", open ? "true" : "false"));
    if (open) {
      $$("[data-load-later]", details).forEach((el) => {
        el.dataset.load = el.dataset.loadLater;
        el.removeAttribute("data-load-later");
        load(el);
      });
    }
  }
  document.addEventListener("click", (ev) => {
    const row = ev.target.closest("tr[data-expand]");
    if (!row || ev.defaultPrevented || ev.button !== 0) return;
    const target = ev.target.closest("a, button, input, select, textarea, label, summary");
    if (target && !target.hasAttribute("data-expand")) return;
    if (target && (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey)) return;
    if (window.getSelection && String(window.getSelection()).length) return; // selecting text, not opening
    ev.preventDefault();
    const open = row.getAttribute("aria-expanded") !== "true";
    setExpanded(row, open);
    // Keep ?repo= (or whatever the row carries) in the address bar, so a reload or a shared link opens the same row.
    if (row.dataset.repo) {
      const url = new URL(location.href);
      const still = $$("tr[data-expand][aria-expanded=true][data-repo]");
      const shown = open ? row : still[still.length - 1];
      if (shown) url.searchParams.set("repo", shown.dataset.repo);
      else url.searchParams.delete("repo");
      history.replaceState(null, "", url);
    }
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

  // The capabilities the Data fieldset has a field for: backups to keep (a dump), what the data starts with (a
  // restore), the first admin and starter content. Any other (data.attach, data.server, bluegreen,
  // revision checks) shows nothing.
  // A slipway.yml phase 2 could read (none of data.attach, data.server, bluegreen) keeps phase 2's rule: the
  // fieldset shows for any capability, with Backups to keep (I1).
  const DATA_FIELD_CAPS = ["backup", "seed", "first_admin", "starter_content"];
  const PHASE3_CAPS = ["attach", "server", "bluegreen"];
  const phase3Caps = (caps) => caps.some((c) => PHASE3_CAPS.includes(c));
  const hasDataFields = (caps) => (phase3Caps(caps) ? caps.some((c) => DATA_FIELD_CAPS.includes(c)) : caps.length > 0);

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
      fs.hidden = !hasDataFields(caps);
      const keep = $('[name="keep_backups"]', fs);
      const keepField = keep && (keep.closest(".field") || keep);
      if (keepField) keepField.hidden = phase3Caps(caps) && !caps.includes("backup");
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
    // The environment pages send them as settings and services (data-settings-field, data-services-field).
    const settingsInput = $(`[name="${box.dataset.settingsField || "app_settings"}"]`, box);
    const servicesInput = $(`[name="${box.dataset.servicesField || "app_services"}"]`, box);
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
      box.dispatchEvent(new CustomEvent("slipway:manifest", { detail: m }));
      form.dispatchEvent(new Event("change"));
    };

    const clear = (html) => {
      manifest = null;
      settingsBox.innerHTML = ""; servicesBox.innerHTML = ""; servicesField.hidden = true; summary.innerHTML = "";
      status.innerHTML = html;
      sync();
      showData(null);
      box.dispatchEvent(new CustomEvent("slipway:manifest", { detail: null }));
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
      // An unticked checkbox has no value: "x=on" holds only while it is ticked.
      const value = field && field.type === "checkbox" && !field.checked ? "" : field && field.value;
      return Boolean(field) && values.split("|").includes(value);
    };
    const update = () => {
      targets.forEach((el) => { el.hidden = !holds(el.dataset.showWhen); });
      required.forEach((el) => { el.required = holds(el.dataset.requiredWhen) && !el.closest("[hidden]"); });
      if (targets.length) syncRequired(form);
    };
    form.addEventListener("change", update);
    update();
  }

  // ------------------------------------------------- the New environment flow (phase 3 §12.3)
  // The step that holds each field a refusal of POST /environments names ({detail, field}, §9.1).
  const FIELD_STEP = {
    name: 1, repository_id: 1, branch: 1, manifest_file: 1,
    data_mode: 2,
    hosts: 3, "hosts.blue": 3, "hosts.green": 3, "hosts.data": 3,
    settings: 4, services: 4, env: 4,
    hostnames: 5, route_tls: 5, traffic: 5, "traffic.switch": 5, "traffic.dns": 5, auto_activate: 5,
    keep_backups: 6, seed_snapshot_id: 6, seed_content: 6, first_admin: 6,
  };
  const FLOW_STEPS = 7;
  const NAME_RE = /^[a-z][a-z0-9-]{0,24}[a-z0-9]$/;

  function fieldStep(field) {
    if (!field) return 0;
    if (FIELD_STEP[field]) return FIELD_STEP[field];
    return FIELD_STEP[String(field).split(".")[0]] || 0;
  }

  // Like api(), but answers {status, data, text} instead of throwing, so the flow can tell a refusal (4xx) from
  // an answer that never came (status 0) or a server error (5xx): after those, a create may have happened.
  async function request(method, url, body) {
    const opts = { method, headers: { Accept: "application/json", "X-CSRF-Token": csrf() }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let res;
    try { res = await fetch(url, opts); } catch (err) {
      return { status: 0, data: null, text: "Slipway didn't answer" + (err && err.message ? ` (${err.message})` : "") };
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (res.status === 401) location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
    return { status: res.status, data, text: errorText(data) || res.statusText || "Request failed" };
  }

  // The field a refusal is about: {detail, field} from validate_create, or the first location of a 422.
  function refusalField(res) {
    const d = res.data;
    if (d && typeof d.field === "string") return d.field;
    if (d && Array.isArray(d.detail) && d.detail[0]) return (d.detail[0].loc || []).filter((x) => x !== "body").join(".");
    return "";
  }

  // What the check and the create send (EnvironmentCreate): the form's fields, reshaped. ``planning`` is set for
  // the checks before the Data step: a first admin the manifest needs is filled with placeholders, so the check
  // can answer the plan (the Traffic step's names) before the Data step is filled in. Nothing is written by a check.
  function flowBody(root, planning, manifest) {
    const raw = serialize(root);
    const shape = ($('[name="shape"]:checked', root) || {}).value || "single";
    const two = shape === "bluegreen";
    const keep = Boolean(($('[name="keep_data"]', root) || {}).checked);
    const mode = two || keep ? "server" : "slot";
    const chosen = raw.hosts || {};
    const hosts = {};
    ["blue", "green", "data"].forEach((slot) => {
      if (slot === "green" && !two) return;
      if (slot === "data" && mode !== "server") return;
      if (chosen[slot]) hosts[slot] = chosen[slot];
    });
    const traffic = raw.traffic || {};
    const dnsOn = Boolean(($('[name="dns_on"]', root) || {}).checked);
    const dns = traffic.dns || {};
    const body = {
      name: raw.name || "", repository_id: raw.repository_id || "", branch: raw.branch, manifest_file: raw.manifest_file,
      data_mode: mode, hosts, settings: raw.settings || {}, env: raw.env || {}, route_tls: raw.route_tls || {},
      auto_activate: two && Boolean(raw.auto_activate),
      traffic: { switch: traffic.switch || (two ? "switchyard" : "none"),
                 dns: dnsOn ? Object.assign({}, dns.address ? { address: dns.address } : {}, { proxied: Boolean(dns.proxied) }) : null },
    };
    if (raw.services !== undefined) body.services = raw.services;
    ["keep_backups", "seed_snapshot_id", "seed_content", "first_admin"].forEach((k) => { if (raw[k] !== undefined) body[k] = raw[k]; });
    Object.keys(body).forEach((k) => { if (body[k] === undefined || body[k] === "") delete body[k]; });
    const fa = manifest && manifest.first_admin;
    if (planning && fa && !body.first_admin && !body.seed_snapshot_id) {
      const fields = {};
      (fa.fields || []).forEach((f) => { fields[f.name] = f.kind === "email" ? "admin@example.com" : "A"; });
      body.first_admin = fa.password
        ? { fields, mode: "password", password: "x".repeat(Math.max(8, fa.password.min_length || 8)) }
        : { fields, mode: "invite" };
    }
    return body;
  }

  function wireEnvFlow(root) {
    const sections = $$("[data-step]", root).sort((a, b) => Number(a.dataset.step) - Number(b.dataset.step));
    const tabs = $$("[data-step-tab]", root);
    const live = $("[data-flow-live]", root);
    const back = $("[data-flow-back]", root), next = $("[data-flow-next]", root);
    const deploy = $("[data-flow-deploy]", root), restart = $("[data-flow-restart]", root);
    const result = $("[data-flow-result]", root), message = $("[data-flow-message]", root), open = $("[data-flow-open]", root);
    const modeInput = $('[name="data_mode"]', root);
    const ds = root.dataset;
    // unsure: a create got no answer or a 5xx, so it may have happened. created: the environment exists and only
    // its first deployment is left to start (the page is locked on Review).
    const state = { current: 1, plan: null, manifest: null, unsure: false, created: null, name: "", busy: false };
    root._flow = state;

    const stepName = (n) => (sections[n - 1] && sections[n - 1].dataset.stepName) || String(n);
    const say = (text, link, href) => {
      if (!result) return;
      result.hidden = !text;
      if (message) message.textContent = text || "";
      if (open) { open.hidden = !link; open.textContent = link || ""; if (href) open.setAttribute("href", href); }
    };
    const stepError = (n, text) => {
      const box = sections[n - 1] && $("[data-step-error]", sections[n - 1]);
      if (box) { box.textContent = text || ""; box.hidden = !text; }
    };
    const clearMarks = () => $$('[aria-invalid="true"]', root).forEach((el) => el.setAttribute("aria-invalid", "false"));
    const mark = (field) => {
      if (!field) return;
      const el = $(`[name="${field}"]`, root) || $(`[data-field="${field}"]`, root) ||
        $(`[data-field="${String(field).split(".")[0]}"]`, root);
      if (el) { el.setAttribute("aria-invalid", "true"); if (el.focus) el.focus(); }
    };

    function go(n) {
      state.current = Math.max(1, Math.min(FLOW_STEPS, n));
      sections.forEach((sec, i) => { sec.classList.toggle("current", i + 1 === state.current); });
      tabs.forEach((tab) => {
        const k = Number(tab.dataset.stepTab);
        tab.setAttribute("aria-current", k === state.current ? "step" : "false");
        tab.classList.toggle("done", k < state.current);
        tab.classList.toggle("active", k === state.current);
      });
      if (live) live.textContent = `Step ${state.current} of ${FLOW_STEPS}: ${stepName(state.current)}`;
      if (back) back.disabled = state.current === 1 || Boolean(state.created);
      if (next) next.hidden = state.current === FLOW_STEPS;
      if (deploy) deploy.hidden = state.current !== FLOW_STEPS;
      if (state.current === 5) fillTraffic();
      if (state.current === FLOW_STEPS) fillReview();
    }

    // The step's own checks, before Slipway is asked: {field, text} or null.
    function clientCheck(n) {
      const body = flowBody(root, false, state.manifest);
      if (n === 1) {
        if (!NAME_RE.test(body.name || "")) return { field: "name", text: "Use 2-26 lowercase letters, digits and hyphens, starting with a letter and ending with a letter or digit" };
        if (!body.repository_id) return { field: "repository_id", text: "Choose a repository" };
        if (!body.branch) return { field: "branch", text: "Choose a branch" };
      }
      if (n === 3) {
        if (!body.hosts.blue) return { field: "hosts.blue", text: "Choose a host for blue" };
        if ((($('[name="shape"]:checked', root) || {}).value) === "bluegreen" && !body.hosts.green) {
          return { field: "hosts.green", text: "Choose a host for green" };
        }
        if (body.data_mode === "server" && !body.hosts.data) return { field: "hosts.data", text: "Choose a host for the data server" };
        if (body.hosts.data && (body.hosts.data === body.hosts.blue || body.hosts.data === body.hosts.green)) {
          return { field: "hosts.data", text: "The data server needs a host of its own" };
        }
      }
      return null;
    }

    async function nextStep() {
      if (state.busy || state.created) return;
      const n = state.current;
      clearMarks(); stepError(n, ""); say("");
      const problem = clientCheck(n);
      if (problem) { stepError(n, problem.text); mark(problem.field); return; }
      state.busy = true; if (next) setLoading(next, true);
      const res = await request("POST", "/api/v1/environments?check=true", flowBody(root, n < 6, state.manifest));
      state.busy = false; if (next) setLoading(next, false);
      if (res.status === 200) {
        state.plan = (res.data && res.data.plan) || null;
        go(n + 1);
        return;
      }
      const field = refusalField(res), at = fieldStep(field);
      if (at > n && res.status >= 400 && res.status < 500) { go(n + 1); return; } // a later step's field: fine for now
      if (at && res.status >= 400 && res.status < 500) {
        go(at);
        stepError(at, res.text);
        mark(field);
        return;
      }
      stepError(n, res.text);
    }

    async function startFirst() {
      const res = await request("POST", `/api/v1/environments/${state.created}/deploy`, {});
      if (res.status === 202) { location.assign(`/environments/${state.created}`); return; }
      // Created, but the first deployment didn't start: stay on Review, locked; Deploy tries the start again.
      lock(true);
      say(`Created ${state.name}, but its first deployment didn't start: ${res.text}.`, "Open the environment",
          `/environments/${state.created}`);
    }

    async function deployAll() {
      if (state.busy) return;
      state.busy = true; if (deploy) setLoading(deploy, true);
      try {
        say(""); stepError(FLOW_STEPS, "");
        if (!state.created) {
          const body = flowBody(root, false, state.manifest);
          const res = await request("POST", "/api/v1/environments", body);
          if (res.status === 201 && res.data && res.data.id) {
            state.created = res.data.id;
            state.name = res.data.name || body.name;
          } else if (res.status === 0 || res.status >= 500) {
            state.unsure = true; // it may have been created: the answer was lost
            say(`${res.text}. The environment may or may not have been created; check the list before trying again.`,
                "Open the list", "/environments");
            return;
          } else {
            const field = refusalField(res), at = fieldStep(field);
            if (state.unsure && /already exists/.test(res.text)) {
              say("It may have been created already:", "open it", "/environments");
              return;
            }
            if (at && at < FLOW_STEPS) { go(at); stepError(at, res.text); mark(field); return; }
            stepError(FLOW_STEPS, res.text);
            return;
          }
        }
        await startFirst();
      } finally {
        state.busy = false; if (deploy) setLoading(deploy, false);
        if (state.created && deploy) deploy.disabled = false;
      }
    }

    function lock(on) {
      root.toggleAttribute ? root.toggleAttribute("data-locked", on) : (on ? root.setAttribute("data-locked", "") : null);
      if (back) back.disabled = on;
      if (restart) restart.disabled = on;
      if (next) next.hidden = true;
      if (deploy) { deploy.hidden = false; deploy.textContent = on ? "Start the deployment" : deploy.textContent; }
    }

    // Keeps data_mode, the hosts' disabled options and the shape's notes in step with what is chosen.
    function syncChoices() {
      const shapeEl = $('[name="shape"]:checked', root);
      const two = Boolean(shapeEl && shapeEl.value === "bluegreen");
      const keep = $('[name="keep_data"]', root);
      const mode = two || (keep && keep.checked && !keep.closest("[hidden]")) ? "server" : "slot";
      if (modeInput) modeInput.value = mode;
      const pick = (slot) => { const el = $(`[data-host-select="${slot}"]`, root); return el ? el.value : ""; };
      const blue = pick("blue"), green = two ? pick("green") : "";
      $$("[data-host-select]", root).forEach((sel) => {
        const slot = sel.dataset.hostSelect;
        $$("option", sel).forEach((o) => {
          if (!o.value || o.dataset.unpinned !== undefined) return;
          let off = "";
          if (mode === "server" && slot !== "data" && !o.dataset.ip) off = "Its address must be an IP for the data server to let it in";
          if (slot === "data" && (o.value === blue || o.value === green)) off = "The data server needs a host of its own";
          o.disabled = Boolean(off);
          o.textContent = (o.dataset.label || o.textContent) + (off ? `: ${off}` : "");
        });
      });
      const same = $("[data-same-host]", root);
      if (same) same.hidden = !(two && blue && blue === green);
      const none = $('[name="traffic.switch"][value="none"]', root), sy = $('[name="traffic.switch"][value="switchyard"]', root);
      if (none) {
        none.disabled = two;
        if (two && none.checked && sy && !sy.disabled) sy.checked = true;
      }
      const slots = $("[data-name-slots]", root), name = ($('[name="name"]', root) || {}).value || "<name>";
      if (slots) slots.textContent = `${name}-blue, ${name}-green and ${name}-data`;
    }

    // The manifest decides whether Blue/Green and a data server are possible (its capabilities, §12.3 step 2).
    root.addEventListener("slipway:manifest", (ev) => {
      const m = ev.detail;
      state.manifest = m;
      const caps = (m && m.capabilities) || [];
      const path = (($('[name="manifest_file"]', root) || {}).value || "slipway.yml").trim();
      const bg = $('[name="shape"][value="bluegreen"]', root), keep = $('[name="keep_data"]', root);
      const bgReason = $("[data-bluegreen-reason]", root), keepReason = $("[data-server-reason]", root);
      if (bg) {
        bg.disabled = !caps.includes("bluegreen");
        if (bg.disabled && bg.checked) $('[name="shape"][value="single"]', root).checked = true;
      }
      if (bgReason) bgReason.textContent = !m ? "Read slipway.yml first." : caps.includes("bluegreen") ? "" :
        `${path} doesn't declare data.migrations: expand_contract, which two slots need`;
      if (keep) {
        keep.disabled = !caps.includes("server");
        if (keep.disabled) keep.checked = false;
      }
      if (keepReason) keepReason.textContent = caps.includes("server") || !m
        ? "The database and file store run on a host of their own, so a second slot can be added later."
        : `${path} doesn't describe a data server (data.server)`;
      const noData = $("[data-no-data]", root);
      if (noData) noData.hidden = Boolean(m) && caps.some((c) => DATA_FIELD_CAPS.includes(c));
      syncChoices();
    });

    // The Traffic step's table, from the last check's plan (§12.3 step 5).
    const tls = {};
    function fillTraffic() {
      const body = $("[data-traffic-rows]", root);
      if (!body) return;
      $$("[data-map='route_tls']", body).forEach((sel) => { if (sel.value) tls[sel.dataset.mapKey] = sel.value; });
      const plan = state.plan;
      if (!plan || !(plan.hostnames || []).length) {
        body.innerHTML = '<tr><td colspan="4" class="muted">slipway.yml gives no public names, or Slipway can list them only once the earlier steps are filled in.</td></tr>';
        return;
      }
      const sw = ($('[name="traffic.switch"]:checked', root) || {}).value || "none";
      const through = sw === "switchyard" ? `Switchyard (${ds.trafficAddress || "no traffic address set"})` : "Not published by Slipway";
      const slots = plan.slots || {};
      const modes = [["auto", "Let's Encrypt"], ["dns", "DNS challenge"], ["internal", "Internal CA"], ["off", "No TLS"]];
      body.innerHTML = plan.hostnames.map((h) => {
        const to = h.follows === "server" ? `The data server on ${(slots.data || {}).host || "its host"}` : `Blue on ${(slots.blue || {}).host || "its host"}`;
        const chosen = tls[h.hostname] || "";
        const options = [`<option value=""${chosen ? "" : " selected"}>Switchyard's (${esc(ds.defaultTls || "auto")})</option>`]
          .concat(modes.map(([v, l]) => `<option value="${v}"${chosen === v ? " selected" : ""}>${esc(l)}</option>`)).join("");
        return `<tr><td class="mono">${esc(h.hostname)}</td><td>${esc(through)}</td><td>${esc(to)}</td>` +
          `<td><select class="input" data-map="route_tls" data-map-key="${esc(h.hostname)}" aria-label="TLS for ${esc(h.hostname)}">${options}</select></td></tr>`;
      }).join("");
    }

    // Review: every choice as a definition list.
    function fillReview() {
      const dl = $("[data-review]", root);
      if (!dl) return;
      const body = flowBody(root, false, state.manifest);
      const text = (sel) => { const el = $(sel, root); const o = el && el.selectedOptions && el.selectedOptions[0]; return o ? (o.dataset.label || o.textContent).trim() : ""; };
      const two = (($('[name="shape"]:checked', root) || {}).value) === "bluegreen";
      const rows = [
        ["Name", body.name], ["Repository", text('[name="repository_id"]')], ["Branch", body.branch],
        ["Manifest", body.manifest_file || "slipway.yml"],
        ["Shape", two ? "Blue/Green, with a data server" : body.data_mode === "server" ? "Single slot, with a data server" : "Single slot"],
        ["Blue", text('[data-host-select="blue"]')],
      ];
      if (body.hosts.green) rows.push(["Green", text('[data-host-select="green"]')]);
      if (body.hosts.data) rows.push(["Data server", text('[data-host-select="data"]')]);
      rows.push(["Settings", Object.keys(body.settings || {}).map((k) => `${k}=${body.settings[k]}`).join(", ") || "None set"]);
      if (body.services) rows.push(["Optional services", body.services.join(", ") || "None"]);
      rows.push(["Variables", Object.keys(body.env || {}).join(", ") || "None"]);
      rows.push(["Switch", body.traffic.switch === "switchyard" ? `Switchyard${ds.trafficAddress ? ` (${ds.trafficAddress})` : ""}` : "None"]);
      rows.push(["DNS", body.traffic.dns ? `Cloudflare, at ${body.traffic.dns.address || "the integration's public IP"}${body.traffic.dns.proxied ? ", proxied" : ""}` : "Not published"]);
      if (two) rows.push(["Activate", body.auto_activate ? "Automatically when the smoke test passes" : "When you choose Activate"]);
      const names = ((state.plan && state.plan.hostnames) || []).map((h) => h.hostname);
      rows.push(["Public names", names.join(", ") || "None"]);
      const fa = body.first_admin;
      rows.push(["Data", body.seed_snapshot_id ? "From a snapshot" : "Start empty"]);
      if (fa) rows.push(["First admin", (fa.fields && (fa.fields.email || Object.values(fa.fields)[0])) || "Set"]);
      if (body.keep_backups) rows.push(["Backups to keep", String(body.keep_backups)]);
      dl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v || "—")}</dd>`).join("");
    }

    root.addEventListener("change", syncChoices);
    root.addEventListener("input", (ev) => { if (ev.target && ev.target.name === "name") syncChoices(); });
    // Enter in a field would submit the form natively: it moves to the next step instead.
    root.addEventListener("submit", (ev) => { ev.preventDefault(); if (state.current < FLOW_STEPS) nextStep(); else deployAll(); });
    if (next) next.addEventListener("click", (ev) => { ev.preventDefault(); nextStep(); });
    if (back) back.addEventListener("click", (ev) => { ev.preventDefault(); if (!state.created) { clearMarks(); go(state.current - 1); } });
    if (deploy) deploy.addEventListener("click", (ev) => { ev.preventDefault(); deployAll(); });
    if (restart) restart.addEventListener("click", (ev) => {
      ev.preventDefault();
      if (state.created || !confirm("Start over? Every choice on this page is cleared.")) return;
      if (root.reset) root.reset();
      state.plan = null; state.unsure = false;
      clearMarks(); say(""); sections.forEach((_, i) => stepError(i + 1, ""));
      root.dispatchEvent(new Event("change"));
      go(1);
    });
    syncChoices();
    go(1);
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
    $$("[data-load]").forEach((el) => { if (el.dataset.lazy === undefined) load(el); });
    $$("select[data-fill]").forEach(wireFill);
    $$("select[data-branches]").forEach(wireBranches);
    // Before wireShowWhen: the flow keeps its computed fields (data_mode) current on every change first.
    $$("form[data-env-flow]").forEach(wireEnvFlow);
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

  window.slipway = { api, toast, serialize, humanBytes, statusBadge, renderers, FIELD_STEP, fieldStep, flowBody };
})();
