/* Slipway front-end: small, dependency-free progressive enhancement.
 *
 * Declarative hooks used by the templates:
 *   <button data-api="POST /api/v1/..." data-confirm="..." data-then="reload|redirect:/x|redirect:/x/{id}|follow:/x">
 *     (follow: goes where the answer's {redirect} says, else to /x)
 *   <form data-form="POST /api/v1/..." data-then="...">   (fields → JSON; see serialize())
 *   <form data-omit-unchanged="field ...">                 (leave those fields out of the body unless the user changed them)
 *   <button data-open="dialog-id">, <button data-close>
 *   <pre data-deploy-log="/api/v1/deployments/<id>">       (live build log)
 *   <div data-load="/api/v1/..." data-render="containers|unmanaged|logs|readme">
 *   <button data-claim="<n>"> in the unmanaged list opens #claim-dialog filled from that group
 *   <button data-copy="text"> / data-copy-target="#el"
 *   <select data-fill> with <option data-fill-<field>="value">   (picking an option fills untouched fields)
 *   <form data-once>                                       (after it succeeds its submit button stays disabled)
 *   <button data-update-target data-branch=.. data-sha=..> opens #update-confirm filled from its data-*
 *   <section data-update-run="<run id>">                   (follows an upgrade of Slipway: steps, status, log)
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
 *
 * New VMs (phase 5 §12.2-12.6):
 *   <select data-vm-host="blue"> + <div data-vm-form="blue">   (New VM on <account>: network, address, size; vmSpec)
 *   <form data-vm-slot-form>                                (Add a slot: a New VM option sends {machine} for host_id)
 *   <div data-render="vm_live">                             (GET .../machines: power, Lost, Hidden, Off, Forget)
 *   <div data-render="vm_snapshots">                        (the VM snapshots card's rows and buttons)
 *   <input type="number" data-scale="1024">                 (typed in one unit, sent in another: GB to MB)
 *
 * DigitalOcean (phase 4 §17.2-17.5):
 *   <div data-render="cloud_objects">                       (the DigitalOcean card's objects; live callouts go to [data-cloud-callouts])
 *   <form data-cost-confirm data-old-cents="4700">          (Check the price, then the new total typed: wireCostForm)
 *   <div data-render="grow_sizes">                          (the Grow dialog's selects, from the account's catalog)
 *
 * Host setup:
 *   <section data-host-setup="/api/v1/hosts/<id>/setup">  (follows Slipway setting up a new server)
 *   <form data-migrate-form="<check url>">                (Check shows what a migration copies; Migrate sends the unticked items as skip)
 *
 * Analytics:
 *   <div class="chart-plot" data-chart='{...}'>             (chart tooltips on hover and from the keyboard)
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
      const err = new Error(errorText(data) || res.statusText || "Request failed");
      err.status = res.status; // a refusal's body stays readable (an untrusted certificate, say)
      err.data = data;
      err.detail = Boolean(data && data.detail !== undefined);
      throw err;
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
    if (spec.startsWith("follow:")) {
      // Sign-out of a HackSpaceLabs session answers {redirect}: Keycloak's own sign-out page, on its own origin.
      const target = data && typeof data.redirect === "string" ? data.redirect : "";
      location.href = /^https?:\/\//i.test(target) ? target : sameOrigin(target || spec.slice(7));
      return;
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
    // data-scale: a number shown in one unit and sent in another (a VM's memory typed in GB, sent in MB).
    if (input.type === "number") {
      if (input.value === "") return null;
      return input.dataset.scale ? Math.round(Number(input.value) * Number(input.dataset.scale)) : Number(input.value);
    }
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
    const once = form.dataset.once !== undefined;
    if (once && form._sent) return; // a second click while the first is on its way, or after it succeeded
    const [method, url] = form.dataset.form.split(" ");
    const submit = ev.submitter || $('[type="submit"]', form);
    let body;
    try { body = serialize(form); } catch (err) { return toast("Invalid input: " + err.message, "error"); }
    omitUnchanged(form, body);
    if (form.dataset.vmSlotForm !== undefined) vmSlotBody(form, body); // Add a slot on a new VM (P5 §9.5)
    if (submit && submit.name) body[submit.name] = submit.value === "true" ? true : submit.value === "false" ? false : submit.value;
    setLoading(submit, true);
    formError(form, "");
    if (once) form._sent = true;
    let ok = false;
    try {
      const data = await api(method, url, body);
      ok = true;
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
      if (once) form._sent = false;
      if (!formError(form, err.message)) toast(err.message, "error");
    } finally {
      setLoading(submit, false);
      if (ok && once && submit) submit.disabled = true;
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
    const ok = inputs.every((i) => {
      if (i.dataset.costInput !== undefined) return Boolean(i.dataset.mustEqual) && i.value === i.dataset.mustEqual;
      return i.closest("[hidden]") || i.value === i.dataset.mustEqual;
    });
    // data-plan-blocked="1": the traffic plan hasn't loaded, failed to, or has blockers; data-blocked: the
    // dialog can't succeed (a production Delete without a snapshot).
    $$('[type="submit"]', form).forEach((b) => {
      b.disabled = !ok || b.dataset.planBlocked === "1" || b.dataset.blocked !== undefined;
    });
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
    $$("form", dlg).forEach((form) => {
      if (form.dataset.costConfirm !== undefined) costReset(form);
      form.dispatchEvent(new Event("change")); syncRequired(form); checkMustEqual(form);
    });
    $$("[data-lazy][data-load]", dlg).forEach(load); // e.g. Activate's plan, read when the dialog opens
    $$("form[data-cost-auto]", dlg).forEach((form) => costPrice(form, $("[data-cost-price]", form)));
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

  // ------------------------------------------------- theme, sign-out
  // The theme belongs to the HSL Suite kit (hsl-ui/suite.js, js/theme.js): light unless the user turns dark mode on
  // in the user menu, never the operating system's. The user menu (<hsl-user-menu>) fires hsl-signout. A HackSpaceLabs
  // session answers {redirect}: Keycloak's own sign-out page; a local one answers 204, which goes to /login.
  document.addEventListener("hsl-signout", async () => {
    try {
      then("follow:/login", await api("POST", "/api/v1/auth/logout"));
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.addEventListener("keydown", (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === "k") {
      const input = $(".search input");
      if (input) { ev.preventDefault(); input.focus(); input.select(); }
    }
  });

  // --------------------------------------------- setting up a new host
  // <section data-host-setup="/api/v1/hosts/<id>/setup" data-status="..."> follows Slipway preparing a server.
  // The log comes from the server (apt output), so it is only ever set with textContent.
  const SETUP_STATUS = {
    running: ["Setting up", "warning spin"], succeeded: ["Set up", "success"],
    failed: ["Failed", "error"], interrupted: ["Interrupted", "error"],
  };

  function drawSetup(el, d) {
    const status = SETUP_STATUS[d.status] ? d.status : "failed";
    const badge = $("[data-setup-status]", el);
    if (badge) {
      badge.className = "badge " + SETUP_STATUS[status][1];
      badge.textContent = SETUP_STATUS[status][0];
    }
    const items = $$("[data-step]", el);
    const at = Math.max(0, items.map((li) => li.dataset.step).indexOf(d.step));
    items.forEach((li, i) => {
      let state = "pending";
      if (status === "succeeded" || i < at) state = "done";
      else if (i === at) state = status === "running" ? "active" : "failed";
      li.className = "update-step " + state;
    });
    const box = $("[data-setup-message]", el);
    if (box) {
      box.textContent = typeof d.error === "string" ? d.error : "";
      box.hidden = !box.textContent || status === "running";
    }
    const pre = $("[data-setup-log]", el);
    if (pre && typeof d.log === "string") {
      const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
      pre.textContent = d.log.replace(ANSI, "");
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    }
  }

  function followSetup(el) {
    const url = el.dataset.hostSetup;
    const started = el.dataset.status === "running";
    async function tick() {
      let d;
      try { d = await api("GET", url); } catch (err) { setTimeout(tick, 5000); return; }
      drawSetup(el, d);
      if (d.status === "running") setTimeout(tick, 1500);
      else if (started) location.reload(); // the host's health, key and buttons changed too
    }
    tick();
  }

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
    // Phases 4 and 5 (P4 §17.5, Decision 33).
    certificate: "Renewing", deactivate: "Taking off the air", vm_snapshot: "Taking VM snapshot",
    vm_revert: "Reverting", vm_drop: "Deleting VM snapshot",
  };
  function statusBadge(status, kind) {
    const known = STATUS[status];
    if (!known) return null;
    let label = known[0];
    if (status === "running" && kind) label = RUNNING[kind] || label;
    if (status === "succeeded" && kind && kind !== "deploy") label = "Done";
    return [label, known[1]];
  }

  // A step's badge by its status; every job kind's steps use the same five (the five new kinds included).
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
        '<th>Size</th><th>' + esc(ds.storedHeader || "On host") + '</th><th></th></tr></thead><tbody>' + rows.map((b) => backupRow(b, ds.instance, ctx)).join("") +
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
      if (submit) {
        const blocked = planBlockers(data).length > 0;
        submit.dataset.planBlocked = blocked ? "1" : "";
        submit.disabled = blocked;
        if (form && $("[data-must-equal]", form)) checkMustEqual(form);
      }
    },
    // GET /environments/{id}/cloud (P4 §16, §17.3): each object read live, its status and price a month; the
    // live callouts (a droplet powered off, the active slot's droplet gone, an object changed by hand).
    cloud_objects(el, data) {
      el.innerHTML = cloudObjectsHtml(data, el.dataset);
      const box = document.querySelector("[data-cloud-callouts]");
      if (box) box.innerHTML = cloudCallouts(data, el.dataset).join("");
    },
    // GET /provider-accounts/{id}/catalog (the Grow dialog): every size offered, the current one selected.
    grow_sizes(el, data) {
      const form = el.closest("form");
      el.innerHTML = "";
      if (!form) return;
      const ds = el.dataset;
      const droplet = $("[data-grow-droplet]", form), db = $("[data-grow-db]", form), standby = $("[data-grow-standby]", form);
      const fill = () => {
        if (droplet) fillOptions(droplet, dropletOptions(data), ds.droplet);
        const nodes = standby && standby.checked ? "2" : String(ds.nodes || "1");
        if (db) fillOptions(db, ((data && data.db_sizes) || {})[nodes] || [], db.value || ds.db, (v) => v);
      };
      fill();
      if (standby && !standby._grow) { standby._grow = true; standby.addEventListener("change", fill); }
    },
  };

  // ---------------------------------------------------- DigitalOcean (P4 §12, §17.2-17.5)
  const DO_KIND = {
    droplet: "Droplet", database: "Database cluster", load_balancer: "Load balancer", vpc: "VPC", firewall: "Cloud firewall",
    certificate: "Certificate", bucket: "Bucket", spaces_key: "Spaces key",
  };
  const DO_STATUS = { ok: ["OK", "success"], gone: ["Gone", "error"], changed: ["Changed", "error"] };
  // Cents as the figure people type ("84.00"), and as a sum ("$84.00").
  const figure = (cents) => { const c = Math.abs(Number(cents) || 0); return `${Number(cents) < 0 ? "-" : ""}${Math.floor(c / 100)}.${String(c % 100).padStart(2, "0")}`; };
  const money = (cents) => (cents === null || cents === undefined ? "—" : Number(cents) === 0 ? "No charge" : `$${figure(cents)}`);
  const deltaText = (oldCents, newCents) => { const d = Number(newCents) - Number(oldCents); return `${d >= 0 ? "+" : "-"}$${figure(Math.abs(d))} a month`; };

  function cloudObjectsHtml(data, ds) {
    const objects = (data && data.objects) || [], pending = (data && data.pending) || [];
    if (!objects.length && !pending.length) {
      return '<div class="card-body"><p class="muted" style="margin: 0">Nothing on DigitalOcean yet: the first deploy makes it.</p></div>';
    }
    const rows = objects.map((o) => {
      const st = DO_STATUS[o.status] || [o.status, ""];
      const power = o.kind === "droplet" && o.power && o.power !== "active" ? ` <span class="badge warning">${esc(o.power === "off" ? "Powered off" : o.power)}</span>` : "";
      return `<tr data-object="${esc(o.kind)}"><td>${esc(DO_KIND[o.kind] || o.kind)}</td><td class="mono">${esc(o.name)}${o.detail ? `<div class="subtle">${esc(o.detail)}</div>` : ""}</td>` +
        `<td><span class="badge ${st[1]}">${esc(st[0])}</span>${power}</td><td class="nowrap">${esc(money(o.monthly_cents))}</td></tr>`;
    });
    pending.forEach((p) => {
      rows.push(`<tr data-object="${esc(p.kind)}" data-pending><td>${esc(DO_KIND[p.kind] || p.kind)}</td><td class="mono">${esc(p.name)}</td>` +
        `<td><span class="badge warning" title="${esc(p.sent_at ? "Sent " + utc(p.sent_at) : "")}">Create not answered yet</span></td><td class="subtle">—</td></tr>`);
    });
    return '<div class="table-wrap"><table class="table cloud-objects"><thead><tr><th>Kind</th><th>Name</th><th>Status</th><th>Monthly</th></tr></thead><tbody>' +
      rows.join("") + "</tbody></table></div>";
  }

  // The callouts only a live read can give (§17.3, §15.13): a droplet left powered off, the active slot's droplet
  // gone (when the page didn't already say so), an object that no longer looks like Slipway's.
  function cloudCallouts(data, ds) {
    const out = [];
    const callout = (cls, key, text, extra) => `<div class="callout ${cls}" data-callout="${esc(key)}"${cls === "error" ? ' role="alert"' : ""}><div>${esc(text)}.${extra || ""}</div></div>`;
    const slot = ds.activeSlot, droplet = ds.activeDroplet;
    ((data && data.notes) || []).forEach((note) => {
      // The read's own "Droplet <active> is gone" note: the gone-<slot> callout below (or the page's) says it.
      if (droplet && note.startsWith(`Droplet ${droplet} is gone from DigitalOcean`)) return;
      const off = /^(\S+) is powered off$/.exec(note);
      out.push(callout("warning", off ? "off-" + off[1] : "note", note, off ? " The next deploy to its slot powers it on first." : ""));
    });
    ((data && data.objects) || []).forEach((o) => {
      if (o.kind === "droplet" && o.status === "gone" && droplet && o.name === droplet && slot &&
          !document.querySelector(`[data-callout="gone-${slot}"]`)) {
        const button = ds.canDeploy !== undefined
          ? `<div class="row wrap" style="margin-top: 10px"><button class="btn btn-sm btn-primary" type="button" data-api="POST /api/v1/environments/${esc(ds.env)}/deploy" data-body="${esc(JSON.stringify({ slot }))}" data-then="reload" data-success="Deploy queued">Deploy to ${esc(slot)}</button></div>` : "";
        out.push(callout("error", "gone-" + slot, `${slot}'s droplet is gone, so nothing answers through the load balancer: deploy to ${slot} to build it again`, button));
      } else if (o.status === "changed") {
        out.push(callout("error", "changed-" + o.name, `${DO_KIND[o.kind] || o.kind} ${o.name} no longer looks like Slipway's: Slipway changes nothing on it until it does`));
      }
    });
    return out;
  }

  // ---------------------------------------------------- VMs on the environment page (P5 §12.3, §12.6 item 2)
  // The build chips only a live read gives (pages.BUILD_CHIPS and BUILD_TITLES say the same).
  const VM_CHIPS = {
    lost: ["Lost", "error", "A ready VM the hypervisor doesn't have any more, or has without Slipway's markers"],
    hidden: ["Hidden", "warning", "Proxmox says the VM's id is in use, but the token can't see it"],
    off: ["Off", "warning", "The VM is powered off"],
  };
  const VM_POWER = { running: "Running", stopped: "Off", suspended: "Suspended" };
  const VM_WHY = { manual: "By hand", pre_resize: "Before a resize", pre_revert: "Before a revert" };
  const VM_SNAP_STATUS = { pending: ["Being taken", "warning"], failed: ["Failed", "error"], missing: ["Missing", "error"] };

  // What GET /environments/{id}/machines says of one VM: its chip (Lost, Hidden, Off or none), its power text,
  // whether Forget the VM applies (lost) and whether Remove would meet blockers forget_vms gets past all of. That
  // last is the answer's own ``forgettable`` (read with ?blockers=true, as Remove slot's check reads them), never
  // guessed from the power read.
  function vmLiveView(m) {
    const live = m && m.live, ready = m && m.stage === "ready";
    const out = { chip: null, text: "", title: "", lost: false, off: false, forgettable: Boolean(m && m.forgettable === true) };
    if (!live) { out.text = ready ? "Not read" : ""; return out; }
    if (live.error) {
      out.text = live.error === "busy" ? "Busy: the account" : "Couldn't check";
      out.title = live.detail || live.error;
      return out;
    }
    if (live.hidden) { out.chip = "hidden"; }
    else if (ready && (live.lost || (live.exists && live.ours === false))) {
      out.chip = "lost"; out.lost = Boolean(live.lost);
      out.title = live.why_not_ours || "";
    } else if (ready && live.power === "stopped") { out.chip = "off"; out.off = true; }
    if (live.busy) out.text = `Busy: ${String(live.busy).split(" (")[0]}`;
    else if (out.chip === "lost") out.text = live.lost ? "Gone" : "Not Slipway's";
    else if (out.chip === "hidden") out.text = "Can't be seen";
    else out.text = VM_POWER[live.power] || live.power || "";
    if (live.busy) out.title = live.busy;
    return out;
  }
  function vmLiveHtml(m) {
    const v = vmLiveView(m);
    const chip = v.chip ? `<span class="badge build-chip ${VM_CHIPS[v.chip][1]}" title="${esc(VM_CHIPS[v.chip][2])}">${esc(VM_CHIPS[v.chip][0])}</span>` : "";
    const power = v.text ? `<span class="vm-power${v.off ? " off" : ""}" title="${esc(v.title)}">${esc(v.text)}</span>` : "";
    return { chip, power, view: v };
  }
  // The Slots card's read (no blockers): power and chips only. Whether Remove and Delete offer forget_vms is
  // read by their dialogs when they open (renderers.vm_forget).
  renderers.vm_live = function (el, answer) {
    const list = Array.isArray(answer) ? answer : [];
    list.forEach((m) => {
      const { chip, power, view } = vmLiveHtml(m);
      $$(`[data-vm-live="${m.slot}"]`).forEach((cell) => { cell.innerHTML = power; });
      if (chip) $$(`[data-vm-chip="${m.slot}"]`).forEach((cell) => { cell.innerHTML = chip; });
      $$(`[data-forget-slot="${m.slot}"]`).forEach((b) => { b.hidden = !view.lost; });
      if (view.off || view.chip) $$(`[data-vm-error="${m.slot}"]`).forEach((e) => { e.hidden = false; });
    });
    el.innerHTML = list.some((m) => m.live)
      ? '<span class="subtle">Power and state as the hypervisors show them now.</span>' : "";
  };

  // GET /environments/{id}/machines?blockers=true, read when Remove slot, Delete or a retry's dialog opens:
  // the forget_vms box shows only when the VMs' removal has blockers and forget_vms gets past every one (what
  // the job's check then does), and names them. ``data-forget-scope`` is ``slot`` (the dialog's slot, filled by
  // its button, or ``data-forget-slot``) or ``all`` (Delete, a teardown's retry). A VM whose blockers weren't
  // read in time, or a failed read, leaves the box as the page rendered it.
  function vmForgetOffer(list, scope, slot) {
    const vms = (Array.isArray(list) ? list : []).filter((m) => scope !== "slot" || m.slot === slot);
    if (!vms.length) return { known: true, offer: false, texts: [] };
    if (vms.some((m) => m.forgettable === null || m.forgettable === undefined)) return { known: false, offer: false, texts: [] };
    const blocked = vms.filter((m) => (m.blockers || []).length);
    const offer = blocked.length > 0 && blocked.every((m) => m.forgettable === true);
    const texts = offer ? [].concat(...blocked.map((m) => m.blockers.map((b) => String(b.text).replace(/\.$/, "")))) : [];
    return { known: true, offer, texts };
  }
  renderers.vm_forget = function (el, answer) {
    const scope = el.dataset.forgetScope || "all";
    const form = el.closest && el.closest("form");
    const slotEl = form && $('[data-slot="slot"]', form);
    const slot = el.dataset.forgetSlot || (slotEl ? slotEl.textContent : "");
    const got = vmForgetOffer(answer, scope, slot);
    el.textContent = got.texts.length ? `${got.texts.join(". ")}.` : "";
    if (!got.known) return;
    const box = el.closest && (el.closest("[data-remove-forget]") || el.closest("[data-forget-vms]"));
    if (!box) return;
    box.hidden = !got.offer;
    if (!got.offer) $$('[name="forget_vms"]', box).forEach((c) => { c.checked = false; });
    if (form) { syncRequired(form); checkMustEqual(form); }
  };

  // GET /environments/{id}/vm-snapshots (S22's object): the card's rows, with Revert and Delete opening their
  // dialogs (#vm-revert, #vm-drop) filled from the row. ``ds`` is the card's dataset (env, account, can-act,
  // none-text).
  function vmSnapshotsHtml(data, ds) {
    const d = data || {}, parts = [];
    if (d.snapshot_mode === "none") {
      return `<div class="card-body"><p class="muted" style="margin: 0">${esc(ds.noneText || "This VM's storage can't take VM snapshots. Backups (above) still work.")}</p></div>`;
    }
    if (d.error) parts.push(`<div class="card-body"><div class="callout warning">${esc(d.detail || d.error)}</div></div>`);
    const rows = d.snapshots || [];
    if (!rows.length) {
      parts.push(`<div class="card-body"><p class="muted" style="margin: 0">No VM snapshots of ${esc(d.vm || "the VM")} yet.</p></div>`);
      return parts.join("");
    }
    const act = ds.canAct !== undefined, account = ds.account || "the hypervisor";
    const base = `/api/v1/environments/${ds.env}/vm-snapshots`;
    const body = rows.map((r) => {
      const st = VM_SNAP_STATUS[r.status];
      const on = r.on_hypervisor === true ? '<span class="badge success">Yes</span>'
        : r.on_hypervisor === false ? '<span class="badge error">Not there any more</span>' : '<span class="subtle">Couldn\'t check</span>';
      const lost = (r.backups_after || []).length
        ? `Everything written since is lost, including these backups: ${r.backups_after.join(", ")}.` : "Everything written since is lost.";
      let actions = "";
      if (act) {
        const revert = r.revert || {}, drop = r.drop || {};
        const rf = { action: `POST ${base}/${r.id}/revert`, snapshot: r.name, taken: utc(r.taken_at), sha7: sha7(r.commit_sha) || "none", lost };
        actions += revert.available
          ? `<button class="btn btn-sm btn-danger" type="button" data-open="vm-revert" data-fill="${esc(JSON.stringify(rf))}">Revert…</button>`
          : `<button class="btn btn-sm" type="button" disabled title="${esc(revert.reason || "")}">Revert…</button>`;
        const df = { action: `DELETE ${base}/${r.id}`, snapshot: r.name };
        actions += drop.available
          ? ` <button class="btn btn-sm" type="button" data-open="vm-drop" data-fill="${esc(JSON.stringify(df))}">Delete…</button>`
          : ` <button class="btn btn-sm" type="button" disabled title="${esc(drop.reason || "")}">Delete…</button>`;
        if (!revert.available && revert.reason) actions += `<div class="subtle">${esc(revert.reason)}</div>`;
      }
      return `<tr data-vm-snapshot="${esc(r.name)}"><td class="mono">${esc(r.name)}${r.newest ? ' <span class="chip">Newest</span>' : ""}` +
        `${st ? ` <span class="badge ${st[1]}">${esc(st[0])}</span>` : ""}</td>` +
        `<td class="nowrap">${esc(utc(r.taken_at))}</td><td>${esc(VM_WHY[r.reason] || r.reason)}</td>` +
        `<td class="mono">${esc(sha7(r.commit_sha) || "—")}</td><td>${esc(r.note || "")}</td><td>${on}</td>` +
        `<td class="actions-cell">${actions}</td></tr>`;
    }).join("");
    parts.push('<div class="table-wrap"><table class="table vm-snapshots"><thead><tr><th>Name</th><th>Taken</th><th>Why</th>' +
      `<th>Commit</th><th>Note</th><th>On ${esc(account)}</th><th></th></tr></thead><tbody>${body}</tbody></table></div>`);
    return parts.join("");
  }
  renderers.vm_snapshots = function (el, data) { el.innerHTML = vmSnapshotsHtml(data, el.dataset); };

  // The estimate as a table (§12.1): every line, the total and the foot.
  function costTableHtml(cost) {
    if (!cost) return "";
    const rows = (cost.lines || []).map((l) => `<tr><td>${esc(l.label)}</td><td class="nowrap">${esc(money(l.cents))}</td></tr>`).join("");
    return '<div class="table-wrap"><table class="table cost-table"><thead><tr><th>What</th><th>A month</th></tr></thead>' +
      `<tbody>${rows}</tbody><tfoot><tr><th>Total</th><th class="nowrap">$${esc(cost.total || figure(cost.total_cents))}</th></tr></tfoot></table></div>` +
      (cost.note ? `<p class="help" style="margin: 0">${esc(cost.note)}</p>` : "");
  }
  renderers.cost = function (el, cost) {
    el.innerHTML = costTableHtml(cost);
    const box = el.closest("form") || document;
    $$("[data-cost-figure]", box).forEach((f) => { f.textContent = cost ? cost.total : ""; });
  };

  const dropletOptions = (data) => ((data && data.sizes) || []).map((z) => ({
    value: z.slug,
    label: `${z.slug} · ${z.vcpus} vCPU, ${Math.round((Number(z.memory) || 0) / 1024 * 10) / 10} GB, ${z.disk} GB` +
      (z.price_monthly !== undefined && z.price_monthly !== null ? ` · $${Number(z.price_monthly).toFixed(2)} a month` : ""),
  }));

  // Fills a select with {value, label} options (or plain values), keeping ``keep`` chosen when it is offered.
  function fillOptions(select, items, keep, label) {
    const opts = items.map((it) => (typeof it === "string" ? { value: it, label: label ? label(it) : it } : it));
    const first = select.dataset.placeholder ? `<option value="">${esc(select.dataset.placeholder)}</option>` : "";
    select.innerHTML = first + opts.map((o) => `<option value="${esc(o.value)}"${o.value === keep ? " selected" : ""}>${esc(o.label)}</option>`).join("");
    if (keep && opts.some((o) => o.value === keep)) select.value = keep;
  }

  // ------------------------------------- a cost a person confirms by typing it (Add slot, Grow; P4 §12.2)
  // <form data-cost-confirm data-old-cents>: Check the price sends the form without confirm_cost as the API's
  // dry run (?check=true, ChangeCheckOut: every refusal runs, nothing is written); its ``cost.total`` is the new
  // total, which the [data-cost-input] then must equal. Changing anything else in the form asks for the price
  // again.
  function costReset(form) {
    const box = $("[data-cost-box]", form), input = $("[data-cost-input]", form);
    if (box) box.hidden = true;
    if (input) { input.value = ""; input.dataset.mustEqual = ""; }
    checkMustEqual(form);
  }

  async function costPrice(form, btn) {
    const [method, url] = form.dataset.form.split(" ");
    let body;
    try { body = serialize(form); } catch (err) { return toast("Invalid input: " + err.message, "error"); }
    delete body.confirm_cost;
    if (btn) setLoading(btn, true);
    formError(form, "");
    const res = await request(method, url + (url.indexOf("?") === -1 ? "?" : "&") + "check=true", body);
    if (btn) setLoading(btn, false);
    const cost = res.status === 200 && res.data && res.data.cost;
    if (!cost || !cost.total) {
      const text = res.status === 200 ? "Slipway couldn't price this change" : res.text;
      if (!formError(form, text)) toast(text, "error");
      return;
    }
    const total = String(cost.total);
    const cents = Number(cost.total_cents);
    const box = $("[data-cost-box]", form), input = $("[data-cost-input]", form), text = $("[data-cost-text]", form);
    $$("[data-cost-figure]", form).forEach((f) => { f.textContent = total; });
    if (text) {
      const old = form.dataset.oldCents;
      const delta = cost.delta || (old !== undefined && old !== "" ? deltaText(old, cents) : "");
      text.textContent = `The new estimate is about $${total} a month` + (delta ? ` (${delta})` : "") + ".";
    }
    if (input) { input.dataset.mustEqual = total; input.value = ""; }
    if (box) box.hidden = false;
    checkMustEqual(form);
    if (input && input.focus) input.focus();
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest && ev.target.closest("[data-cost-price]");
    if (!btn) return;
    const form = btn.closest("form[data-cost-confirm]");
    if (form) { ev.preventDefault(); costPrice(form, btn); }
  });
  document.addEventListener("change", (ev) => {
    const el = ev.target;
    const form = el && el.closest && el.closest("form[data-cost-confirm]");
    if (form && el.dataset && el.dataset.costInput === undefined && el.name) costReset(form);
  });

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
    // The load balancer (do_lb) plans one change for every name: its targets (P4 §11.6).
    const whole = ds.switchLabel && sw && (sw.changes || []).length === 1 ? sw.changes[0] : null;
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
        (blockers.length ? `<p class="error-text" style="margin: 0">Slipway changed nothing. Fix these in ${ds.switchLabel ? "DigitalOcean" : "Switchyard"} or Cloudflare, then open this again.</p>` : "");
    }

    const rows = routes.map((r) => {
      const s = swc[r.hostname], d = dnsc[r.hostname];
      const sb = blockedBy(sw, r.hostname), db = blockedBy(dns, r.hostname);
      sb.concat(db).forEach((b) => { if (named.indexOf(b) < 0) named.push(b); });
      let swCell;
      if (!sw) swCell = '<span class="subtle">Not used</span>';
      else if (sb.length) swCell = `${badge(["Blocked", "error"], sb.join("\n"))} <span class="subtle">${esc(sb.join("; "))}</span>`;
      else if (s || whole) swCell = badge(SWITCH_STATE[(s || whole).action] || [(s || whole).action, ""], (s || whole).summary);
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
      `<th>${esc(ds.switchLabel || "Switchyard")}</th><th>DNS</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
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
    // A managed environment's backups are kept on this Slipway server (P4 §10.5); pages.backup_present agrees.
    const stored = b.location === "slipway" ? ["On Slipway", "success"] : ["On host", "success"];
    const onHost = b.status === "ready" ? (b.checked_at ? stored : ["Not checked", ""]) : (ON_HOST[b.status] || [b.status, ""]);
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

  // A traffic plan's dialog button stays off while the plan is read, and after a read that failed: only
  // renderers.traffic_plan, with the plan in hand and no blocker, lets it on.
  function planSubmitOf(el) {
    if (el.dataset.render !== "traffic_plan") return null;
    const form = el.closest && el.closest("form");
    return (form && $("[data-plan-submit]", form)) || null;
  }
  function blockPlan(submit) {
    if (!submit) return;
    submit.dataset.planBlocked = "1";
    submit.disabled = true;
  }

  async function load(el) {
    const planSubmit = planSubmitOf(el);
    blockPlan(planSubmit);
    try {
      const data = await api("GET", el.dataset.load);
      renderers[el.dataset.render](el, data);
    } catch (err) {
      el.innerHTML = `<p class="callout error">${esc(err.message)}</p>`;
      blockPlan(planSubmit);
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

  // ------------------------------------------------------- migrate dialog
  // Check asks the server what the migration would copy; Migrate stays disabled until a check passes.
  function sizeText(kb) {
    if (kb === null || kb === undefined) return "size unknown";
    let v = kb, unit = "KiB";
    for (const u of ["MiB", "GiB", "TiB"]) { if (v < 1024) break; v /= 1024; unit = u; }
    return (unit === "KiB" || v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + unit;
  }

  function migrateState(form) {
    const plan = form._plan;
    const submit = $("[data-migrate-submit]", form);
    if (!plan) { submit.disabled = true; return; }
    const skip = $$("[data-migrate-item]", form).filter((c) => !c.checked).map((c) => c.value);
    $('[name="skip"]', form).value = JSON.stringify(skip);
    const items = plan.items.filter((i) => i.copy && !skip.includes(i.id));
    const conflicts = items.filter((i) => i.conflict);
    const total = items.reduce((n, i) => n + (i.size_kb || 0), 0);
    const summary = $("[data-migrate-summary]", form);
    if (summary) {
      summary.textContent = plan.problems.length || conflicts.length
        ? "Fix or untick what is marked before migrating."
        : `${plan.running ? "It is stopped while " : "Slipway copies "}about ${sizeText(total)} ${plan.running ? "is copied, then built and started on " + plan.target + "." : "to " + plan.target + ", then builds and starts it there."}`;
    }
    submit.disabled = Boolean(plan.problems.length || conflicts.length);
  }

  function renderMigratePlan(form, plan) {
    const box = $("[data-migrate-plan]", form);
    const kindText = { folder: "Settings", volume: "Volume", bind: "Path" };
    const rows = plan.items.map((i) => {
      const head = `<strong>${esc(kindText[i.kind] || i.kind)}</strong> <span class="mono" style="word-break: break-all">${esc(i.name)}</span>`;
      if (!i.copy) return `<div class="check" style="opacity: .7"><input type="checkbox" disabled><span>${head}<br><span class="subtle">${esc(i.note)}</span></span></div>`;
      const extra = i.conflict ? `<br><span style="color: var(--error)">${esc(i.conflict)}</span>` : (i.note ? `<br><span class="subtle">${esc(i.note)}</span>` : "");
      return `<label class="check"><input type="checkbox" data-migrate-item value="${esc(i.id)}" ${i.skipped ? "" : "checked"}><span>${head} <span class="subtle">· ${esc(sizeText(i.size_kb))}</span>${extra}</span></label>`;
    }).join("");
    const list = (items, cls) => items.length
      ? `<div class="callout ${cls}"><ul style="margin: 0; padding-left: 18px">${items.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></div>` : "";
    box.innerHTML =
      list(plan.problems, "error") +
      `<div class="subtle">From <span class="mono">${esc(plan.source_dir)}</span> on ${esc(plan.source)} to <span class="mono">${esc(plan.target_dir)}</span> on ${esc(plan.target)}. Ticked items are copied; an unticked one is left on ${esc(plan.source)}, and the new host's own is used.</div>` +
      `<div class="stack" style="gap: 8px">${rows}</div>` +
      list(plan.notes, "primary") +
      `<p class="lede" style="margin: 0" data-migrate-summary></p>`;
    box.hidden = false;
    form._plan = plan;
    migrateState(form);
  }

  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-migrate-check]");
    if (!btn) return;
    const form = btn.closest("form[data-migrate-form]");
    const host = $('[name="host_id"]', form).value;
    if (!host) return formError(form, "Choose the host to migrate to");
    formError(form, "");
    const body = { host_id: host, skip: [] };
    const dir = $('[name="deploy_dir"]', form).value.trim();
    if (dir) body.deploy_dir = dir;
    setLoading(btn, true);
    try {
      renderMigratePlan(form, await api("POST", form.dataset.migrateForm, body));
    } catch (err) {
      form._plan = null;
      migrateState(form);
      if (!formError(form, err.message)) toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  });

  document.addEventListener("change", (ev) => {
    const form = ev.target.closest("form[data-migrate-form]");
    if (!form) return;
    if (ev.target.matches("[data-migrate-item]")) return migrateState(form);
    if (ev.target.matches("[data-migrate-input]")) {
      form._plan = null;
      $("[data-migrate-plan]", form).hidden = true;
      const opt = $('[name="host_id"]', form).selectedOptions[0];
      if (opt && opt.dataset.root) $('[name="deploy_dir"]', form).placeholder = `${opt.dataset.root}/${form.dataset.slug || ""}`.replace(/\/$/, "/<instance>");
      migrateState(form);
    }
  });
  document.addEventListener("input", (ev) => {
    const form = ev.target.closest("form[data-migrate-form]");
    if (form && ev.target.matches('[name="deploy_dir"]') && form._plan) {
      form._plan = null;
      $("[data-migrate-plan]", form).hidden = true;
      migrateState(form);
    }
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

  // ------- conditional fields: data-show-when="field=value" (or value|value; several, space-separated, all hold)
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
    const allHold = (specs) => specs.split(/\s+/).filter(Boolean).every(holds);
    const update = () => {
      targets.forEach((el) => { el.hidden = !allHold(el.dataset.showWhen); });
      required.forEach((el) => { el.required = allHold(el.dataset.requiredWhen) && !el.closest("[hidden]"); });
      if (targets.length) syncRequired(form);
      checkMustEqual(form); // a typed field shown or hidden by this change counts, or no longer counts
    };
    form.addEventListener("change", update);
    update();
  }

  // ------------------------------------------------- new VMs (P5 §12.2, §12.4, §12.6 item 1)
  // A host select ([data-vm-host="<slot>"]) offers "New VM on <account>" (value vm:<account id>); its sub-form
  // ([data-vm-form="<slot>"]) shows while one is chosen, lists that account's networks and the pool's free
  // addresses (GET /provider-accounts/{id}/addresses), and vmSpec reads it as the body's ``machine``.
  const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const VM_SLOTS = ["blue", "green", "data"];
  // "4 vCPU · 8 GB · 64 GB" (pages._vm_size says the same).
  const vmSizeText = (size) => {
    const s = size || {}, parts = [];
    if (s.cores) parts.push(`${s.cores} vCPU`);
    if (s.memory_mb) parts.push(`${Math.round(Number(s.memory_mb) / 1024 * 100) / 100} GB`);
    if (s.disk_gb) parts.push(`${s.disk_gb} GB`);
    return parts.join(" · ");
  };
  const vmAccountOf = (sel) => { const v = (sel && sel.value) || ""; return v.indexOf("vm:") === 0 ? v.slice(3) : ""; };
  const vmFormOf = (scope, slot) => $(`[data-vm-form="${slot}"]`, scope);
  const vmField = (box, key) => $(`[data-vm="${key}"]`, box);

  // {account_id, network, address, cores?, memory_mb?, disk_gb?} for ``slot``'s new VM, or null for a host.
  // The address is the pool's pick (``auto`` until the free ones are read), or the typed one.
  function vmSpec(scope, slot) {
    const sel = $(`[data-vm-host="${slot}"]`, scope), account = vmAccountOf(sel), box = vmFormOf(scope, slot);
    if (!account || !box) return null;
    const from = ($('[data-vm="from"]:checked', box) || {}).value || "pool";
    const typed = String((vmField(box, "typed") || {}).value || "").trim();
    const picked = (vmField(box, "pick") || {}).value || "auto";
    const spec = { account_id: account, network: (vmField(box, "network") || {}).value || "", address: from === "typed" ? typed : picked };
    const num = (key) => { const el = vmField(box, key); return el && el.value !== "" && !isNaN(Number(el.value)) ? Number(el.value) : null; };
    if (num("cores") !== null) spec.cores = num("cores");
    if (num("memory_gb") !== null) spec.memory_mb = Math.round(num("memory_gb") * 1024);
    if (num("disk_gb") !== null) spec.disk_gb = num("disk_gb");
    return spec;
  }

  // The step's own checks of the new VMs in ``hosts`` ({slot: {machine}}): {field, text} or null.
  function vmProblem(hosts) {
    const given = {};
    for (const slot of VM_SLOTS) {
      const m = hosts[slot] && hosts[slot].machine;
      if (!m) continue;
      const base = `hosts.${slot}.machine`, who = slot === "data" ? "the data server" : slot;
      if (!m.network) return { field: `${base}.network`, text: `Choose a network for ${who}'s VM` };
      if (m.address !== "auto") {
        if (!m.address) return { field: `${base}.address`, text: `Type ${who}'s address, or pick one from the pool` };
        if (!IPV4.test(m.address)) return { field: `${base}.address`, text: `${m.address} isn't an IPv4 address, such as 10.0.0.12` };
        if (given[m.address]) return { field: `${base}.address`, text: `${m.address} is given to both ${given[m.address]} and ${slot}: give each VM its own address` };
        given[m.address] = slot;
      }
    }
    return null;
  }

  // Shows each sub-form while its select holds a new VM, keeps its networks to that account's (and, with
  // ``lock`` {slot, account, network}, every other slot to the lead VM's network) and reads the free addresses.
  function syncVmForms(scope, lock, loadNow) {
    $$("[data-vm-host]", scope).forEach((sel) => {
      const slot = sel.dataset.vmHost, box = vmFormOf(scope, slot);
      if (!box) return;
      const account = vmAccountOf(sel);
      box.hidden = !account || Boolean(sel.closest("[hidden]"));
      const net = vmField(box, "network");
      if (net) {
        $$("option", net).forEach((o) => {
          o.disabled = o.dataset.account !== account || Boolean(lock && lock.network && lock.slot !== slot && o.value !== lock.network);
        });
        const chosen = net.selectedOptions && net.selectedOptions[0];
        if (!chosen || chosen.disabled) {
          const first = $$("option", net).find((o) => !o.disabled);
          net.value = first ? first.value : "";
        }
      }
      if (account && !box.hidden && loadNow !== false) loadAddresses(scope, slot);
    });
  }

  async function loadAddresses(scope, slot) {
    const box = vmFormOf(scope, slot), account = vmAccountOf($(`[data-vm-host="${slot}"]`, scope));
    const network = (vmField(box, "network") || {}).value || "";
    if (!account || !network) return;
    const key = `${account}|${network}`;
    if (box.dataset.addresses === key) return;
    box.dataset.addresses = key;
    const cache = scope._vmAddresses = scope._vmAddresses || {};
    const url = `/api/v1/provider-accounts/${encodeURIComponent(account)}/addresses?network=${encodeURIComponent(network)}&count=10`;
    if (!cache[key]) cache[key] = api("GET", url).catch((err) => ({ error: err.message }));
    const data = await cache[key];
    if (box.dataset.addresses !== key) return; // the account or the network changed meanwhile
    fillAddresses(scope, box, data || {}, network);
  }

  // The pool's free addresses in the pick select; each VM of the form starts on one no other slot's pick holds.
  function fillAddresses(scope, box, data, network) {
    const pick = vmField(box, "pick"), help = $("[data-vm-taken]", box);
    const pool = $('[data-vm="from"][value="pool"]', box), typed = $('[data-vm="from"][value="typed"]', box);
    const say = (text) => { if (help) help.textContent = text; };
    if (data.error) { say(`Slipway couldn't read ${network}'s free addresses: ${data.error}. Type one, or Slipway takes the next free one.`); return; }
    const free = data.free || [];
    if (!data.pool || !free.length) {
      if (pick) fillOptions(pick, [], "");
      if (pool) { pool.disabled = true; pool.checked = false; }
      if (typed) { typed.checked = true; typed.dispatchEvent(new Event("change", { bubbles: true })); }
      say(data.pool ? `${network} has no free address left in its pool: type an address` : `${network} has no address pool: type an address`);
      return;
    }
    if (pool) pool.disabled = false;
    const others = $$("[data-vm-form]", scope).filter((b) => b !== box && !b.hidden && b.dataset.addresses === box.dataset.addresses)
      .map((b) => (vmField(b, "pick") || {}).value);
    const keep = pick && free.includes(pick.value) && !others.includes(pick.value) ? pick.value : (free.find((a) => !others.includes(a)) || free[0]);
    if (pick) fillOptions(pick, free, keep);
    const used = data.in_use || [];
    say(used.length ? `In use on ${network}: ${used.slice(0, 4).map((u) => `${u.address} (${u.by})`).join(", ")}` +
      (used.length > 4 ? `, and ${used.length - 4} more` : "") : `Nothing else on ${network} uses its pool yet.`);
  }

  // Add a slot (P5 §9.5): a New VM option sends {machine} instead of host_id.
  function vmSlotBody(form, body) {
    const sel = $("[data-vm-host]", form);
    if (!vmAccountOf(sel)) return;
    delete body.host_id;
    body.machine = vmSpec(form, sel.dataset.vmHost);
  }

  function wireVmForms(form) {
    if (!$("[data-vm-host]", form) || form.dataset.envFlow !== undefined) return; // the flow syncs its own
    form.addEventListener("change", () => syncVmForms(form, null));
    syncVmForms(form, null, false);
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
    // DigitalOcean placement (P4 §17.2): Where and Production are step 2's, the account and sizes step 3's, the
    // typed total the Review's.
    "placement.provider": 2, "placement.slots": 2, production: 2, placement: 3, confirm_cost: 7,
    // A new VM's fields (P5 §12.2): hosts.<slot>.machine.* (account_id, network, address, size) are step 3's,
    // through the "hosts" prefix; listed here so the map says so.
    "hosts.blue.machine": 3, "hosts.green.machine": 3, "hosts.data.machine": 3,
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
      const vm = vmSpec(root, slot); // a new VM: {machine: MachineSpecIn} (P5 §9.2)
      if (vm) hosts[slot] = { machine: vm };
      else if (chosen[slot]) hosts[slot] = chosen[slot];
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
    if (flowWhere(root) === "digitalocean") {
      // P4 §15.1: placement, production and the typed total; data_mode managed, traffic through the load balancer.
      const p = raw.placement || {};
      const production = flowProduction(root);
      body.data_mode = "managed";
      body.hosts = {};
      body.placement = { provider: "digitalocean", account_id: p.account_id || "", region: p.region || undefined,
                         droplet_size: p.droplet_size || "", db_size: p.db_size || "", db_standby: Boolean(p.db_standby),
                         acme_staging: !production && Boolean(p.acme_staging), slots: two ? 2 : 1 };
      body.production = production;
      body.traffic = { switch: "do_lb", dns: { proxied: Boolean(($('[name="do_proxied"]', root) || {}).checked) } };
      delete body.route_tls;
      if (production) body.auto_activate = false;
      const typed = ($("[data-flow-cost]", root) || {}).value;
      if (!planning && typed) body.confirm_cost = typed;
    }
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

  const flowWhere = (root) => (($('[name="where"]:checked', root) || {}).value) || "hosts";
  const flowProduction = (root) => flowWhere(root) === "digitalocean" && Boolean(($('[name="production"]', root) || {}).checked);

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
    const state = { current: 1, plan: null, manifest: null, unsure: false, created: null, name: "", busy: false,
                    cost: null, catalog: null, catalogAccount: null };
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
      gateDeploy();
    }

    // DigitalOcean: Deploy stays disabled until the total is typed as shown (P4 §12.2, §17.2).
    const costInput = $("[data-flow-cost]", root);
    const costOk = () => flowWhere(root) !== "digitalocean" ||
      Boolean(state.cost && costInput && costInput.value === String(state.cost.total));
    function gateDeploy() {
      if (deploy && !state.created && !state.busy) deploy.disabled = state.current === FLOW_STEPS && !costOk();
    }
    if (costInput) costInput.addEventListener("input", gateDeploy);

    // The step's own checks, before Slipway is asked: {field, text} or null.
    function clientCheck(n) {
      const body = flowBody(root, false, state.manifest);
      if (n === 1) {
        if (!NAME_RE.test(body.name || "")) return { field: "name", text: "Use 2-26 lowercase letters, digits and hyphens, starting with a letter and ending with a letter or digit" };
        if (!body.repository_id) return { field: "repository_id", text: "Choose a repository" };
        if (!body.branch) return { field: "branch", text: "Choose a branch" };
      }
      if (n === 3 && body.placement) {
        if (!body.placement.account_id) return { field: "placement.account_id", text: "Choose a DigitalOcean account" };
        if (!body.placement.droplet_size) return { field: "placement.droplet_size", text: "Choose a droplet size" };
        if (!body.placement.db_size) return { field: "placement.db_size", text: "Choose a database size" };
        return null;
      }
      if (n === 3) {
        if (!body.hosts.blue) return { field: "hosts.blue", text: "Choose a host for blue" };
        if ((($('[name="shape"]:checked', root) || {}).value) === "bluegreen" && !body.hosts.green) {
          return { field: "hosts.green", text: "Choose a host for green" };
        }
        if (body.data_mode === "server" && !body.hosts.data) return { field: "hosts.data", text: "Choose a host for the data server" };
        if (typeof body.hosts.data === "string" && (body.hosts.data === body.hosts.blue || body.hosts.data === body.hosts.green)) {
          return { field: "hosts.data", text: "The data server needs a host of its own" };
        }
        return vmProblem(body.hosts);
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
      const checked = flowBody(root, n < 6, state.manifest);
      delete checked.confirm_cost; // a check writes nothing and confirms nothing
      const res = await request("POST", "/api/v1/environments?check=true", checked);
      state.busy = false; if (next) setLoading(next, false);
      if (res.status === 200) {
        state.plan = (res.data && res.data.plan) || null;
        state.cost = (res.data && res.data.cost) || null;
        go(n + 1);
        return;
      }
      // Whatever the check refused, the estimate it would have answered isn't known: Review never shows an
      // older total (nor accepts it typed).
      state.cost = null;
      const field = refusalField(res), at = fieldStep(field);
      const refusal = res.status >= 400 && res.status < 500;
      // A later step's field is fine for now: that step's input isn't given yet. Review has no input a check
      // sends (the typed total never is), so a refusal naming it (the account's monthly limit, confirm_cost) is
      // about what is chosen so far: it is shown here.
      if (refusal && at > n && at < FLOW_STEPS) { go(n + 1); return; }
      if (refusal && at && at <= n) {
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

    // The estimate again, after a create said it moved (409): the new total must be typed.
    // Answers the check's refusal text when it couldn't price it (state.cost is then cleared, as nextStep does).
    async function reprice() {
      if (costInput) costInput.value = "";
      const checked = flowBody(root, false, state.manifest);
      delete checked.confirm_cost;
      const res = await request("POST", "/api/v1/environments?check=true", checked);
      let failed = "";
      if (res.status === 200) { state.cost = (res.data && res.data.cost) || null; state.plan = (res.data && res.data.plan) || state.plan; }
      else { state.cost = null; failed = res.text; }
      fillReview();
      return failed;
    }

    async function deployAll() {
      if (state.busy) return;
      if (!state.created && !costOk()) { gateDeploy(); return; }
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
            if (field === "confirm_cost" && res.status === 409) {
              const failed = await reprice();
              stepError(FLOW_STEPS, failed || res.text); mark(field); return;
            }
            stepError(FLOW_STEPS, res.text);
            mark(field);
            return;
          }
        }
        await startFirst();
      } finally {
        state.busy = false; if (deploy) setLoading(deploy, false);
        if (state.created && deploy) deploy.disabled = false;
        gateDeploy();
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
      const onDo = flowWhere(root) === "digitalocean";
      const production = flowProduction(root);
      // Production runs Blue and Green and waits for Activate (P4 §13).
      const single = $('[name="shape"][value="single"]', root), bg = $('[name="shape"][value="bluegreen"]', root);
      if (single) single.disabled = production;
      if (production && bg && !bg.disabled) { bg.checked = true; if (single) single.checked = false; }
      const auto = $('[name="auto_activate"]', root);
      if (auto) { auto.disabled = production; if (production) auto.checked = false; }
      const staging = $("[data-do-staging]", root);
      if (staging) { staging.hidden = production; if (production) $("input", staging).checked = false; }
      // A production environment needs a production account, and only it may use one.
      const account = $("[data-do-account]", root);
      if (account) {
        $$("option", account).forEach((o) => {
          const off = o.dataset.unusable !== undefined || (production ? o.dataset.production === undefined : o.dataset.production !== undefined);
          o.disabled = off;
        });
        const chosen = account.selectedOptions && account.selectedOptions[0];
        if (!chosen || chosen.disabled) {
          const first = $$("option", account).find((o) => !o.disabled);
          account.value = first ? first.value : "";
        }
      }
      const label = onDo ? "DigitalOcean" : "Hosts";
      if (sections[2]) sections[2].dataset.stepName = label;
      const tab = tabs.find((t) => t.dataset.stepTab === "3"), tabLabel = tab && $("[data-step-label]", tab);
      if (tabLabel) tabLabel.textContent = label;
      // The settings the load balancer sets (edge.env) aren't asked for on DigitalOcean (P4 §5).
      const edge = (state.manifest && state.manifest.edge && state.manifest.edge.env) || [];
      $$("[data-app-setting]", root).forEach((i) => {
        const field = i.closest(".field");
        if (field) field.hidden = onDo && edge.includes(i.dataset.appSetting);
      });
      const shapeEl = $('[name="shape"]:checked', root);
      const two = Boolean(shapeEl && shapeEl.value === "bluegreen");
      const keep = $('[name="keep_data"]', root);
      const mode = onDo ? "managed" : two || (keep && keep.checked && !keep.closest("[hidden]")) ? "server" : "slot";
      if (modeInput) modeInput.value = mode;
      const pick = (slot) => { const el = $(`[data-host-select="${slot}"]`, root); return el ? el.value : ""; };
      const blue = pick("blue"), green = two ? pick("green") : "";
      $$("[data-host-select]", root).forEach((sel) => {
        const slot = sel.dataset.hostSelect;
        $$("option", sel).forEach((o) => {
          if (!o.value || o.dataset.unpinned !== undefined || o.dataset.vmAccount !== undefined) return;
          let off = "";
          if (mode === "server" && slot !== "data" && !o.dataset.ip) off = "Its address must be an IP for the data server to let it in";
          if (slot === "data" && (o.value === blue || o.value === green)) off = "The data server needs a host of its own";
          o.disabled = Boolean(off);
          o.textContent = (o.dataset.label || o.textContent) + (off ? `: ${off}` : "");
        });
      });
      const same = $("[data-same-host]", root);
      if (same) same.hidden = !(two && blue && blue === green && !vmAccountOf({ value: blue }));
      syncVms(two, mode);
      const none = $('[name="traffic.switch"][value="none"]', root), sy = $('[name="traffic.switch"][value="switchyard"]', root);
      if (none) {
        none.disabled = two;
        if (two && none.checked && sy && !sy.disabled) sy.checked = true;
      }
      const slots = $("[data-name-slots]", root), name = ($('[name="name"]', root) || {}).value || "<name>";
      if (slots) slots.textContent = `${name}-blue, ${name}-green and ${name}-data`;
    }

    // New VMs (P5 §12.2): once one slot is a new VM, every other slot's New VM options are limited to its
    // account, and its network to the lead VM's (an environment's VMs share one account and one network).
    function syncVms(two, mode) {
      const used = VM_SLOTS.filter((slot) => slot === "blue" || (slot === "green" && two) || (slot === "data" && mode === "server"));
      const name = ($('[name="name"]', root) || {}).value || "<name>";
      $$("[data-vm-env]", root).forEach((el) => { el.textContent = name; });
      const leadSlot = used.find((slot) => vmAccountOf($(`[data-vm-host="${slot}"]`, root)));
      const lead = leadSlot ? { slot: leadSlot, account: vmAccountOf($(`[data-vm-host="${leadSlot}"]`, root)) } : null;
      $$("[data-vm-host]", root).forEach((sel) => {
        $$("option[data-vm-account]", sel).forEach((o) => {
          if (o.dataset.vmOff !== undefined) return; // off for good (a permission, an account that can't be used)
          const off = Boolean(lead && lead.slot !== sel.dataset.vmHost && o.dataset.vmAccount !== lead.account);
          o.disabled = off;
          o.textContent = (o.dataset.label || o.textContent) + (off ? `: ${name}'s VMs share one account and one network` : "");
        });
        const chosen = sel.selectedOptions && sel.selectedOptions[0];
        if (chosen && chosen.disabled && chosen.dataset.vmAccount !== undefined) sel.value = "";
      });
      syncVmForms(root, null, false); // each sub-form on its own account's networks first
      if (lead) lead.network = (vmField(vmFormOf(root, lead.slot), "network") || {}).value || "";
      syncVmForms(root, lead);
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
      // DigitalOcean needs slipway.yml's data.managed and edge (P4 §15.1 refusal 3).
      const doRadio = $('[name="where"][value="digitalocean"]', root), doReason = $("[data-do-reason]", root);
      if (doRadio) {
        if (doRadio.dataset.off === undefined) doRadio.dataset.off = doRadio.disabled ? "1" : "";
        const missing = Boolean(m) && !caps.includes("digitalocean");
        doRadio.disabled = doRadio.dataset.off === "1" || missing;
        if (doReason && doRadio.dataset.off !== "1") {
          const branch = ($('[name="branch"]', root) || {}).value || "";
          doReason.textContent = missing ? `${path}${branch ? " on " + branch : ""} doesn't say how it runs on managed data behind a load balancer (data.managed and edge)` : "";
        }
        if (doRadio.disabled && doRadio.checked) { const hosts = $('[name="where"][value="hosts"]', root); if (hosts) hosts.checked = true; root.dispatchEvent(new Event("change")); }
      }
      syncChoices();
    });

    // The account's catalog (GET /provider-accounts/{id}/catalog): the regions with Spaces, the droplet sizes with
    // their prices and the database sizes for the node count. Read when DigitalOcean is chosen, the account or
    // the region changes.
    let catalogSeq = 0;
    const doStatus = (html) => { const el = $("[data-do-catalog-status]", root); if (el) el.innerHTML = html || ""; };
    function fillDb() {
      const db = $("[data-do-db]", root), standby = $("[data-do-standby]", root);
      if (!db || !state.catalog) return;
      const nodes = standby && standby.checked ? "2" : "1";
      db.dataset.placeholder = "Choose a size";
      fillOptions(db, (state.catalog.db_sizes || {})[nodes] || [], db.value);
    }
    async function loadCatalog(regionChosen) {
      const account = $("[data-do-account]", root), region = $("[data-do-region]", root), droplet = $("[data-do-droplet]", root);
      if (!account || !account.value || flowWhere(root) !== "digitalocean") return;
      const opt = account.selectedOptions && account.selectedOptions[0];
      const same = state.catalogAccount === account.value;
      const want = (regionChosen || same) && region && region.value ? region.value : (opt && opt.dataset.region) || "";
      const mine = ++catalogSeq;
      doStatus(`<p class="muted" style="margin: 0">Reading ${esc((opt && opt.dataset.label) || "the account")}'s sizes and prices…</p>`);
      const res = await request("GET", `/api/v1/provider-accounts/${encodeURIComponent(account.value)}/catalog${want ? "?region=" + encodeURIComponent(want) : ""}`);
      if (mine !== catalogSeq) return;
      if (res.status !== 200 || !res.data) { doStatus(`<div class="callout error">${esc(res.text)}</div>`); return; }
      state.catalog = res.data; state.catalogAccount = account.value;
      doStatus("");
      if (region) {
        region.dataset.placeholder = "Choose a region";
        const regions = (res.data.regions || []).filter((r) => r.available && r.spaces)
          .map((r) => ({ value: r.slug, label: r.name ? `${r.slug} · ${r.name}` : r.slug }));
        fillOptions(region, regions, res.data.region);
      }
      if (droplet) { droplet.dataset.placeholder = "Choose a size"; fillOptions(droplet, dropletOptions(res.data), droplet.value); }
      fillDb();
    }
    const is = (el, sel) => Boolean(el && el.closest && el.closest(sel) === el);
    root.addEventListener("change", (ev) => {
      const t = ev.target;
      if (is(t, '[name="where"]') || is(t, "[data-do-account]") || is(t, '[name="production"]')) loadCatalog(false);
      else if (is(t, "[data-do-region]")) loadCatalog(true);
      else if (is(t, "[data-do-standby]")) fillDb();
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
      if (flowWhere(root) === "digitalocean") {
        body.innerHTML = plan.hostnames.map((h) => `<tr><td class="mono">${esc(h.hostname)}</td><td>DigitalOcean load balancer</td>` +
          `<td>The live slot's droplet</td><td class="subtle">The load balancer's certificate</td></tr>`).join("");
        return;
      }
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
      const p = body.placement;
      const rows = [
        ["Name", body.name], ["Repository", text('[name="repository_id"]')], ["Branch", body.branch],
        ["Manifest", body.manifest_file || "slipway.yml"],
        ["Shape", p ? (two ? "Blue/Green, on managed data" : "Single slot, on managed data")
          : two ? "Blue/Green, with a data server" : body.data_mode === "server" ? "Single slot, with a data server" : "Single slot"],
      ];
      if (p) {
        rows.push(["Where", `DigitalOcean: ${text("[data-do-account]")}${p.region ? ", " + p.region : ""}`]);
        if (body.production) rows.push(["Production", "Yes: it waits for Activate, and is deleted only after it is retired and snapshotted"]);
        rows.push(["Droplets", `${two ? 2 : 1} × ${text("[data-do-droplet]")}`]);
        rows.push(["Database", `${p.db_size}${p.db_standby ? ", with a standby node" : ", one node"}`]);
        rows.push(["Certificate", p.acme_staging ? "Let's Encrypt staging (not trusted by browsers)" : "Let's Encrypt"]);
      } else {
        // A new VM is listed as the last check planned it (plan.machines, P5 §9.2): name, account, address, size.
        const planned = {};
        ((state.plan && state.plan.machines) || []).forEach((m) => { planned[m.slot] = m; });
        const host = (slot) => {
          const m = body.hosts[slot] && body.hosts[slot].machine;
          if (!m) return text(`[data-host-select="${slot}"]`);
          const p = planned[slot] || {};
          const account = p.account || text(`[data-host-select="${slot}"]`).replace(/^New VM on /, "");
          const address = p.address || (m.address === "auto" ? "the next free address" : m.address);
          return `New VM ${p.name || `slipway-${body.name || "<name>"}-${slot}`} on ${account}, at ${address} on ${p.network || m.network}, ` +
            vmSizeText(p.size || { cores: m.cores, memory_mb: m.memory_mb, disk_gb: m.disk_gb });
        };
        rows.push(["Blue", host("blue")]);
        if (body.hosts.green) rows.push(["Green", host("green")]);
        if (body.hosts.data) rows.push(["Data server", host("data")]);
      }
      rows.push(["Settings", Object.keys(body.settings || {}).map((k) => `${k}=${body.settings[k]}`).join(", ") || "None set"]);
      if (body.services) rows.push(["Optional services", body.services.join(", ") || "None"]);
      rows.push(["Variables", Object.keys(body.env || {}).join(", ") || "None"]);
      if (p) {
        rows.push(["Switch", "DigitalOcean load balancer"]);
        rows.push(["DNS", `Cloudflare, at the load balancer's address${body.traffic.dns.proxied ? ", proxied" : ""}`]);
      } else {
        rows.push(["Switch", body.traffic.switch === "switchyard" ? `Switchyard${ds.trafficAddress ? ` (${ds.trafficAddress})` : ""}` : "None"]);
        rows.push(["DNS", body.traffic.dns ? `Cloudflare, at ${body.traffic.dns.address || "the integration's public IP"}${body.traffic.dns.proxied ? ", proxied" : ""}` : "Not published"]);
      }
      if (two) rows.push(["Activate", body.auto_activate ? "Automatically when the smoke test passes" : "When you choose Activate"]);
      const names = ((state.plan && state.plan.hostnames) || []).map((h) => h.hostname);
      rows.push(["Public names", names.join(", ") || "None"]);
      const fa = body.first_admin;
      rows.push(["Data", body.seed_snapshot_id ? "From a snapshot" : "Start empty"]);
      if (fa) rows.push(["First admin", (fa.fields && (fa.fields.email || Object.values(fa.fields)[0])) || "Set"]);
      if (body.keep_backups) rows.push(["Backups to keep", String(body.keep_backups)]);
      dl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v || "—")}</dd>`).join("");
      const table = $("[data-cost-table]", root);
      if (table && p) {
        if (state.cost) renderers.cost(table, state.cost);
        else table.innerHTML = '<p class="muted" style="margin: 0">Slipway couldn\'t price the environment yet: go back and check each step.</p>';
      }
      gateDeploy();
    }

    root.addEventListener("change", syncChoices);
    root.addEventListener("input", (ev) => { if (ev.target && ev.target.name === "name") syncChoices(); });
    root.addEventListener("slipway:manifest", () => syncChoices());
    // Enter in a field would submit the form natively: it moves to the next step instead.
    root.addEventListener("submit", (ev) => { ev.preventDefault(); if (state.current < FLOW_STEPS) nextStep(); else deployAll(); });
    if (next) next.addEventListener("click", (ev) => { ev.preventDefault(); nextStep(); });
    if (back) back.addEventListener("click", (ev) => { ev.preventDefault(); if (!state.created) { clearMarks(); go(state.current - 1); } });
    if (deploy) deploy.addEventListener("click", (ev) => { ev.preventDefault(); deployAll(); });
    if (restart) restart.addEventListener("click", (ev) => {
      ev.preventDefault();
      if (state.created || !confirm("Start over? Every choice on this page is cleared.")) return;
      if (root.reset) root.reset();
      state.plan = null; state.unsure = false; state.cost = null;
      clearMarks(); say(""); sections.forEach((_, i) => stepError(i + 1, ""));
      root.dispatchEvent(new Event("change"));
      go(1);
    });
    syncChoices();
    go(1);
  }

  // ------------------------------------------- provider accounts (P4 §17.1, P5 §12.1, §12.6 item 3)
  // _account_dialogs.html holds one dialog per provider, <form data-account-form="digitalocean|proxmox|esxi">.
  //   <button data-account-open="<provider>" data-account='{...}'>   Add, or Edit filled from the account (no secret)
  //   <button data-account-trust="<id>" data-provider data-where>     trust the certificate an account presents now
  // wireAccountForm builds the body (the networks table rows, SSH sources, the limit in dollars), saves through
  // /api/v1/provider-accounts, shows Test's checks, and on a 409 tls_untrusted opens "Trust this certificate?"
  // and saves again with trust_fingerprint.
  const ACCOUNT_NAMES = { digitalocean: "DigitalOcean", proxmox: "Proxmox", esxi: "VMware ESXi" };
  const CHECK_BADGE = { ok: ["OK", "success"], note: ["Note", "plain"], warning: ["Warning", "warning"], error: ["Failed", "error"] };
  const TEST_STATUS = { unknown: "Not tested", ok: "Every check passed.", warning: "It works, with warnings.", error: "A check failed." };
  // No certificate has this fingerprint: a save or trust sent with it is refused with the certificate the
  // account's address presents now, for the person to compare (nothing is written).
  const PROBE_FINGERPRINT = Array(32).fill("00").join(":");
  const NET_FIELDS = {
    proxmox: [["name", "Name", "lan"], ["bridge", "Bridge", "vmbr0"], ["vlan_tag", "VLAN", "none"],
      ["subnet", "Subnet", "10.0.0.0/24"], ["gateway", "Gateway", "10.0.0.1"], ["dns_servers", "DNS servers", "the gateway"],
      ["pool_first", "Pool from", "10.0.0.100"], ["pool_last", "Pool to", "10.0.0.150"]],
    esxi: [["name", "Name", "lan"], ["port_group", "Port group", "VM Network"],
      ["subnet", "Subnet", "10.0.0.0/24"], ["gateway", "Gateway", "10.0.0.1"], ["dns_servers", "DNS servers", "the gateway"],
      ["pool_first", "Pool from", "10.0.0.100"], ["pool_last", "Pool to", "10.0.0.150"]],
  };
  const ACCOUNT_KEYS = ["url", "node", "pool", "storage", "template_vmid", "user", "datastore", "resource_pool", "source_vm"];

  const listOf = (text) => String(text || "").split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);

  // A value as text for "did it change": object keys sorted, and an object's null, empty-text and empty-list
  // members left out (a stored network may lack keys the table sends as null).
  function canon(v) {
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    if (v && typeof v === "object") {
      return "{" + Object.keys(v).sort().filter((k) => {
        const x = v[k];
        return !(x === null || x === undefined || x === "" || (Array.isArray(x) && !x.length));
      }).map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
    }
    return JSON.stringify(v === undefined ? null : v);
  }

  function fieldValue(form, name) {
    const el = $(`[name="${name}"]`, form);
    return el ? String(el.value || "").trim() : "";
  }

  // One row of the Networks table, with the columns of the form's provider (Proxmox: bridge and VLAN; ESXi:
  // port group), filled from ``net`` (an account's network) when given.
  function networkRow(form, net) {
    const row = document.createElement("div");
    row.className = "net-row";
    row.setAttribute("data-network-row", "");
    (NET_FIELDS[form.dataset.provider] || []).forEach(([key, label, hint]) => {
      const input = document.createElement("input");
      input.className = "input mono";
      input.setAttribute("data-net", key);
      input.setAttribute("aria-label", label);
      input.setAttribute("placeholder", hint);
      input.setAttribute("autocomplete", "off");
      let v = "";
      if (net) {
        if (key === "pool_first" || key === "pool_last") v = net.pool ? net.pool[key === "pool_first" ? "first" : "last"] : "";
        else if (key === "dns_servers") v = (net.dns_servers || []).join(", ");
        else v = net[key];
      }
      input.value = v === null || v === undefined ? "" : String(v);
      row.appendChild(input);
    });
    const remove = document.createElement("button");
    remove.className = "btn btn-sm";
    remove.setAttribute("type", "button");
    remove.setAttribute("data-network-remove", "");
    remove.setAttribute("title", "Remove this network");
    remove.textContent = "Remove";
    row.appendChild(remove);
    $("[data-network-rows]", form).appendChild(row);
    return row;
  }

  // The rows as the API's networks: every row with something typed in it, in the table's order.
  function networksBody(form) {
    const proxmox = form.dataset.provider === "proxmox";
    return $$("[data-network-row]", form).map((row) => {
      const v = (key) => { const el = $(`[data-net="${key}"]`, row); return el ? String(el.value || "").trim() : ""; };
      const typed = (NET_FIELDS[form.dataset.provider] || []).some(([key]) => v(key));
      if (!typed) return null;
      const net = { name: v("name") };
      if (proxmox) {
        net.bridge = v("bridge");
        const tag = v("vlan_tag");
        net.vlan_tag = tag === "" ? null : /^\d+$/.test(tag) ? Number(tag) : tag;
      } else {
        net.port_group = v("port_group");
      }
      Object.assign(net, { subnet: v("subnet"), gateway: v("gateway"), dns_servers: listOf(v("dns_servers")) });
      const first = v("pool_first"), last = v("pool_last");
      net.pool = first || last ? { first, last } : null;
      return net;
    }).filter(Boolean);
  }

  // The body of a save. On an edit only what differs from the account as it was opened is sent, so an untouched
  // field (SSH sources, networks) is never checked again.
  function accountBody(form) {
    const provider = form.dataset.provider;
    const account = form._account || null;
    const body = { name: fieldValue(form, "name") };
    const secret = ($('[name="secret"]', form) || {}).value || "";
    if (provider === "digitalocean") {
      body.region = fieldValue(form, "region");
      body.production = Boolean(($('[name="production"]', form) || {}).checked);
      body.ssh_sources = listOf(fieldValue(form, "ssh_sources"));
      const limit = fieldValue(form, "monthly_limit");
      if (limit !== "" && !(Number(limit) > 0)) throw new Error("The monthly limit is a number of US dollars, such as 150");
      body.monthly_limit_cents = limit === "" ? null : Math.round(Number(limit) * 100);
      const prices = fieldValue(form, "prices");
      try { body.prices = prices ? JSON.parse(prices) : null; } catch (e) { throw new Error("The price overrides aren't valid JSON"); }
    } else {
      ACCOUNT_KEYS.forEach((key) => { if ($(`[name="${key}"]`, form)) body[key] = fieldValue(form, key); });
      if ("template_vmid" in body && /^\d+$/.test(body.template_vmid)) body.template_vmid = Number(body.template_vmid);
      if (provider === "esxi" && body.resource_pool === "") body.resource_pool = account ? account.resource_pool : null;
      body.networks = networksBody(form);
    }
    if (!account) {
      Object.keys(body).forEach((k) => { if (body[k] === null || body[k] === "") delete body[k]; });
      body.provider = provider;
    } else {
      Object.keys(body).forEach((k) => {
        if (canon(body[k]) === canon(account[k] === undefined ? null : account[k])) delete body[k];
      });
      const clear = $('[name="clear_secret"]', form);
      if (clear && clear.checked && !secret) body.clear_secret = true;
    }
    if (secret) body.secret = secret;
    return body;
  }

  // An edit that moves a Proxmox or ESXi account to another address (or ESXi user) forgets its pinned
  // certificate, so it is saved together with trusting the new one.
  function movesAddress(form, body) {
    return Boolean(form._account) && form.dataset.provider !== "digitalocean" && ("url" in body || "user" in body);
  }

  function openTrust(pending) {
    const dlg = $("#account-trust");
    if (!dlg) return toast("Reload the page to trust this certificate", "error");
    const c = pending.certificate || {};
    dlg._trust = pending;
    fill(dlg, {
      where: pending.where || "The server", note: pending.note || "", fingerprint_sha256: c.fingerprint_sha256,
      subject: c.subject || "", issuer: c.issuer || "", not_after: String(c.not_after || "").replace("T", " ").slice(0, 16),
      sans: (c.sans || []).join(", ") || "None",
    });
    $$("[data-trust-hint]", dlg).forEach((el) => { el.hidden = el.dataset.trustHint !== pending.provider; });
    openDialog(dlg);
  }

  function trustRefusal(err) {
    const d = err && err.data;
    return d && d.certificate && (d.code === "tls_untrusted" || d.code === "tls_mismatch") ? d.certificate : null;
  }

  async function saveAccount(form, extra) {
    const id = form.dataset.accountId;
    let body;
    try { body = accountBody(form); } catch (err) { if (!formError(form, err.message)) toast(err.message, "error"); return; }
    if (!extra && movesAddress(form, body)) extra = { trust_fingerprint: PROBE_FINGERPRINT };
    Object.assign(body, extra || {});
    const submit = $('[type="submit"]', form);
    setLoading(submit, true);
    formError(form, "");
    try {
      await api(id ? "PATCH" : "POST", "/api/v1/provider-accounts" + (id ? "/" + id : ""), body);
      flashAfterReload(id ? "Account saved" : "Account added");
      location.reload();
    } catch (err) {
      const cert = trustRefusal(err);
      if (cert) {
        const real = body.trust_fingerprint && body.trust_fingerprint !== PROBE_FINGERPRINT;
        openTrust({ form, certificate: cert, provider: form.dataset.provider,
          where: body.url || (form._account && form._account.url) || fieldValue(form, "name"),
          note: real ? err.message : "" });
      } else if (!formError(form, err.message)) {
        toast(err.message, "error");
      }
    } finally {
      setLoading(submit, false);
    }
  }

  async function trustAccount(btn, id, fingerprint, pending) {
    setLoading(btn, true);
    try {
      await api("POST", `/api/v1/provider-accounts/${id}/trust`, { fingerprint });
      flashAfterReload("Certificate trusted");
      location.reload();
    } catch (err) {
      const cert = trustRefusal(err);
      if (cert) openTrust(Object.assign({}, pending, { id, certificate: cert, note: fingerprint === PROBE_FINGERPRINT ? "" : err.message }));
      else toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  }

  function showChecks(form, answer) {
    const box = $("[data-account-test-result]", form);
    if (!box) return;
    const list = $("[data-account-checks]", box);
    list.textContent = "";
    (answer.checks || []).forEach((c) => {
      const [label, cls] = CHECK_BADGE[c.level] || [String(c.level || ""), ""];
      const li = document.createElement("li");
      const chip = document.createElement("span");
      chip.className = "badge " + cls;
      chip.textContent = label;
      const text = document.createElement("span");
      text.textContent = c.text || c.name || "";
      li.appendChild(chip);
      li.appendChild(text);
      list.appendChild(li);
    });
    $("[data-account-test-status]", box).textContent = TEST_STATUS[answer.status] || String(answer.status || "");
    box.hidden = false;
  }

  // Test: an unsaved DigitalOcean token is tested as typed (with the region chosen); otherwise the saved account.
  async function testAccount(form, btn) {
    const id = form.dataset.accountId;
    const secret = ($('[name="secret"]', form) || {}).value || "";
    let call = null;
    if (form.dataset.provider === "digitalocean" && secret) {
      const region = fieldValue(form, "region");
      call = ["POST", "/api/v1/provider-accounts/test", region ? { secret, region } : { secret }];
    } else if (id) {
      call = ["POST", `/api/v1/provider-accounts/${id}/test`, undefined];
    }
    if (!call) {
      const text = "Paste the API token to test it";
      if (!formError(form, text)) toast(text, "error");
      return;
    }
    setLoading(btn, true);
    formError(form, "");
    try {
      showChecks(form, await api(call[0], call[1], call[2]) || {});
    } catch (err) {
      if (!formError(form, err.message)) toast(err.message, "error");
    } finally {
      setLoading(btn, false);
    }
  }

  function ensureOption(select, value) {
    if (!select || !value || $$("option", select).some((o) => o.value === value)) return;
    const option = document.createElement("option");
    option.setAttribute("value", value);
    option.textContent = value;
    select.appendChild(option);
  }

  // Opens the provider's dialog to add an account, or to edit ``account`` (a ProviderAccountOut without secrets).
  function openAccount(provider, account) {
    const dlg = document.getElementById(`account-${provider}`);
    if (!dlg) return;
    const form = $("form[data-account-form]", dlg);
    const a = account || null;
    form.dataset.accountId = a ? a.id : "";
    form._account = a;
    const set = (name, v) => $$(`[name="${name}"]`, form).forEach((el) => {
      if (el.type === "checkbox") el.checked = Boolean(v);
      else el.value = v === null || v === undefined ? "" : String(v);
    });
    fill(dlg, { account_title: a ? `Edit ${a.name}` : `Add a ${ACCOUNT_NAMES[provider] || provider} account` });
    set("name", a ? a.name : "");
    set("secret", "");
    const secret = $('[name="secret"]', form);
    if (secret) {
      secret.required = !a && provider !== "digitalocean";
      const hint = a && a.secret_hint && a.secret_hint !== "set" ? ` (…${a.secret_hint})` : "";
      secret.setAttribute("placeholder", a && a.has_secret ? `Set${hint}; leave it empty to keep it` : (provider === "digitalocean" ? "dop_v1_…" : ""));
    }
    const state = $("[data-secret-state]", form);
    if (state) state.textContent = a && a.has_secret ? `Set${a.secret_hint && a.secret_hint !== "set" ? ` (…${a.secret_hint})` : ""}. ` : "";
    if (provider === "digitalocean") {
      const region = (a && a.region) || "nyc3";
      ensureOption($('[name="region"]', form), region);
      set("region", region);
      set("production", a && a.production);
      set("ssh_sources", a ? (a.ssh_sources || []).join("\n") : "");
      set("monthly_limit", a ? a.monthly_limit : "");
      set("prices", a && a.prices ? JSON.stringify(a.prices, null, 2) : "");
      set("clear_secret", false);
      $$("[data-clear-secret]", form).forEach((el) => { el.hidden = !(a && a.has_secret); });
    } else {
      ACCOUNT_KEYS.forEach((key) => set(key, a ? a[key] : ""));
      const rows = $("[data-network-rows]", form);
      if (rows) {
        rows.textContent = "";
        const nets = (a && a.networks) || [];
        (nets.length ? nets : [null]).forEach((net) => networkRow(form, net));
      }
    }
    $$("[data-saved-only]", form).forEach((el) => { el.hidden = !a; });
    $$("[data-account-test-result]", form).forEach((el) => { el.hidden = true; });
    openDialog(dlg);
  }

  function wireAccountForm(form) {
    if (form._wired) return;
    form._wired = true;
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      saveAccount(form);
    });
    form.addEventListener("click", (ev) => {
      if (ev.target.closest("[data-network-add]")) {
        ev.preventDefault();
        const first = $("input", networkRow(form, null));
        if (first) first.focus();
        return;
      }
      const remove = ev.target.closest("[data-network-remove]");
      if (remove) {
        ev.preventDefault();
        remove.closest("[data-network-row]").remove();
        return;
      }
      const test = ev.target.closest("[data-account-test]");
      if (test) {
        ev.preventDefault();
        testAccount(form, test);
      }
    });
  }

  document.addEventListener("click", (ev) => {
    const opener = ev.target.closest("[data-account-open]");
    if (opener) {
      ev.preventDefault();
      let account = null;
      try { account = opener.dataset.account ? JSON.parse(opener.dataset.account) : null; } catch (e) { account = null; }
      openAccount(opener.dataset.accountOpen, account);
      return;
    }
    const trust = ev.target.closest("[data-account-trust]");
    if (trust) {
      ev.preventDefault();
      trustAccount(trust, trust.dataset.accountTrust, PROBE_FINGERPRINT,
        { provider: trust.dataset.provider, where: trust.dataset.where, button: trust });
    }
  });

  // "Trust this certificate?": saves the account again with the fingerprint shown, or trusts it on the account.
  document.addEventListener("submit", (ev) => {
    const form = ev.target.closest("form[data-trust-form]");
    if (!form) return;
    ev.preventDefault();
    const dlg = form.closest("dialog");
    const pending = dlg && dlg._trust;
    if (!pending) return;
    dlg._trust = null;
    dlg.close();
    const fingerprint = pending.certificate.fingerprint_sha256;
    if (pending.form) saveAccount(pending.form, { trust_fingerprint: fingerprint });
    else trustAccount(pending.button || $("[data-trust-confirm]", form), pending.id, fingerprint, pending);
  });

  // ------------------------------------------------------ Slipway updates
  // Every value here came from git or the server (branch names, subjects, authors, messages, the log), so it is
  // only ever set with textContent, .value or a checked href; never with innerHTML.
  const RUN_ID = /^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$/;
  const SHA = /^[0-9a-f]{40}$/;
  const COMPARE = /^https:\/\/github\.com\/[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}\/compare\/[0-9a-f]{40}\.\.\.[0-9a-f]{40}$/;
  const ANSI = /\x1b\[[0-?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;
  const RUN_STATUS = {
    running: ["Running", "warning spin"], succeeded: ["Upgraded", "success"], failed: ["Failed", "error"],
    rolled_back: ["Rolled back", "warning"], rollback_failed: ["Rollback failed", "error"],
    interrupted: ["Interrupted", "error"], unknown: ["Unknown", ""],
  };
  const RUN_FINAL = ["succeeded", "failed", "rolled_back", "rollback_failed", "interrupted"];
  const RUN_DONE_TEXT = {
    succeeded: "Slipway was upgraded. Reload to use the new version.",
    rolled_back: "The new version didn't start, so Slipway rolled back to the old one.",
    rollback_failed: "The roll back failed. Follow the by-hand steps in docs/updates.md.",
    failed: "The upgrade failed before anything changed.",
    interrupted: "The upgrade stopped before it finished. Check docs/updates.md.",
  };
  const RESTART_LIMIT = 10 * 60 * 1000; // how long to keep polling while Slipway can't be reached
  const POLL_MS = 2000;

  function openUpgrade(btn) {
    const dlg = $("#update-confirm");
    const form = dlg && $("form", dlg);
    const d = btn.dataset;
    if (!form || !SHA.test(d.sha || "")) return;
    const text = (key, value) => $$(`[data-confirm-text="${key}"]`, dlg).forEach((n) => { n.textContent = value || ""; });
    const show = (key, on) => $$(`[data-confirm-show="${key}"]`, dlg).forEach((n) => { n.hidden = !on; });
    ["branch", "sha", "short", "author", "subject", "migrations", "privileged"].forEach((k) => text(k, d[k]));
    const n = Number(d.migrations) || 0;
    text("migrations-count", n === 1 ? "1 migration" : `${n} migrations`);
    show("other", !d.followed);
    show("migrations", Number(d.migrations) > 0);
    show("privileged", Boolean(d.privileged));
    const link = $('[data-confirm-link="compare"]', dlg);
    if (link) {
      const ok = COMPARE.test(d.compare || "");
      if (ok) link.setAttribute("href", d.compare);
      link.hidden = !ok;
    }
    $('[name="branch"]', form).value = d.branch || "";
    $('[name="sha"]', form).value = d.sha;
    $$("[data-form-error]", dlg).forEach((el) => el.remove());
    dlg.showModal();
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-update-target]");
    if (!btn || btn.disabled) return;
    ev.preventDefault();
    openUpgrade(btn);
  });

  // Draws one read of GET /api/v1/updates/runs/<id>. Returns whether to stop polling: the run has finished,
  // or its status can't be read (a missing or broken status file stays that way).
  function showRun(el, d) {
    const status = RUN_STATUS[d.status] ? d.status : "unknown";
    const final = RUN_FINAL.indexOf(status) >= 0 || d.final === true;
    const stop = final || status === "unknown";
    const badge = $("[data-run-status]", el);
    if (badge) {
      badge.className = "badge " + RUN_STATUS[status][1];
      badge.textContent = RUN_STATUS[status][0];
    }
    const items = $$("[data-step]", el);
    const names = items.map((li) => li.dataset.step);
    const at = names.indexOf(d.step);
    const rolledBack = d.step === "rollback" || status === "rolled_back" || status === "rollback_failed";
    // During or after a rollback, the step that failed (switch or health) is marked failed, and the ones
    // after it that never ran stay pending. Older status files don't say: then it was the health check.
    const rb = names.indexOf("rollback");
    let failedAt = -1;
    if (d.step === "rollback" && rb > 0) {
      failedAt = names.indexOf(d.failed_step);
      if (failedAt < 0 || failedAt >= rb) failedAt = rb - 1;
    }
    items.forEach((li, i) => {
      let state = "pending";
      if (status === "succeeded") state = "done";
      else if (failedAt >= 0 && i < rb) state = i < failedAt ? "done" : i === failedAt ? "failed" : "pending";
      else if (at >= 0 && i < at) state = "done";
      else if (i === at) state = !final ? "active" : status === "rolled_back" ? "done" : "failed";
      li.className = "update-step " + state;
      if (names[i] === "rollback") li.hidden = !rolledBack;
    });
    const box = $("[data-run-message]", el);
    if (box) {
      const message = typeof d.message === "string" && d.message ? d.message : final ? RUN_DONE_TEXT[status] : "";
      const kind = status === "succeeded" ? "success" : status === "rolled_back" ? "warning" : final || status === "unknown" ? "error" : "";
      box.textContent = message || "";
      box.className = "callout " + kind;
      box.hidden = !message;
    }
    const pre = $("[data-run-log]", el);
    if (pre && typeof d.log === "string") {
      const atBottom = !(pre.scrollHeight > 0) || pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
      pre.textContent = d.log.replace(ANSI, "");
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    }
    const reload = $("[data-run-reload]", el);
    if (reload) reload.hidden = !stop;
    return stop;
  }

  function restarting(el, text) {
    const box = $("[data-run-restarting]", el);
    if (!box) return;
    box.hidden = !text;
    const label = $("[data-run-restarting-text]", box);
    if (label && text) label.textContent = text;
  }

  // ---------------------------------------------------- updates: Branch to follow
  // <select data-update-branches="<followed>"> lists the branches on GitHub, read live through the server
  // (GET /api/v1/updates/branches). Names go in with textContent; the followed branch stays selected and stays
  // in the list even if GitHub no longer has it. On a failure the list Slipway saw last stays, with the reason.
  async function loadUpdateBranches(sel) {
    const followed = sel.dataset.updateBranches;
    const field = sel.closest(".field");
    const note = field && field.querySelector("[data-update-branches-note]");
    const say = (t) => { if (note) note.textContent = t; };
    say("Reading the branches on GitHub...");
    let body;
    try {
      const res = await fetch("/api/v1/updates/branches", { method: "GET", headers: { Accept: "application/json" }, credentials: "same-origin" });
      body = await res.json().catch(() => ({}));
      if (!res.ok) { say(`Couldn't read GitHub's branches: ${body.detail || res.status}. Showing the last known list.`); return; }
    } catch (e) {
      say("Couldn't read GitHub's branches. Showing the last known list.");
      return;
    }
    const live = Array.isArray(body.branches) ? body.branches.filter((n) => typeof n === "string") : [];
    // What is chosen now (the user may have picked one while the list loaded): kept, and marked when GitHub
    // doesn't have it, like the followed branch. "" is "the install's own branch".
    const current = sel.value;
    const names = live.slice();
    [current, followed].forEach((n) => { if (n && !names.includes(n)) names.unshift(n); });
    const own = $("[data-own-branch]", sel);
    $$("option", sel).forEach((o) => o.remove());
    names.forEach((n) => {
      const o = document.createElement("option");
      o.setAttribute("value", n);
      o.textContent = live.includes(n) ? n : `${n} (not on GitHub any more)`;
      if (n === (current === "" ? null : current || followed)) o.selected = true;
      sel.appendChild(o);
    });
    if (own) { sel.appendChild(own); if (current === "") own.selected = true; }
    const hidden = Number(body.hidden) || 0, cut = Number(body.truncated) || 0;
    say(`${live.length + cut} branch${live.length + cut === 1 ? "" : "es"} on GitHub.` +
        (cut ? ` The list shows the first ${live.length}.` : "") +
        (hidden === 1 ? " 1 more with a name Slipway doesn't use is left out."
          : hidden ? ` ${hidden} more with names Slipway doesn't use are left out.` : ""));
  }

  function watchRun(el) {
    const id = el.dataset.updateRun || "";
    if (!RUN_ID.test(id)) return;
    let downSince = 0;
    async function tick() {
      let d;
      try {
        d = await api("GET", "/api/v1/updates/runs/" + id);
      } catch (err) {
        // While the switch recreates Slipway's container nothing answers, or a proxy answers 502/503/504.
        const unreachable = !err.status || (err.status >= 500 && !err.detail);
        if (!unreachable && err.status !== 502) {
          restarting(el, "");
          const box = $("[data-run-message]", el);
          if (box) { box.textContent = err.message; box.className = "callout error"; box.hidden = false; }
          return; // 404, 403, 409: asking again won't change the answer
        }
        downSince = downSince || Date.now();
        if (Date.now() - downSince > RESTART_LIMIT) {
          restarting(el, "Slipway didn't answer for 10 minutes. Check the server, then reload this page.");
          return;
        }
        restarting(el, unreachable ? "Slipway is restarting…" : "Can't read the upgrade from the server right now: " + err.message + ". Trying again.");
        setTimeout(tick, POLL_MS);
        return;
      }
      downSince = 0;
      restarting(el, "");
      if (!showRun(el, d || {})) setTimeout(tick, POLL_MS);
    }
    tick();
  }

  // -------------------------------------------------------------- charts
  // <div class="chart-plot" data-chart='{"kind": "bars" | "line", ...}'> (templates/_charts.html) gets a tooltip:
  // per day slot on bars (the whole slot is the target), the nearest point with a crosshair on lines. The same
  // shows from the keyboard once the plot has focus (arrows, Page Up/Down, Home, End; Escape hides it).
  // Screen readers hear the keyboard's moves only, from a separate live region: the pointer's tooltip is
  // visual and would otherwise queue an announcement on every move. Everything goes in with textContent. Without JavaScript the bars keep their SVG <title>s, and every chart
  // has a table view.
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const pad2 = (n) => String(n).padStart(2, "0");

  // Same rule as the page's pct filter: one decimal under 10, whole numbers above.
  function fmtPct(v) {
    if (typeof v !== "number" || !isFinite(v)) return "—";
    return (v < 10 ? v.toFixed(1) : String(Math.round(v))) + "%";
  }

  function fmtWhen(epoch, hourly) {
    epoch = Math.round(epoch);
    const d = new Date(epoch * 1000);
    const day = WEEKDAYS[d.getUTCDay()] + " " + d.getUTCDate() + " " + MONTHS[d.getUTCMonth()];
    const hm = pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
    if (!hourly) return day + ", " + hm + " UTC";
    return day + ", " + hm + "–" + pad2(new Date((epoch + 3600) * 1000).getUTCHours()) + ":00 UTC";
  }

  // Index in the sorted list ``ts`` closest to ``x``.
  function nearestIndex(ts, x) {
    let lo = 0, hi = ts.length - 1;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      if (ts[mid] <= x) lo = mid; else hi = mid;
    }
    return Math.abs(ts[hi] - x) < Math.abs(x - ts[lo]) ? hi : lo;
  }

  function chartEl(tag, cls, text) {
    const el = document.createElement(tag);
    el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  // A line chart's points live once per host on <div id=".." data-points='{"start", "span", "hourly", "t": [..],
  // "cpu": [..], "mem": [..], "disk"?: [..], "cpu_peak"?: [..], "mem_peak"?: [..]}'>, shared by its charts.
  // Returns the chart's own series (points without a value left out), or null.
  const pointSets = {};
  function linePoints(spec) {
    const src = typeof spec.points === "string" ? document.getElementById(spec.points) : null;
    if (!src) return null;
    if (!(spec.points in pointSets)) {
      try { pointSets[spec.points] = JSON.parse(src.dataset.points); } catch (e) { pointSets[spec.points] = null; }
    }
    const all = pointSets[spec.points];
    if (!all || !Array.isArray(all.t) || !Array.isArray(all[spec.key])) return null;
    const peaks = all[spec.key + "_peak"];
    const out = { start: all.start, span: all.span, hourly: !!all.hourly, t: [], v: [], peak: Array.isArray(peaks) ? [] : null };
    all.t.forEach((t, i) => {
      const v = all[spec.key][i];
      if (typeof v !== "number") return;
      out.t.push(t);
      out.v.push(v);
      if (out.peak) out.peak.push(peaks[i]);
    });
    return out;
  }

  function wireChart(plot) {
    let spec;
    try { spec = JSON.parse(plot.dataset.chart); } catch (e) { return; }
    const bars = spec.kind === "bars";
    if (!bars) {
      const pts = linePoints(spec);
      if (!pts) return;
      spec = Object.assign({}, spec, pts);
    }
    const n = bars ? (spec.rows || []).length : (spec.t || []).length;
    if (!n || (!bars && !(spec.span > 0))) return;
    $$("title", plot).forEach((t) => t.remove());  // the tooltip replaces the browser's own
    const tip = chartEl("div", "chart-tip");
    tip.hidden = true;
    tip.setAttribute("aria-hidden", "true");
    plot.appendChild(tip);
    const live = chartEl("div", "sr-only");
    live.setAttribute("aria-live", "polite");
    plot.appendChild(live);
    let cross = null, dot = null;
    if (!bars) {
      cross = chartEl("div", "chart-cross");
      dot = chartEl("span", "chart-dot");
      cross.hidden = dot.hidden = true;
      plot.appendChild(cross);
      plot.appendChild(dot);
    }
    const marks = bars ? $$("[data-i]", plot) : [];
    let current = -1, spoken = "";

    function row(value, name, key) {
      spoken += ", " + value + " " + name;
      const r = chartEl("div", "chart-tip-row");
      r.appendChild(chartEl("span", "chart-key " + key));
      r.appendChild(chartEl("b", "", value));
      r.appendChild(chartEl("span", "chart-tip-name", name));
      return r;
    }

    // Whether the tip goes right of the point, left of it, or (when neither fits, as on a phone) is pinned
    // inside the plot. Measured when the sizes are known; otherwise right of the point on the left 60%.
    function place(pos) {
      const width = plot.clientWidth, tipWidth = tip.offsetWidth;
      let mode = pos > 60 ? "flip" : "";
      if (width > 0 && tipWidth > 0) {
        const x = pos / 100 * width;
        mode = x + 14 + tipWidth <= width ? "" : x - 14 - tipWidth >= 0 ? "flip" : "pin";
      }
      tip.style.left = mode === "pin" ? Math.max(0, width - tipWidth) + "px" : pos + "%";
      tip.classList.toggle("flip", mode === "flip");
      tip.classList.toggle("pin", mode === "pin");
    }

    function show(i, announce) {
      i = Math.max(0, Math.min(n - 1, i));
      if (i === current && !tip.hidden) {  // the pointer moved within the same point: nothing changes
        if (announce) live.textContent = spoken;
        return;
      }
      current = i;
      tip.textContent = "";
      spoken = "";
      let pos;
      if (bars) {
        const r = spec.rows[i];
        pos = (i + 0.5) / n * 100;
        tip.appendChild(chartEl("div", "chart-tip-head", r.label));
        spoken = r.label;
        spec.series.forEach((s, k) => tip.appendChild(row(String(r.values[k]), s.name, s.key)));
        marks.forEach((m) => m.classList.toggle("is-active", Number(m.getAttribute("data-i")) === i));
        plot.classList.toggle("has-active", true);
      } else {
        const v = spec.v[i];
        pos = Math.max(0, Math.min(100, spec.t[i] / spec.span * 100));
        spoken = fmtWhen(spec.start + spec.t[i], spec.hourly);
        tip.appendChild(chartEl("div", "chart-tip-head", spoken));
        tip.appendChild(row(fmtPct(v), spec.value_name || spec.name, "line"));
        if (spec.peak) tip.appendChild(row(fmtPct(spec.peak[i]), "Peak", "line"));
        cross.style.left = dot.style.left = pos + "%";
        dot.style.top = (100 - Math.max(0, Math.min(100, v))) + "%";
        cross.hidden = dot.hidden = false;
      }
      tip.hidden = false;
      place(pos);
      if (announce) live.textContent = spoken;
    }

    function hide() {
      current = -1;
      tip.hidden = true;
      live.textContent = "";
      if (cross) cross.hidden = dot.hidden = true;
      marks.forEach((m) => m.classList.toggle("is-active", false));
      plot.classList.toggle("has-active", false);
    }

    function indexAt(ev) {
      const box = plot.getBoundingClientRect();
      if (!box || !box.width) return -1;
      const frac = Math.max(0, Math.min(1, (ev.clientX - box.left) / box.width));
      return bars ? Math.min(n - 1, Math.floor(frac * n)) : nearestIndex(spec.t, frac * spec.span);
    }

    const follow = (ev) => { const i = indexAt(ev); if (i >= 0) show(i); };
    plot.addEventListener("pointermove", follow);
    plot.addEventListener("pointerdown", follow);
    plot.addEventListener("pointerleave", () => { if (document.activeElement === plot) show(current); else hide(); });
    plot.addEventListener("focus", () => show(current >= 0 ? current : n - 1, true));
    plot.addEventListener("blur", hide);
    plot.addEventListener("keydown", (ev) => {
      const page = Math.max(1, Math.round(n / 10));
      const at = current >= 0 ? current : n - 1;
      const moves = { ArrowLeft: at - 1, ArrowRight: at + 1, PageUp: at - page, PageDown: at + page, Home: 0, End: n - 1 };
      if (ev.key in moves) { ev.preventDefault(); show(moves[ev.key], true); }
      else if (ev.key === "Escape") hide();
    });
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
    $$("[data-update-run]").forEach(watchRun);
    $$("[data-host-setup]").forEach(followSetup);
    $$("[data-update-branches]").forEach(loadUpdateBranches);
    $$("[data-load]").forEach((el) => { if (el.dataset.lazy === undefined) load(el); });
    $$("[data-chart]").forEach(wireChart);
    $$("select[data-fill]").forEach(wireFill);
    $$("select[data-branches]").forEach(wireBranches);
    // Before wireShowWhen: the flow keeps its computed fields (data_mode) current on every change first.
    $$("form[data-env-flow]").forEach(wireEnvFlow);
    $$("form").forEach(wireVmForms);
    $$("form").forEach(wireShowWhen);
    $$("[data-app-form]").forEach(wireAppForm);
    $$("form[data-account-form]").forEach(wireAccountForm);
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

  window.slipway = {
    api, toast, serialize, humanBytes, statusBadge, renderers, FIELD_STEP, fieldStep, flowBody,
    wireAccountForm, openAccount, accountBody, PROBE_FINGERPRINT,
    cloudObjectsHtml, cloudCallouts, costTableHtml, costPrice, RUNNING,
    vmSpec, vmProblem, vmSizeText, vmLiveView, vmLiveHtml, vmSnapshotsHtml,
  };
})();
