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
 *   <form data-once>                                       (after it succeeds its submit button stays disabled)
 *   <button data-update-target data-branch=.. data-sha=..> opens #update-confirm filled from its data-*
 *   <section data-update-run="<run id>">                   (follows an upgrade of Slipway: steps, status, log)
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
      err.status = res.status;
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

  function then(spec, data) {
    if (!spec) return;
    if (spec === "reload") return location.reload();
    if (spec.startsWith("redirect:")) {
      const url = spec.slice(9).replace(/\{(\w+)\}/g, (_, k) => encodeURIComponent((data && data[k]) || ""));
      location.href = sameOrigin(url);
    }
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

  function serialize(form) {
    const out = {};
    $$("[name]", form).forEach((el) => {
      if (el.tagName === "BUTTON" || el.disabled || el.closest("[data-repeater]") || el.closest("[hidden]")) return;
      if (el.type === "radio" && !el.checked) return;
      if (el.dataset.array !== undefined) {
        out[el.name] = out[el.name] || [];
        if (el.checked) out[el.name].push(el.value);
        return;
      }
      const v = coerce(el);
      if ((v === "" || v === null) && el.dataset.keepEmpty === undefined) return;
      out[el.name] = v;
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
  document.addEventListener("click", (ev) => {
    const opener = ev.target.closest("[data-open]");
    if (opener) {
      const dlg = document.getElementById(opener.dataset.open);
      if (dlg) { $$("[data-form-error]", dlg).forEach((el) => el.remove()); dlg.showModal(); const f = $("input:not([type=hidden]), textarea, select", dlg); if (f) f.focus(); }
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
    const text = (btn.dataset.copy || (target && target.textContent) || "").trim();
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
        if (badge && STATUS[d.status]) {
          badge.className = "badge " + STATUS[d.status][1];
          badge.textContent = STATUS[d.status][0];
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
    readme(el, data) { el.textContent = (data && data.content) || "This repository has no README."; },
  };

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
      set("repository", repo && repo.selectedOptions[0] ? repo.selectedOptions[0].textContent.trim() : "");
      set("branch", data.branch);
      set("source", compose ? `docker compose (${(composeFile && composeFile.value) || "docker-compose.yml"})`
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
      set("ports", compose ? (overrides.length ? `Compose file, with ${overrides.join(", ")}` : "Defined by compose file") : (data.ports || []).map((p) => `${p.host} → ${p.container} (${(p.protocol || "tcp").toUpperCase()})`).join(", ") || "None");
      set("hostnames", (data.routes || []).map((r) => `${r.hostname} → ${r.service ? r.service + ":" : ""}${r.container || "?"}`).join(", ") || "None");
      set("volumes", compose ? "Defined by compose file" : (data.volumes || []).map((v) => `${v.source} → ${v.target}`).join(", ") || "None");
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  }

  // ------------------------------------- conditional fields: data-show-when="field=value"
  function wireShowWhen(form) {
    const targets = $$("[data-show-when]", form);
    if (!targets.length) return;
    const update = () => {
      targets.forEach((el) => {
        const [name, value] = el.dataset.showWhen.split("=");
        const checked = $(`[name="${name}"]:checked`, form);
        const field = checked || $(`[name="${name}"]:not([type=radio])`, form);
        el.hidden = !field || field.value !== value;
      });
    };
    form.addEventListener("change", update);
    update();
  }

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
    $$("[data-update-branches]").forEach(loadUpdateBranches);
    $$("[data-load]").forEach(load);
    $$("[data-chart]").forEach(wireChart);
    $$("select[data-fill]").forEach(wireFill);
    $$("select[data-branches]").forEach(wireBranches);
    $$("form").forEach(wireShowWhen);
    $$("form[data-preview-form]").forEach(wirePreview);
    const params = new URLSearchParams(location.search);
    $$("dialog[data-open-on]").forEach((dlg) => { if (params.get(dlg.dataset.openOn)) dlg.showModal(); });
    $$("[data-filter]").forEach((input) => {
      input.addEventListener("input", () => {
        const q = input.value.toLowerCase();
        $$(input.dataset.filter + " tbody tr").forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
      });
    });
  });

  window.slipway = { api, toast, serialize };
})();
