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
    const [method, url] = form.dataset.form.split(" ");
    const submit = ev.submitter || $('[type="submit"]', form);
    let body;
    try { body = serialize(form); } catch (err) { return toast("Invalid input: " + err.message, "error"); }
    omitUnchanged(form, body);
    if (submit && submit.name) body[submit.name] = submit.value === "true" ? true : submit.value === "false" ? false : submit.value;
    setLoading(submit, true);
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
      if (form.dataset.success) {
        (form.dataset.then || "").startsWith("redirect") || form.dataset.then === "reload"
          ? flashAfterReload(form.dataset.success) : toast(form.dataset.success);
      }
      then(form.dataset.then, data);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setLoading(submit, false);
    }
  });

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
      if (dlg) { dlg.showModal(); const f = $("input:not([type=hidden]), textarea, select", dlg); if (f) f.focus(); }
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
      set("env", Object.keys(data.env || {}).length + " variable(s)");
      const overrides = (data.port_overrides || []).map((o) => `${o.service} ${o.host} → ${o.container}`);
      set("ports", compose ? (overrides.length ? `Compose file, with ${overrides.join(", ")}` : "Defined by compose file") : (data.ports || []).map((p) => `${p.host} → ${p.container} (${(p.protocol || "tcp").toUpperCase()})`).join(", ") || "None");
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
