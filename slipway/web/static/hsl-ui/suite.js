/*
 * HSL Suite widgets (hackspacelabs-web/ui): <hsl-app-switcher>, <hsl-user-menu>, the light/dark
 * theme, and the H mark. No dependencies, no shadow DOM, no inline styles and no <style> tags, so it
 * works under a Content-Security-Policy of style-src 'self'. Load it as a plain <script> or import it
 * for its side effects; it defines window.HSLSuite. Markup and events: see README.md.
 */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.HSLSuite) return;

  var THEME_KEY = 'hsl-suite-theme';
  var SVG = 'http://www.w3.org/2000/svg';
  var uid = 0;
  var nextId = function (prefix) {
    uid += 1;
    return prefix + '-' + uid;
  };

  // ---------------------------------------------------------------- theme
  // Light unless the user chose dark. Never follows the operating system.

  function readTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light';
    } catch (e) {
      return 'light';
    }
  }

  function applyTheme(theme) {
    var root = document.documentElement;
    if (theme === 'dark') root.setAttribute('data-theme', 'dark');
    else root.removeAttribute('data-theme');
  }

  function setTheme(theme) {
    theme = theme === 'dark' ? 'dark' : 'light';
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (e) {
      /* storage blocked: the choice lasts for this page only */
    }
    applyTheme(theme);
    document.dispatchEvent(new CustomEvent('hsl-themechange', { detail: { theme: theme } }));
    return theme;
  }

  /**
   * Moves an app's old theme setting to the shared key once: the first of oldKeys holding "dark" or
   * "light" is copied (only while the shared key is empty) and every old key is removed.
   */
  function migrateTheme(oldKeys) {
    try {
      var store = window.localStorage;
      var found = null;
      (oldKeys || []).forEach(function (key) {
        var v = store.getItem(key);
        if (found === null && (v === 'dark' || v === 'light')) found = v;
        if (v !== null) store.removeItem(key);
      });
      if (found !== null && store.getItem(THEME_KEY) === null) store.setItem(THEME_KEY, found);
    } catch (e) {
      /* nothing to migrate */
    }
    applyTheme(readTheme());
    return readTheme();
  }

  applyTheme(readTheme());

  // ---------------------------------------------------------------- the H mark

  var MARK_H = 'M95 45H215L255 85V240H445V85L485 45H605L665 105V570L605 630H485L445 590V465H255V590L215 630H95L35 570V105Z';
  var MARK_GAP = 'M0 434H168C206 434 206 374 244 374H446C496 374 496 277 546 277H700';
  // [colour, lower edge], drawn bottom band first; navy fills the rest.
  var MARK_BANDS = [
    ['#0a8dba', 'M0 562C160 546 320 560 460 546S620 502 700 496'],
    ['#0fb0d6', 'M0 522C160 506 300 520 450 496S620 432 700 422'],
    ['#74d4ec', 'M0 470C150 456 280 470 420 440S600 352 700 346'],
    ['#d81f27', MARK_GAP],
    ['#ec2d1d', 'M0 338C150 318 300 352 450 332S620 282 700 277'],
    ['#fb7d24', 'M0 272C140 256 260 292 400 276S600 226 700 222'],
    ['#ffc760', 'M0 176C150 160 260 196 420 170S620 142 700 142'],
    ['#fbae2c', 'M0 112C150 92 260 138 410 118S610 96 700 100'],
  ];

  function svgEl(name, attrs) {
    var el = document.createElementNS(SVG, name);
    Object.keys(attrs).forEach(function (k) {
      el.setAttribute(k, attrs[k]);
    });
    return el;
  }

  /** The H mark as an <svg> element, `size` pixels wide. Decorative (aria-hidden). */
  function mark(size) {
    size = size || 34;
    var id = nextId('hsl-mark');
    var svg = svgEl('svg', {
      class: 'hsl-mark',
      viewBox: '35 45 630 585',
      width: String(size),
      height: String(Math.round((size * 585) / 630)),
      'aria-hidden': 'true',
      focusable: 'false',
    });
    var mask = svgEl('mask', { id: id });
    mask.appendChild(svgEl('path', { d: MARK_H, fill: '#fff' }));
    mask.appendChild(svgEl('path', { d: MARK_GAP, fill: 'none', stroke: '#000', 'stroke-width': '16' }));
    svg.appendChild(mask);
    var g = svgEl('g', { mask: 'url(#' + id + ')' });
    g.appendChild(svgEl('rect', { x: '0', y: '0', width: '700', height: '670', fill: '#003e65' }));
    MARK_BANDS.forEach(function (band) {
      g.appendChild(svgEl('path', { d: band[1] + 'V0H0Z', fill: band[0] }));
    });
    svg.appendChild(g);
    return svg;
  }

  function gridIcon() {
    var svg = svgEl('svg', { width: '18', height: '18', viewBox: '0 0 18 18', fill: 'currentColor', 'aria-hidden': 'true', focusable: 'false' });
    [3, 9, 15].forEach(function (y) {
      [3, 9, 15].forEach(function (x) {
        svg.appendChild(svgEl('circle', { cx: String(x), cy: String(y), r: '2' }));
      });
    });
    return svg;
  }

  // ---------------------------------------------------------------- helpers

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  /** Only http(s) addresses and same-site paths become links. */
  function safeUrl(value) {
    if (typeof value !== 'string' || value === '') return null;
    if (value.charAt(0) === '/' && value.charAt(1) !== '/' && value.charAt(1) !== '\\') return value;
    try {
      var u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
    } catch (e) {
      return null;
    }
  }

  function initials(name) {
    var parts = String(name || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return '?';
    var first = Array.from(parts[0])[0] || '';
    var last = parts.length > 1 ? Array.from(parts[parts.length - 1])[0] || '' : '';
    return (first + last).toUpperCase();
  }

  // ---------------------------------------------------------------- menu button behaviour
  // WAI-ARIA menu button: Enter, Space or Down opens on the first item, Up on the last; arrows, Home
  // and End move; Escape closes and returns to the button; Tab or a click outside closes.

  function MenuButton(host, button, pop, menu) {
    this.host = host;
    this.button = button;
    this.pop = pop;
    this.menu = menu;
    var self = this;

    button.addEventListener('click', function () {
      if (self.isOpen()) self.close(false);
      else self.open(0);
    });
    button.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        self.open(0);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        self.open(-1);
      }
    });
    menu.addEventListener('keydown', function (e) {
      var items = self.items();
      var i = items.indexOf(document.activeElement);
      var move = function (to) {
        e.preventDefault();
        if (items.length) items[(to + items.length) % items.length].focus();
      };
      switch (e.key) {
        case 'ArrowDown':
        case 'ArrowRight':
          move(i + 1);
          break;
        case 'ArrowUp':
        case 'ArrowLeft':
          move(i - 1);
          break;
        case 'Home':
          move(0);
          break;
        case 'End':
          move(items.length - 1);
          break;
        case 'Escape':
          e.preventDefault();
          self.close(true);
          break;
        case 'Tab':
          self.close(false);
          break;
        case ' ':
          // Links don't act on Space by themselves.
          if (i >= 0) {
            e.preventDefault();
            items[i].click();
          }
          break;
        default:
          break;
      }
    });

    this.onDocClick = function (e) {
      if (self.isOpen() && !self.host.contains(e.target)) self.close(false);
    };
    this.onOtherOpen = function (e) {
      if (e.detail !== self.host) self.close(false);
    };
  }

  MenuButton.prototype.items = function () {
    return Array.prototype.slice.call(this.menu.querySelectorAll('[role^="menuitem"]'));
  };
  MenuButton.prototype.isOpen = function () {
    return !this.pop.hidden;
  };
  MenuButton.prototype.open = function (index) {
    document.dispatchEvent(new CustomEvent('hsl-menu-open', { detail: this.host }));
    this.pop.hidden = false;
    this.button.setAttribute('aria-expanded', 'true');
    var items = this.items();
    if (items.length) items[(index + items.length) % items.length].focus();
  };
  MenuButton.prototype.close = function (focusButton) {
    if (!this.isOpen()) return;
    this.pop.hidden = true;
    this.button.setAttribute('aria-expanded', 'false');
    if (focusButton) this.button.focus();
  };
  MenuButton.prototype.connect = function () {
    document.addEventListener('click', this.onDocClick);
    document.addEventListener('hsl-menu-open', this.onOtherOpen);
  };
  MenuButton.prototype.disconnect = function () {
    document.removeEventListener('click', this.onDocClick);
    document.removeEventListener('hsl-menu-open', this.onOtherOpen);
  };

  function menuItem(tag, role, className, label) {
    var item = el(tag, 'hsl-menu-item' + (className ? ' ' + className : ''));
    item.setAttribute('role', role);
    item.setAttribute('tabindex', '-1');
    if (tag === 'button') item.type = 'button';
    if (label !== undefined) item.appendChild(el('span', null, label));
    return item;
  }

  // ---------------------------------------------------------------- <hsl-app-switcher>
  // apps: JSON array of {id, name, url, description?}; current: the id of this app.

  class HslAppSwitcher extends HTMLElement {
    static get observedAttributes() {
      return ['apps', 'current', 'label'];
    }
  }

  HslAppSwitcher.prototype.connectedCallback = function () {
    this.render();
  };
  HslAppSwitcher.prototype.disconnectedCallback = function () {
    if (this.menuButton) this.menuButton.disconnect();
  };
  HslAppSwitcher.prototype.attributeChangedCallback = function () {
    if (this.isConnected) this.render();
  };

  HslAppSwitcher.prototype.apps = function () {
    var list;
    try {
      list = JSON.parse(this.getAttribute('apps') || '[]');
    } catch (e) {
      list = [];
    }
    if (!Array.isArray(list)) return [];
    return list.filter(function (a) {
      return a && typeof a.name === 'string' && safeUrl(a.url);
    });
  };

  HslAppSwitcher.prototype.render = function () {
    if (this.menuButton) this.menuButton.disconnect();
    while (this.firstChild) this.removeChild(this.firstChild);
    var apps = this.apps();
    this.hidden = apps.length === 0;
    if (this.hidden) return;

    var label = this.getAttribute('label') || 'Switch app';
    var current = this.getAttribute('current') || '';
    var popId = nextId('hsl-switcher');

    var button = el('button', 'hsl-iconbtn');
    button.type = 'button';
    button.setAttribute('aria-haspopup', 'menu');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', popId);
    button.setAttribute('aria-label', label);
    button.title = label;
    button.appendChild(gridIcon());

    var pop = el('div', 'hsl-pop');
    pop.id = popId;
    pop.hidden = true;
    var title = el('p', 'hsl-pop-title', 'HackSpaceLabs apps');
    title.id = popId + '-title';
    pop.appendChild(title);
    var menu = el('div', 'hsl-switcher-grid');
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-labelledby', popId + '-title');

    apps.forEach(function (app) {
      var link = el('a', 'hsl-switcher-app');
      link.href = safeUrl(app.url);
      link.setAttribute('role', 'menuitem');
      link.setAttribute('tabindex', '-1');
      if (app.id === current) link.setAttribute('aria-current', 'page');
      link.appendChild(mark(26));
      var text = el('span', null, app.name);
      if (app.description) text.appendChild(el('small', null, app.description));
      link.appendChild(text);
      menu.appendChild(link);
    });
    pop.appendChild(menu);
    this.appendChild(button);
    this.appendChild(pop);

    this.menuButton = new MenuButton(this, button, pop, menu);
    this.menuButton.connect();
  };

  // ---------------------------------------------------------------- <hsl-user-menu>
  // name, detail (role line), profile-url, profile-label, signout-label. Fires "hsl-signout".

  class HslUserMenu extends HTMLElement {
    static get observedAttributes() {
      return ['name', 'detail', 'profile-url', 'profile-label', 'signout-label'];
    }
  }

  HslUserMenu.prototype.connectedCallback = function () {
    var self = this;
    this.onTheme = function () {
      self.syncTheme();
    };
    document.addEventListener('hsl-themechange', this.onTheme);
    this.render();
  };
  HslUserMenu.prototype.disconnectedCallback = function () {
    document.removeEventListener('hsl-themechange', this.onTheme);
    if (this.menuButton) this.menuButton.disconnect();
  };
  HslUserMenu.prototype.attributeChangedCallback = function () {
    if (this.isConnected) this.render();
  };

  HslUserMenu.prototype.syncTheme = function () {
    if (!this.themeItem) return;
    var dark = readTheme() === 'dark';
    this.themeItem.setAttribute('aria-checked', String(dark));
    this.themeState.textContent = dark ? 'On' : 'Off';
  };

  HslUserMenu.prototype.render = function () {
    var self = this;
    if (this.menuButton) this.menuButton.disconnect();
    while (this.firstChild) this.removeChild(this.firstChild);

    var name = this.getAttribute('name') || 'Signed in';
    var detail = this.getAttribute('detail') || '';
    var popId = nextId('hsl-user');

    var button = el('button', 'hsl-userbtn');
    button.type = 'button';
    button.setAttribute('aria-haspopup', 'menu');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', popId);
    button.setAttribute('aria-label', 'Account: ' + name);
    var avatar = el('span', 'hsl-avatar', initials(name));
    avatar.setAttribute('aria-hidden', 'true');
    button.appendChild(avatar);
    button.appendChild(el('span', 'hsl-userbtn-name', name));

    var pop = el('div', 'hsl-pop hsl-menu');
    pop.id = popId;
    pop.hidden = true;
    var head = el('div', 'hsl-menu-head');
    head.appendChild(el('strong', null, name));
    if (detail) head.appendChild(el('small', null, detail));
    pop.appendChild(head);

    var menu = el('div');
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', 'Account');

    var profile = safeUrl(this.getAttribute('profile-url'));
    if (profile) {
      var link = menuItem('a', 'menuitem', '', this.getAttribute('profile-label') || 'Profile');
      link.href = profile;
      menu.appendChild(link);
    }

    var theme = menuItem('button', 'menuitemcheckbox', '', 'Dark mode');
    this.themeState = el('span', 'hsl-menu-state');
    this.themeState.setAttribute('aria-hidden', 'true');
    theme.appendChild(this.themeState);
    theme.addEventListener('click', function () {
      setTheme(readTheme() === 'dark' ? 'light' : 'dark');
    });
    this.themeItem = theme;
    menu.appendChild(theme);

    var sep = el('div', 'hsl-menu-sep');
    sep.setAttribute('role', 'separator');
    menu.appendChild(sep);

    var signout = menuItem('button', 'menuitem', 'is-danger', this.getAttribute('signout-label') || 'Sign out');
    signout.addEventListener('click', function () {
      self.menuButton.close(false);
      self.dispatchEvent(new CustomEvent('hsl-signout', { bubbles: true, cancelable: true }));
    });
    menu.appendChild(signout);

    pop.appendChild(menu);
    this.appendChild(button);
    this.appendChild(pop);
    this.syncTheme();

    this.menuButton = new MenuButton(this, button, pop, menu);
    this.menuButton.connect();
  };

  if (window.customElements) {
    if (!window.customElements.get('hsl-app-switcher')) window.customElements.define('hsl-app-switcher', HslAppSwitcher);
    if (!window.customElements.get('hsl-user-menu')) window.customElements.define('hsl-user-menu', HslUserMenu);
  }

  window.HSLSuite = {
    version: '0.1.0',
    theme: {
      key: THEME_KEY,
      get: readTheme,
      set: setTheme,
      toggle: function () {
        return setTheme(readTheme() === 'dark' ? 'light' : 'dark');
      },
      migrate: migrateTheme,
    },
    mark: mark,
  };
})();
