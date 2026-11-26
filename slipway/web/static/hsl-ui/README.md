# HSL Suite kit

The shared look of HackSpaceLabs, Slipway, Switchyard, Harbor Master and Tideline: colour and font
tokens, the app frame (sidebar and top bar), the sign-in card, the app switcher, the user menu with the
light/dark toggle, the H mark and the fonts. It has no framework and no build step, so the React apps and
Slipway's server-rendered pages use the same files.

Open `demo.html` through any local web server (it sets a strict Content-Security-Policy, which `file://`
pages don't get reliably), e.g. `python3 -m http.server -d ui 8765`, then <http://localhost:8765/demo.html>.
Its toolbar switches between the frame, the sign-in pages and the token swatches, turns dark mode on, and
runs a WCAG contrast check on whatever is showing.

## Files

| File | What it holds |
|---|---|
| `tokens.css` | Every colour, radius, shadow and font token on `:root`; dark values under `:root[data-theme='dark']` only |
| `fonts.css`, `fonts/` | Inter Variable and Outfit 700 (latin, latin-ext) with their licences, for pages without a bundler |
| `shell.css` | The frame and the two widgets; every class starts with `hsl-` |
| `auth.css` | The centred card for sign-in, signed-out, no-access and change-password pages |
| `suite.js` | `<hsl-app-switcher>`, `<hsl-user-menu>`, the theme, and the mark |
| `hsl-suite.d.ts` | TypeScript declarations for `window.HSLSuite` and the two elements (JSX attributes for React) |
| `mark.svg`, `favicon.svg` | The H mark |
| `apple-touch-icon.png` | The H mark on white, 180 × 180, for phone home screens |
| `VERSION` | The kit's version; releases are tagged `ui-v<VERSION>` |
| `demo.html`, `demo.css`, `demo.js` | The demo page (not copied into apps) |

## Rules

- **Light by default.** Dark only when the user turns it on. Nothing here reads `prefers-color-scheme`,
  and apps must not either.
- **Works under `style-src 'self'`.** No inline styles, no `<style>` tags and no shadow DOM, so it runs
  under Tideline's Content-Security-Policy. Load the CSS and `suite.js` from your own origin.
- **Apps keep their own components.** Cards, buttons, tables and forms stay in each app's CSS, written
  against these tokens. Only the tokens, the frame, the sign-in card and the two widgets are shared.
- **Don't edit a synced copy.** Change the kit here, bump `VERSION`, tag `ui-vX.Y.Z`, and sync.

## Using it in an app

Copy it in at a release with `scripts/sync-hsl-ui.sh` (copy that script into the app too):

```bash
scripts/sync-hsl-ui.sh ui-v0.1.0 web/src/hsl-ui
```

```bash
scripts/sync-hsl-ui.sh --check web/src/hsl-ui
```

The second command is for CI: it fails if the copy no longer matches what was synced.

- **React apps (Vite):** import the CSS and the script once at the top of `main.tsx`, and keep the
  `@fontsource` packages, which declare the same font family names:

  ```ts
  import './hsl-ui/tokens.css'
  import './hsl-ui/shell.css'
  import './hsl-ui/auth.css'
  import './hsl-ui/suite.js'
  ```

- **Server-rendered pages (Slipway):** link the files in `<head>`, `suite.js` as a plain script without
  `defer`, so the theme is applied before the page paints:

  ```html
  <link rel="stylesheet" href="/static/hsl-ui/fonts.css">
  <link rel="stylesheet" href="/static/hsl-ui/tokens.css">
  <link rel="stylesheet" href="/static/hsl-ui/shell.css">
  <script src="/static/hsl-ui/suite.js"></script>
  ```

- **Icons:** `favicon.svg` for the tab and `apple-touch-icon.png` for phone home screens:

  ```html
  <link rel="icon" href="/hsl-ui/favicon.svg" type="image/svg+xml">
  <link rel="apple-touch-icon" href="/hsl-ui/apple-touch-icon.png">
  ```

## The frame

```html
<a class="hsl-skip" href="#main">Skip to content</a>
<div class="hsl-shell">
  <aside class="hsl-sidebar">
    <a class="hsl-brand" href="/" aria-label="Tideline home">
      <img class="hsl-mark" src="/hsl-ui/mark.svg" width="34" height="32" alt="">
      <span class="hsl-wordmark">Tideline</span>
    </a>
    <nav class="hsl-nav" aria-label="Main">
      <div class="hsl-nav-group">
        <a class="hsl-nav-item" href="/" aria-current="page"><svg aria-hidden="true">…</svg>Search</a>
        <a class="hsl-nav-item" href="/sources">…Sources<span class="hsl-nav-badge">3</span></a>
      </div>
      <div class="hsl-nav-group">
        <div class="hsl-nav-label">Administration</div>
        <a class="hsl-nav-item" href="/users">…Users</a>
      </div>
    </nav>
    <!-- optional: <div class="hsl-sidebar-foot">…</div> for app-specific controls -->
  </aside>
  <div class="hsl-main">
    <header class="hsl-topbar">
      <div class="hsl-topbar-title">
        <a href="/">Tideline</a><span class="hsl-topbar-sep" aria-hidden="true">/</span><strong>Search</strong>
      </div>
      <!-- the app's own tools (search box, status) go here -->
      <div class="hsl-topbar-end">
        <hsl-app-switcher current="tideline" apps='[…]'></hsl-app-switcher>
        <hsl-user-menu name="Jimmy Henderson" detail="Admin · HackSpaceLabs" profile-url="https://hackspacelabs.com/me"></hsl-user-menu>
      </div>
    </header>
    <main class="hsl-content" id="main" tabindex="-1">…</main>
  </div>
</div>
```

- Mark the current page with `aria-current="page"` (or the class `is-active`) on its `.hsl-nav-item`.
- Under 900 px the sidebar becomes a strip above the page, with the nav scrolling sideways, and the user
  menu shows only the avatar.
- The sizes are tokens: `--hsl-sidebar-width` (248 px) and `--hsl-topbar-height` (64 px). To narrow the
  sidebar (a collapsed rail, say), set `--hsl-sidebar-width` on `.hsl-shell` rather than overriding
  `grid-template-columns`: the full-height sidebar colour is drawn from the same token.

## The sign-in card

```html
<div class="hsl-auth">
  <div class="hsl-auth-card">
    <div class="hsl-auth-brand"><img class="hsl-mark" src="…/mark.svg" width="44" height="41" alt=""><span class="hsl-wordmark">Switchyard</span></div>
    <h1 class="hsl-auth-title">Sign in</h1>
    <p class="hsl-auth-alert" role="alert">…</p>                <!-- add is-warn for a warning -->
    <a class="hsl-auth-button is-sso" href="/api/auth/oidc/login?next=%2F"><img class="hsl-mark" src="…/mark.svg" width="20" height="19" alt="">Sign in with HackSpaceLabs</a>
    <div class="hsl-auth-divider">or with a local account</div>
    <form class="hsl-auth-form">
      <label class="hsl-auth-field">Username<input class="hsl-auth-input" autocomplete="username"></label>
      <label class="hsl-auth-field">Password<input class="hsl-auth-input" type="password" autocomplete="current-password"></label>
      <button class="hsl-auth-button is-primary">Sign in</button>
    </form>
    <button type="button" class="hsl-auth-link">Use a local account</button>
    <p class="hsl-auth-note">…</p>
  </div>
</div>
```

`hsl-auth-text` is a muted paragraph (the signed-out page uses it). `hsl-auth-check` is a tick-box row.

## `<hsl-app-switcher>`

| Attribute | |
|---|---|
| `apps` | JSON array of `{"id", "name", "url", "description"}`, usually built from `HSL_SUITE_APPS` |
| `current` | the `id` of this app, marked with `aria-current="page"` |
| `label` | button label, default "Switch app" |

It hides itself when `apps` is empty. Only `http(s)` addresses and same-site paths become links.

## `<hsl-user-menu>`

| Attribute | |
|---|---|
| `name` | the person's name; the avatar shows its initials |
| `detail` | the line under the name: the role, then how they signed in (below) |
| `avatar-url` | optional: a photo for the avatar (same-site path or http(s)); initials if it's empty or fails to load |
| `profile-url` | the Profile link (the portal's `/me`); left out when empty |
| `profile-label`, `signout-label` | default "Profile" and "Sign out" |
| `compact-below` | optional: a window width in px at or below which the button shows only the avatar. Every app gets this below 900 px; set it when your top bar needs the room sooner (Harbor Master uses 1200). |

**The `detail` line is the same in every app:** the person's role in this app as the app names it, then
` · HackSpaceLabs` for an account signed in through HackSpaceLabs, or ` · Local account` for one that
signed in with the app's own password. For example "Admin · HackSpaceLabs", "Editor · Local account",
"Administrator · HackSpaceLabs" (the portal).

The photo must be allowed by the page's `img-src`. Serve it from your own origin where you can.

The menu has Profile, a "Dark mode" switch and Sign out. **Sign out fires a `hsl-signout` event** (it
bubbles), and the app does the signing out:

```js
document.querySelector('hsl-user-menu').addEventListener('hsl-signout', () => signOut())
```

In React, pass the attributes as props (strings; `apps={JSON.stringify(list)}`) and listen with a ref and
`addEventListener`. Give the element no children: it draws its own content. Choosing a link or Sign out
closes the menu; the Dark mode switch leaves it open.

**Keyboard.** Both widgets are WAI-ARIA menu buttons:
- On the button, Enter, Space or Down opens the menu on its first item, and Up opens it on its last.
- In the menu, the arrow keys move and wrap, Home and End jump to the ends, and Space or Enter chooses.
- Escape closes the menu and returns focus to its button; Tab or a click outside closes it.
- Opening one menu closes the other.

## Theme and the mark (`window.HSLSuite`)

| | |
|---|---|
| `HSLSuite.theme.get()` / `set('light' \| 'dark')` / `toggle()` | The choice is stored in `localStorage` under `hsl-suite-theme` and applied as `data-theme="dark"` on `<html>`. `suite.js` applies it as soon as it loads. Changes fire `hsl-themechange` on `document`. |
| `HSLSuite.theme.migrate(['old-key', …])` | Run once at start-up: copies the first old value that is `dark` or `light` into `hsl-suite-theme` (only if that is empty), and deletes the old keys. Old keys: `cpm-theme` (Switchyard), `tideline.theme`, `hsl-theme-v2` (Harbor Master; ignore the older `hsl-theme`), `slipway-theme`. |
| `HSLSuite.mark(size)` | The H mark as an `<svg>` element, for script-built pages. |

## Tokens

`tokens.css` holds Switchyard's values (PLAN.md appendix A in encondata/hsl-suite), plus the names
Tideline and Harbor Master use (`--ok-bg`, `--off`, `--off-bg`, `--radius-ctl`, `--radius-sm`,
`--shadow-2`, `--font`, `--font-brand`, `--mono`). `--accent` is `var(--accent-base, #0072b1)`, so an app
can offer a per-user accent by setting `--accent-base`.

Two light values differ from Switchyard's so that text passes WCAG AA (4.5:1):

| Token | Switchyard | Kit | Contrast now |
|---|---|---|---|
| `--accent-soft` | accent 11% on white | accent 8% on white | 4.66:1 for accent text on it |
| `--ok` | `#12805f` | `#0f7a5b` | 4.63:1 on `--ok-bg`, 5.31:1 on white |

`--faint` is below 4.5:1 on light surfaces. Use it for icons, borders and placeholders, not for text
people must read; the kit's own labels use `--muted`.

## Changes

- **0.1.2**
  - `<hsl-user-menu>` takes `avatar-url` (a photo) and `compact-below` (when the name hides).
  - Kit classes on a `<button>` (`hsl-auth-link`, `hsl-auth-button`, the menu items, the nav items, the
    user button) set their own background, border colour and text colour on hover, so an app's global
    `button:hover` rules no longer show through. Kit links (brand, nav items, switcher and menu rows,
    `hsl-auth-button`) don't underline on hover, whatever the app's `a:hover` says.
  - The sidebar's colour and edge run the full height of pages taller than the window.
  - Added `apple-touch-icon.png`.
  - The `detail` line's wording is set down above.

- **0.1.1**
  - The switcher no longer has an `apps()` method, which React 19 overwrote when `apps` was passed as a prop.
  - Choosing a menu item closes the menu, which matters in single-page apps.
  - Under 900 px the sidebar strip keeps its own height instead of stretching on short pages.
  - A wrapped `.hsl-auth-link` is centred.
  - Added `hsl-suite.d.ts`.
- **0.1.0** First release.
