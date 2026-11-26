// TypeScript declarations for the HSL Suite kit (suite.js is plain JavaScript). Synced with the kit:
// never edit an app's copy. The JSX part is for React apps; other TypeScript consumers can ignore it.
import type { DetailedHTMLProps, HTMLAttributes } from 'react'

type HslTheme = 'light' | 'dark'

declare global {
  interface Window {
    HSLSuite: {
      version: string
      theme: {
        /** The localStorage key: "hsl-suite-theme". */
        key: string
        get(): HslTheme
        set(theme: HslTheme): HslTheme
        toggle(): HslTheme
        /** Moves an app's old theme keys to the shared one, once. */
        migrate(oldKeys: string[]): HslTheme
      }
      /** The H mark as an <svg> element, `size` pixels wide. */
      mark(size?: number): SVGSVGElement
    }
  }
  interface DocumentEventMap {
    'hsl-themechange': CustomEvent<{ theme: HslTheme }>
  }
}

type Base = DetailedHTMLProps<HTMLAttributes<HTMLElement>, HTMLElement>

/** Attributes are strings: pass `apps` as JSON.stringify([...]). The element draws its own children. */
export interface HslAppSwitcherAttributes extends Base {
  apps?: string
  current?: string
  label?: string
}

export interface HslUserMenuAttributes extends Base {
  name?: string
  detail?: string
  'profile-url'?: string
  'profile-label'?: string
  'signout-label'?: string
}

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'hsl-app-switcher': HslAppSwitcherAttributes
      'hsl-user-menu': HslUserMenuAttributes
    }
  }
}
