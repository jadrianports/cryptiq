# Cryptiq Design Reference — Phase 4 (Core UI)

These components are the **single design source of truth** for Phase 4 (decision
**P4-01**). They establish Cryptiq's visual language in real Svelte 5 + Tailwind v4
code; downstream GSD plans implement the remaining screens **against** them. There
is deliberately **no `UI-SPEC.md`** — the code + tokens are the contract.

> Produced by the `frontend-design` skill, not `/gsd-ui-phase` (P4-01 forbids a
> second, competing design contract).

## Aesthetic (P4-02)

Calm, serious, slightly-premium security vault — Proton Pass / 1Password lineage.
Restraint over flourish. The memorable quality is *quiet confidence*: generous
spacing, hairline borders, one reserved accent, soft low-spread elevation, and
monospace for every secret. Light + dark, **system-driven** (`prefers-color-scheme`,
no manual toggle this phase — P4-03).

## Tokens — `src/app.css` (`@theme`)

Never write a literal color/size in a component. Use a token (utility or `var()`).
Dark is the **same variables overridden** in a media query (P4-03 token swap), so
`bg-cryptiq-*` / `text-cryptiq-*` utilities re-resolve automatically — no
per-component `dark:` work.

| Group | Tokens |
|---|---|
| Surfaces (60/30) | `bg` · `surface` · `surface-2` · `hover` · `selected` |
| Text | `fg` · `fg-muted` · `fg-subtle` |
| Lines | `border` · `border-strong` |
| Accent (10%, reserved) | `accent` · `accent-hover` · `accent-fg` · `ring` |
| Semantic | `success` · `attention` (needs-update) · `danger` (+ `-fg`/`-surface`/`-border`) |
| Type | sizes `text-meta`/`body`/`emphasis`/`title`/`display`; weights regular/medium/semibold |
| Shape | `rounded-cryptiq` (8) · `rounded-cryptiq-lg` (14) · `shadow-cryptiq-panel` · `-popover` |
| Fonts | `--font-sans` (Inter) · `--font-mono` (secrets) |

**Accent is reserved** for: primary CTA, selected nav/row marker, focus ring,
links, active toggles, favorite star, strength=excellent. Nothing else earns it.

Type scale: **12 / 14 / 16 / 20 / 28** (3 weights). Spacing: multiples of 4
(`gap-1.5` 6px is the one allowed sub-step for icon clusters).

## The four canonical components

| File | Role | Locked contract it encodes |
|---|---|---|
| `EntryListRow.svelte` | Center-list row | UI-02 list, UI-09 needs-update dot, favorites pinned, hover/selected |
| `EntryDetail.svelte` | Right-pane detail/edit | UI-05 inline edit, UI-06 copy, UI-08 inline generator, UI-12 saved toast, P4-11 auto-save, P4-12 popover, P4-13 reveal |
| `FirstRunStep.svelte` | Wizard step shell | P4-07 stepped + progress, P4-08 danger panel + required-ack gate |
| `GeneratorSurface.svelte` | Generator (popover + standalone) | P4-12 inline popover, GEN-05/06 standalone + save |

`VisualIdentity.svelte` is the shared deterministic identity tile (UI-10);
`_reference/DesignGallery.svelte` is a preview harness (not shipped).

## Interaction patterns to carry forward

- **Auto-save on blur + "Saved" toast** — no Save button (P4-11/UI-12).
- **Password reveal** — press-and-hold to peek (re-masks on release) **and** a
  click toggle for accessibility (P4-13). Modeled as `heldReveal || toggledReveal`.
- **Inline generator** — popover anchored to the password field; "Use" fills it
  (P4-12). Same `GeneratorSurface` powers the standalone screen.
- **Danger gate** — required acknowledgment checkbox arms Continue; not
  type-to-confirm, not a timed modal (P4-08).

## Planner follow-ups (NOT done here — by design)

These components are **prop-driven references**. Wiring is the planner's job:

1. **Wire to `VaultSession`** — replace local `$state` seeds with session CRUD →
   `save()` (mutex + FNV-1a dedup already handle correctness). Filling a generated
   password must push the old value to `passwordHistory` via the core change path (ENTRY-07).
2. **Real generation** — `GeneratorSurface` ships a **DEMO LCG** for believable
   output without `Math.random`. Production generates via `@cryptiq/core`
   (`randombytes_uniform` + Fisher–Yates) and reads bits from `estimateEntropyBits`.
3. **Real copy** — per-field copy is visual-only here; wire through the Tauri
   clipboard-manager **write** path (never `allow-read-text` — CLAUDE.md ban).
4. **Open URL** — emits `onOpenUrl`; wire to a capability-scoped opener (literal-path
   capability discipline, SEC-11/12).
5. **Virtualization** — `EntryListRow` is render-ready; the windowing technique for
   5,000+ rows (UI-03) is the planner's call (prefer hand-rolled per minimal-deps).
6. **Font bundling** — Inter is *named* but not bundled (currently falls back to
   system-ui). Offline + strict CSP means **no CDN** — self-host a woff2 (Inter +
   a mono) or accept the system stack. Decide before shipping.
7. **View shell** — `App.svelte` keeps the `sodium.ready` gate; its body becomes
   the rune view-state enum (P4-06) hosting the sidebar/list/detail seen in the gallery.

## Preview

Temporarily render the gallery from `App.svelte` (behind the sodium gate):

```svelte
<script lang="ts">import DesignGallery from './lib/components/_reference/DesignGallery.svelte';</script>
<DesignGallery />
```

```bash
pnpm --filter @cryptiq/desktop dev
```

Toggle your OS light/dark to verify the token swap. Revert `App.svelte` before committing.
