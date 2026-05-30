<!--
  VisualIdentity.svelte — the recurring brand texture (UI-10).

  A deterministic colored tile + initial derived from the entry's title. Same
  title → same hue, always, with no network and no Math.random (project rule):
  the hue is a stable hash of the label. Real-favicon fetch is a separate,
  off-by-default Setting (UI-10) the planner wires later; this tile is the
  always-available default identity.

  Design role: appears in every list row and at the head of the detail pane, so
  it must read as calm, not decorative-noisy — a soft two-stop wash in the
  entry's hue, never a flat saturated block.
-->
<script lang="ts" module>
  /**
   * Stable 32-bit FNV-1a hash → hue (0–359). Deterministic, CSPRNG-free; the
   * tile colour is presentational, not a secret. Exported so the planner can
   * reuse the exact derivation when wiring real entries.
   */
  export function hueFromLabel(label: string): number {
    let h = 0x811c9dc5;
    for (let i = 0; i < label.length; i++) {
      h ^= label.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0) % 360;
  }

  /** First visible character, uppercased; falls back to a neutral glyph. */
  export function initialFromLabel(label: string): string {
    const trimmed = label.trim();
    return trimmed ? trimmed[0]!.toUpperCase() : '•';
  }
</script>

<script lang="ts">
  type Props = {
    /** Entry title (or username) the identity is derived from. */
    label?: string;
    /** Edge length in px. 36 = list row, 44 = detail header. */
    size?: number;
  };
  let { label = '', size = 36 }: Props = $props();

  const hue = $derived(hueFromLabel(label));
  const initial = $derived(initialFromLabel(label));
  // Two-stop wash keeps chroma low (calm) while staying legible against white
  // initial text in both themes.
  const background = $derived(
    `linear-gradient(140deg, oklch(0.66 0.12 ${hue}), oklch(0.55 0.15 ${hue}))`,
  );
</script>

<span
  class="grid shrink-0 place-items-center rounded-cryptiq font-semibold text-white shadow-cryptiq-panel select-none"
  style="width:{size}px; height:{size}px; background:{background}; font-size:{Math.round(size * 0.42)}px;"
  aria-hidden="true"
>
  {initial}
</span>
