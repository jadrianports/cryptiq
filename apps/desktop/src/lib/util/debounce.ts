// apps/desktop/src/lib/util/debounce.ts
//
// Standard generic debounce utility.
//
// Used for:
//   - Search input → query assignment (~100ms, D-TIMING / UI-04)
//   - Entry-field blur → auto-save (~500ms, D-TIMING / P4-11)
//
// No dependencies. No Math.random. clearTimeout-on-recall pattern.

/**
 * Debounce a function by `ms` milliseconds.
 *
 * Calling the returned function cancels any pending timer and restarts it.
 * The underlying `fn` is only called once the debounced function has NOT been
 * called for `ms` milliseconds.
 *
 * @param fn  The function to debounce.
 * @param ms  The debounce delay in milliseconds.
 * @returns A debounced wrapper around `fn`.
 *
 * @example
 * const setQuery = debounce((v: string) => { query = v; }, 100);
 * // in template: <input oninput={e => setQuery(e.currentTarget.value)} />
 */
export function debounce<T extends unknown[]>(
  fn: (...args: T) => void,
  ms: number,
): (...args: T) => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  return (...args: T): void => {
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(() => {
      fn(...args);
      timer = null;
    }, ms);
  };
}
