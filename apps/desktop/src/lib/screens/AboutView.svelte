<!--
  AboutView.svelte — About & Security screen (UI-14, P6-12).

  Content:
    - Threat model stated plainly: what Cryptiq DEFENDS against, what it does NOT.
    - Differentiators: calibrated KDF, per-entry presets, stale-password audit,
      needs-site-update flag, file-size padding, zero-account.
    - App version (read at runtime via getVersion() — Pitfall 5 defense, never hard-coded).
    - Repo link (opens browser via opener:allow-open-url).
    - v1 honesty disclosures: no code-signing (DIST-04) and no auto-updater (DIST-05).

  Navigation: go('settings') via the back button (Settings sub-view — P6-12).

  Token rules: cryptiq-* tokens only; no literal hex/oklch.
  No vault reads — purely static content + runtime version.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { go } from '../state/view.svelte';
  import { getVersion } from '@tauri-apps/api/app';
  import { openUrl } from '@tauri-apps/plugin-opener';

  type Props = {
    /**
     * Optional back callback. When provided (e.g. rendered as a sub-view inside
     * SettingsShell), calls this instead of go('settings') so the parent can update
     * its own showAbout local state. When omitted, falls back to go('settings').
     */
    onBack?: () => void;
  };

  let { onBack }: Props = $props();

  const REPO_URL = 'https://github.com/jadrianports/cryptiq';

  // Runtime version (never hard-coded — Pitfall 5 / About screen requirement).
  let appVersion = $state('—');

  onMount(async () => {
    try {
      appVersion = await getVersion();
    } catch {
      appVersion = 'unknown';
    }
  });

  async function openRepo(): Promise<void> {
    try {
      await openUrl(REPO_URL);
    } catch {
      // If opener fails (e.g. on a platform without a browser), silently ignore.
    }
  }

  function handleBack(): void {
    if (onBack) {
      onBack();
    } else {
      go('settings');
    }
  }
</script>

<div class="flex h-screen flex-col bg-cryptiq-bg">
  <!-- Page header with back navigation -->
  <header class="flex items-center gap-3 border-b border-cryptiq-border bg-cryptiq-surface px-6 py-4">
    <button
      type="button"
      onclick={handleBack}
      class="grid size-8 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      aria-label="Back to settings"
      title="Back to settings"
    >
      <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M19 12H5" /><path d="m12 5-7 7 7 7" />
      </svg>
    </button>
    <h1 class="text-title font-semibold text-cryptiq-fg">About &amp; Security</h1>
  </header>

  <!-- Content -->
  <div class="flex-1 overflow-y-auto px-6 py-6">
    <div class="mx-auto max-w-lg space-y-6">

      <!-- ── App identity + version ──────────────────────────────────────── -->
      <section aria-labelledby="about-identity-heading">
        <h2 id="about-identity-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          About Cryptiq
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <div class="flex items-center justify-between gap-4">
              <div>
                <p class="text-body font-semibold text-cryptiq-fg">Cryptiq</p>
                <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                  Local-first, self-built desktop password manager. No account, no server, no subscription.
                </p>
              </div>
              <span class="shrink-0 rounded-cryptiq border border-cryptiq-border px-2.5 py-1 text-meta font-mono text-cryptiq-fg-subtle">
                v{appVersion}
              </span>
            </div>

            <div class="border-t border-cryptiq-border pt-3">
              <button
                type="button"
                onclick={() => void openRepo()}
                class="flex items-center gap-1.5 text-meta text-cryptiq-accent transition-colors hover:opacity-80"
                aria-label="Open source repository on GitHub"
              >
                <svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                  <polyline points="15 3 21 3 21 9" />
                  <line x1="10" y1="14" x2="21" y2="3" />
                </svg>
                View source on GitHub
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- ── Threat model ────────────────────────────────────────────────── -->
      <section aria-labelledby="threat-model-heading">
        <h2 id="threat-model-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Threat Model
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-4">

            <!-- What Cryptiq defends against -->
            <div>
              <p class="mb-2 text-body font-semibold text-cryptiq-fg">Cryptiq defends against</p>
              <ul class="space-y-1.5 text-meta text-cryptiq-fg-subtle">
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Stolen vault file</strong> — the encrypted <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">.cryptiq</code> file is safe without your master password.</span>
                </li>
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Lost or stolen device</strong> — the vault is encrypted at rest; without the password it's unreadable.</span>
                </li>
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Untrusted sync host</strong> — syncing the vault file through an untrusted service is safe; the file is always encrypted before it leaves your machine.</span>
                </li>
              </ul>
            </div>

            <div class="border-t border-cryptiq-border"></div>

            <!-- What Cryptiq does NOT defend against -->
            <div>
              <p class="mb-2 text-body font-semibold text-cryptiq-fg">Cryptiq does NOT defend against</p>
              <ul class="space-y-1.5 text-meta text-cryptiq-fg-subtle">
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Compromised machine</strong> — if malware runs on your computer, it can read decrypted passwords while the vault is unlocked. No password manager can prevent this.</span>
                </li>
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Keyloggers</strong> — a keylogger captures your master password as you type it.</span>
                </li>
                <li class="flex items-start gap-2">
                  <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  <span><strong class="font-medium text-cryptiq-fg">Memory forensics while unlocked</strong> — while the vault is open, decrypted passwords exist in process memory and can be extracted by a privileged attacker.</span>
                </li>
              </ul>
            </div>

            <div class="border-t border-cryptiq-border"></div>

            <!-- Browser extension (v3.0) — honest both-sided threat model for the autofill bridge -->
            <div class="space-y-3">
              <p class="text-body font-semibold text-cryptiq-fg">Browser extension</p>

              <!-- What the extension bridge defends against -->
              <div>
                <p class="mb-2 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Defends against</p>
                <ul class="space-y-1.5 text-meta text-cryptiq-fg-subtle">
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">No keys or crypto in the browser</strong> — the extension is a thin client; the vault key never leaves the desktop app, so the browser can't be made to decrypt anything.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Wire-minimization</strong> — only the one secret you click crosses the bridge; site pickers receive metadata (names, usernames) only, never passwords.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Per-origin matching</strong> — entries are matched to a site by registrable domain (eTLD+1), not a loose URL substring.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Explicit association</strong> — a browser is answered only after a one-time approval; an unapproved extension gets nothing.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Click-to-fill, never auto-submit</strong> — a secret is handed over only on your explicit click, and the form is never submitted for you.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Cross-origin iframe refusal</strong> — a fill is refused inside an iframe whose origin doesn't match the page you're on.</span>
                  </li>
                </ul>
              </div>

              <div class="border-t border-cryptiq-border"></div>

              <!-- What the extension bridge does NOT defend against -->
              <div>
                <p class="mb-2 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Does NOT defend against</p>
                <ul class="space-y-1.5 text-meta text-cryptiq-fg-subtle">
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">The page you fill into</strong> — While the app is unlocked and an extension is associated, clicking Fill hands exactly one secret to the current page.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Compromised OS or browser</strong> — malware or a hostile browser can read a filled secret, the same as with any password manager.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">A malicious other extension</strong> — another extension installed in the same browser can tamper with the page you fill into.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Page-level XSS</strong> — the extension can't read your vault, but a secret you fill does land in that page's DOM, where injected script can reach it.</span>
                  </li>
                  <li class="flex items-start gap-2">
                    <svg class="mt-0.5 size-3.5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span><strong class="font-medium text-cryptiq-fg">Residual DOM-clickjacking</strong> — a page that manipulates its own layout can still attempt to trick a click; the extension reduces but cannot fully eliminate this.</span>
                  </li>
                </ul>
              </div>

              <p class="text-meta text-cryptiq-fg-subtle">
                Browser permissions:
                <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">nativeMessaging</code>,
                <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">storage</code>,
                <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">activeTab</code>,
                <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">scripting</code>,
                <code class="rounded bg-cryptiq-surface-2 px-1 text-xs">contextMenus</code>
                — each traced to a live feature in the extension's install guide.
              </p>
            </div>

          </div>
        </div>
      </section>

      <!-- ── What makes Cryptiq different ───────────────────────────────── -->
      <section aria-labelledby="differentiators-heading">
        <h2 id="differentiators-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          What makes it different
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <ul class="divide-y divide-cryptiq-border">
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">Calibrated KDF</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Argon2id is tuned to your machine's memory at vault creation — not a fixed weak preset. The harder it is to derive the key, the harder offline attacks are.
              </p>
            </li>
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">Per-entry generator presets</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Each entry can save its own password-generator settings (length, character set, passphrase) so re-generating the right kind of password is always one click.
              </p>
            </li>
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">Stale-password audit</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                The Health view flags passwords that haven't changed in over a year (configurable), so you can catch forgotten stale credentials before an attacker does.
              </p>
            </li>
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">Needs-site-update flag</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Mark any entry "site changed password requirements" to remind yourself to regenerate it — surfaced in the Health view.
              </p>
            </li>
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">File-size padding</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                The encrypted vault file is padded to a power-of-two size. Syncing doesn't leak "they added 3 entries today" via file size alone.
              </p>
            </li>
            <li class="px-4 py-3">
              <p class="text-body font-medium text-cryptiq-fg">Zero account</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                No sign-up, no servers, no subscription. Your passwords are a file on your machine. You can audit exactly what happens to them.
              </p>
            </li>
          </ul>
        </div>
      </section>

      <!-- ── v1 honesty disclosures ──────────────────────────────────────── -->
      <section aria-labelledby="v1-disclosures-heading">
        <h2 id="v1-disclosures-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          v1 Disclosures
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="divide-y divide-cryptiq-border">

            <!-- DIST-04: no code-signing -->
            <div class="flex items-start gap-3 px-4 py-3.5">
              <svg class="mt-0.5 size-4 shrink-0 text-cryptiq-fg-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <div>
                <p class="text-body font-medium text-cryptiq-fg">No code-signing in v1</p>
                <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                  Installers show an "unidentified developer" warning on macOS and a SmartScreen alert on Windows. This is expected — code-signing is deferred to v1.5. The source is open and auditable.
                </p>
              </div>
            </div>

            <!-- DIST-05: no auto-updater -->
            <div class="flex items-start gap-3 px-4 py-3.5">
              <svg class="mt-0.5 size-4 shrink-0 text-cryptiq-fg-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <div>
                <p class="text-body font-medium text-cryptiq-fg">No auto-updater in v1</p>
                <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                  There is no automatic update mechanism. Check the repository for new releases. Auto-update is deferred to v1.5.
                </p>
              </div>
            </div>

          </div>
        </div>
      </section>

    </div>
  </div>
</div>
