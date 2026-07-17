# CI Self-Test — Break-Patches (CI-06 / D-05)

**The milestone discipline this directory encodes: a gate is not landed until a RED-RUN URL is
recorded.** CI was green-looking and structurally dead (silently skipping the sidecar-dependent
gates) for four milestones before Phase 33. Green tests and a green lint suite are not proof a
gate can actually fail — only a live GitHub Actions run that goes RED, on purpose, is proof.

**Status: ritual COMPLETE (2026-07-14).** All 10 patches were run against a green `main`. 9 gates
are red-run-proven with verified step attribution. 1 (`clean-clone-smoke.patch`, CI-12) exposed a
**fake gate** on its first attempt — see below, it is the single most instructive result in this
directory. 1 (`cargo-cross-target.patch`, CI-02) is honestly recorded as currently unexercisable,
not faked. The full ledger with every URL lives in
`../../.planning/phases/33-ci-resurrection-build-integrity-gate/33-VERIFICATION.md`.

This was a **one-time manual ritual** (D-05), not an automated recurring meta-job. An automated
"break something every night and confirm it's still red" job is itself fragile, self-modifying CI
that burns minutes forever to re-prove a property that doesn't change. Instead: each gate got a
committed `.patch` file that breaks it on purpose. The `.patch` files remain **living, re-runnable
artifacts** — if the pipeline is ever restructured, re-run the same ritual against the new shape
and confirm the patch (or an updated version of it) still turns the gate red.

## Green baseline (the anchor)

A red run is only meaningful against a known-green baseline — otherwise a red run proves nothing,
since the pipeline might be red for unrelated reasons.

| Run | Result | Notes |
|---|---|---|
| [29321062089](https://github.com/jadrianports/cryptiq/actions/runs/29321062089) | green | First fully-green CI in four milestones. `rust` / `node` / `build (windows-2025)` / `CI Required` all passed. |
| [29322705945](https://github.com/jadrianports/cryptiq/actions/runs/29322705945) | green | Re-verified green after the CI-12 fake-gate fix (`c0599d7`). |

## Gate ledger (final — red-run-proven)

| # | Gate (requirement) | Patch | Red-run URL | Failed at (attribution verified) |
|---|---|---|---|---|
| 1 | CI-01 sidecar staging precedes `cargo check` | `sidecar.patch` | [29321805977](https://github.com/jadrianports/cryptiq/actions/runs/29321805977) | `rust` → cargo check (Tauri), missing `externalBin`; also independently caught by the sidecar-staging lint |
| 2 | CI-02 `--target` cross-compile output path | `cargo-cross-target.patch` | **N/A — unexercisable, not fabricated** | See "Honest gap: CI-02" below |
| 3 | CI-03/CI-05 version-consistency (byte-equality across 4 files) | `version-consistency.patch` | [29321819124](https://github.com/jadrianports/cryptiq/actions/runs/29321819124) | `node` → Custom lint — version consistency |
| 4 | CI-11 `msi` dropped from `bundle.targets` | `msi-drop.patch` | [29321822883](https://github.com/jadrianports/cryptiq/actions/runs/29321822883) | `node` → Custom lint — version consistency (33-01 folded the MSI gate into it) |
| 5 | CI-04 sidecar-staging ORDER lint | `sidecar-staging-lint.patch` | [29321826599](https://github.com/jadrianports/cryptiq/actions/runs/29321826599) | `node` → Custom lint — sidecar staging order |
| 6 | CI-10 Vite key-leak guard (envPrefix) | `vite-key-leak.patch` | [29321829450](https://github.com/jadrianports/cryptiq/actions/runs/29321829450) | Fired at BOTH stages: `node` → static lint, AND `build` → post-build dist grep |
| 7 | CI-09 workspace-scripts (`typecheck` script presence) | `typecheck-skip.patch` | [29321833623](https://github.com/jadrianports/cryptiq/actions/runs/29321833623) | `node` → Custom lint — workspace scripts |
| 8 | CI-07 `ci-required` aggregator (skip = fail) | `ci-required-aggregator.patch` | [29321812489](https://github.com/jadrianports/cryptiq/actions/runs/29321812489) | `node` **skipped**, `rust`+`build` succeeded, `CI Required` still **RED** |
| 9 | CI-08 pwsh non-final-line exit propagation | `pwsh-exit-propagation.patch` | [29321809530](https://github.com/jadrianports/cryptiq/actions/runs/29321809530) | `rust` → `NativeCommandExitException` at **Line 3** (the non-final `cargo build`); the trailing `Write-Host` never ran |
| 10 | CI-12 clean-clone `pnpm build` (root build routes through staging) | `clean-clone-smoke.patch` | [29322716256](https://github.com/jadrianports/cryptiq/actions/runs/29322716256) | `build` → `pnpm build`. First attempt came back GREEN — see "The fake gate" below. |
| 11 | HARD-01 `secrets` job / gitleaks custom minisign rule | `gitleaks-minisign.patch` | [29359090838](https://github.com/jadrianports/cryptiq/actions/runs/29359090838) | `secrets` → gitleaks scan (incremental). Log names the CUSTOM rules: `RuleID: tauri-minisign-secret-key` + `-body`, `Secret: REDACTED`. `rust`/`node`/`build` all GREEN in the same run. |
| 12 | HARD-02a `cargo audit (Tauri)` — planted yanked dep in `apps/desktop/src-tauri` | `cargo-audit-tauri.patch` | [29357301109](https://github.com/jadrianports/cryptiq/actions/runs/29357301109) | `rust` → **`cargo audit (Tauri)`** (yanked `once_cell 1.20.0`) |
| 13 | HARD-02b `cargo audit (native-host)` — planted yanked dep in `apps/native-host` | `cargo-audit-nativehost.patch` | [29357285887](https://github.com/jadrianports/cryptiq/actions/runs/29357285887) | `rust` → **`cargo audit (native-host)`** — the historically-blind workspace, failing at its OWN named step |
| 14 | HARD-04 ESLint over an `apps/extension/**/*.svelte` `{@html}` violation | `eslint-extension-svelte.patch` | [29357276756](https://github.com/jadrianports/cryptiq/actions/runs/29357276756) | `node` → **ESLint** (`svelte/no-at-html-tags`) |
| 15 | HARD-06 `pnpm lint:custom` still NAMES the failing lint after the DRY collapse | `version-consistency.patch` (reused) | [29357290223](https://github.com/jadrianports/cryptiq/actions/runs/29357290223) | `node` → **Custom lints (auto-discovered)**; log reads `✖ 1/11 custom lint(s) failed: lint-version-consistency.mjs` — legibility survived |
| 16 | HARD-03 CodeQL `javascript-typescript` — planted `eval(location.hash)` code-injection sink | `codeql-jsts.patch` | [29365157862](https://github.com/jadrianports/cryptiq/actions/runs/29365157862) | `CodeQL Gate` RED — alert `js/code-injection` **[critical]** @ `codeql-jsts-sink.mjs:14` |
| 17 | HARD-03 CodeQL `actions` — planted `github.event.comment.body` expression-injection sink in a scratch workflow | `codeql-actions.patch` | [29365149841](https://github.com/jadrianports/cryptiq/actions/runs/29365149841) | `CodeQL Gate` RED — alert `actions/cache-poisoning/code-injection` **[high]** @ `ci-selftest-actions-scratch.yml:26` |
| 18 | HARD-03 CodeQL `rust` — planted null-pointer-deref sink in `apps/desktop/src-tauri` | `codeql-rust-tauri.patch` | [29365153581](https://github.com/jadrianports/cryptiq/actions/runs/29365153581) | `CodeQL Gate` RED — alert `rust/access-invalid-pointer` **[high]** @ `apps/desktop/src-tauri/src/codeql_selftest.rs:15` |
| 19 | HARD-03 CodeQL `rust` — planted null-pointer-deref sink in `apps/native-host` (the historically-blind workspace) | `codeql-rust-nativehost.patch` | [29365145847](https://github.com/jadrianports/cryptiq/actions/runs/29365145847) | `CodeQL Gate` RED — alert `rust/access-invalid-pointer` **[high]** @ **`apps/native-host/src/codeql_selftest.rs:15`** — proves the extractor walks the 2nd workspace (OQ#2 answered; no 2nd matrix entry needed) |
| 20 | HARD-05 concurrency `cancel-in-progress` on ci.yml (never release.yml) | 2 rapid pushes to `selftest/hard05-concurrency` | [29365641308](https://github.com/jadrianports/cryptiq/actions/runs/29365641308) | run **cancelled** by the superseding push ([29365671150](https://github.com/jadrianports/cryptiq/actions/runs/29365671150)); release.yml has no concurrency block, so a tag build is never cancelled |
| 21 | HARD-05 warm rust-cache speedup | natural experiment (lockfile = cache key) | cold [29357246295](https://github.com/jadrianports/cryptiq/actions/runs/29357246295) vs warm [29359083518](https://github.com/jadrianports/cryptiq/actions/runs/29359083518) | `rust` job **11m17s cold** (commit `41c0fad` changed Cargo.lock) → **3m07s warm** (unchanged lockfile) — ~3.5× |
| 22 | REL-03 install-smoke **post-uninstall** read-back (orphan registry keys survive uninstall) | `unregister-red.patch` | **pending — authored, not yet red-run** | See "Honest gap: REL-03 post-uninstall" below |
| 23 | UPD-01 tampered-artifact-byte signature-verification proof | `updater-signature.patch` | **pending — authored, locally pre-flighted, not yet red-run** | See "Phase 36-04 local pre-flight" below |
| 24 | UPD-02 explicit anti-rollback `version_comparator` lint | `updater-comparator.patch` | **pending — authored, locally pre-flighted, not yet red-run** | See "Phase 36-04 local pre-flight" below |
| 25 | UPD-04 capability/CSP byte-identity golden-snapshot lint | `updater-capability-diff.patch` | **pending — authored, locally pre-flighted, not yet red-run** | See "Phase 36-04 local pre-flight" below |
| 26 | D-11 rollback mitigation fail-closed on a corrupt high-water store | `updater-rollback.patch` | **pending — authored, locally pre-flighted, not yet red-run** | See "Phase 36-09 local pre-flight" below |
| 27 | DEBT-01 consent guard fail-direction (fail-OPEN reintroduces W-1) | `updater-consent-guard.patch` | **pending — authored, locally pre-flighted, not yet red-run** | See "Phase 36-11 local pre-flight" below |

**Green-on-real:** [29359083518](https://github.com/jadrianports/cryptiq/actions/runs/29359083518) — main, every job green (`rust`, `node`, `build`, `secrets`, `CI Required`) at the same commit these breaks were forked from.

Attribution was checked on every row — the gate had to fail at *its own step*, not incidentally.

### Phase 34's fake gates: the ritual earned its keep FOUR more times

Config-text review would have shipped every one of these. Each looked correct; none worked.

1. **gitleaks never executed.** `Expand-Archive -DestinationPath .` unpacked the zip's own
   `LICENSE` into the repo root, colliding with ours. The `secrets` job was red on *every*
   branch having never scanned a byte. Red = "working", if you only look at the colour.
   `gitleaks-full.yml` had the identical bug, so the weekly sweep was dead on arrival too.
2. **`cargo audit (native-host)` never ran.** Steps are sequential; the Tauri audit was failing
   (on *real* pre-existing advisories), so the native-host step was **skipped every time** —
   leaving the historically-blind workspace unaudited *precisely when something was already
   wrong*. The four-milestone blind spot, faithfully reproduced inside its own fix. `if: always()`.
3. **gitleaks flagged our own break-patch.** With those fixed, `secrets` still went red on
   branches planting no secret: a new branch has an all-zeros `event.before`, so the scan falls
   back to full history — which contains `gitleaks-minisign.patch` itself. HARD-01's "red" was
   attributable to the patch file, not the planted key. Allowlisted `*.patch` (the `__fixtures__/`
   path it plants into is deliberately NOT allowlisted, or the gate would prove nothing).
4. **CodeQL passed GREEN on a planted CRITICAL vuln** — the worst of the four, because it hid
   inside the security tool itself. `codeql-action/analyze` uploads alerts to the Security tab
   and exits 0; a planted `js/code-injection` (critical) left the workflow green (run 29361233154).
   Fix: a `codeql-gate` job that reads back the alerts CodeQL filed for the just-analyzed SHA and
   fails on any open critical/high — so a push actually reds. Its own green-on-real
   ([29362564405](https://github.com/jadrianports/cryptiq/actions/runs/29362564405)) only came
   after a real pre-existing high alert in `pairing.rs` (an FFI-provenance false positive CodeQL
   cannot model) was reviewed and dismissed with justification.

Also worth recording: the executor's first Rust CodeQL patches used `rust/cleartext-logging`,
which produced **zero** alerts in either workspace — that query is not in the default suite. Had
we trusted "the patch is a vuln" without observing detection, OQ#2 (does the extractor walk
native-host?) would have stayed silently unanswered. Rewritten to `rust/access-invalid-pointer`
(known-in-suite: it fired on real `pairing.rs`), both workspaces then went red at their own paths.

Rows 11-21 above are the *post-fix* runs. The lesson is the same one CI-12 taught, now four times
over: **a red run is not proof a gate works — only a red run that fails at the right step, paired
with a green-on-real, is.** Colour alone is what "green but blind" looks like in the mirror.

## The fake gate — the ritual's most valuable catch (CI-12)

`clean-clone-smoke.patch` reverts the root build script from `tauri:build` (stages the sidecar)
back to bare `tauri build` (does not). Pushed expecting RED. **CI came back GREEN:**

- fake-green run: [29321815825](https://github.com/jadrianports/cryptiq/actions/runs/29321815825)

**Cause:** the `build` job pre-staged the sidecar in its own explicit step, so `pnpm build` never
had to stage it itself. The root build script's correctness — the exact thing CI-12 asserts — was
completely unobservable in CI. A user's clean clone would still have broken; CI would never have
known. The gate was protecting nothing.

**Fix (`c0599d7`):** removed the redundant pre-staging from the `build` job. `pnpm build` now
resolves to `pnpm -r build && tauri:build`, and `tauri:build` is `pnpm stage:nmhost && tauri
build` — it stages its own sidecar, exactly as a user's clean clone does.

**Re-verified:** [29322716256](https://github.com/jadrianports/cryptiq/actions/runs/29322716256) → RED at `pnpm build`. The gate is now real.

Deliberately unchanged: `rust` keeps explicit staging (its `cargo check` resolves `externalBin`
with no `tauri:build` wrapper to stage for it — CI-01), and `release.yml` keeps explicit staging
(it drives `tauri-action` directly, never routing through `pnpm build`).

**Without the red-run ritual, this gate would have shipped as protection that protects nothing.**
That is the entire argument for D-05, demonstrated on its first outing. If you only read one
section of this README, read this one.

## Honest gap: REL-03 post-uninstall (`unregister-red.patch`) — authored, red-run pending

Phase 35's `install-smoke-red.patch` breaks only the **register** path (a wrong `(default)`
registry value), proving `scripts/ci/install-smoke.ps1:42-50`. Nothing exercised lines 65-69 —
the **post-uninstall orphan assertions**. Since `hooks.nsh`'s PREUNINSTALL hook cannot itself
surface a failure the user will act on, those four lines are the *only* thing in the entire
pipeline that can catch a broken unregister, and they shipped unproven — exactly the shape of
gate this directory exists to disallow (WR-04, Phase 35 review).

`unregister-red.patch` closes that: it drops both browser registry keys from the removal set,
leaving them **orphaned while the script still exits 0 and still prints a success line** — so
the installer's exit code and the NSIS hook both stay happy, and only the post-uninstall
read-back can catch it. Same shape as `install-smoke-red.patch`'s "succeeds but writes the
wrong value" (the DIST-02 lesson), applied to the uninstall half.

**Local pre-flight (done, on this machine).** Not a substitute for a red run — recorded per the
"proven locally ≠ proven in CI" discipline above:

- `git apply --check` passes; apply → `git apply -R` leaves `git status --short` clean.
- Running the **patched** script with its two path expressions redirected to a throwaway dir +
  test registry hive (shipped control flow otherwise intact): **exit code 0**, prints
  `Unregistered com.cryptiq.bridge (1 removed, 0 already absent)`, and leaves **2 orphaned
  registry keys**, with the manifest correctly removed (the patch is surgical — it breaks only
  the registry half). That is precisely the silent failure lines 65-69 must catch.
- The developer's real `com.cryptiq.bridge` registration was deliberately not touched.

**Still required:** the live red run. This gate needs a real `windows-2025` runner to install
the built `*-setup.exe` and uninstall it, which local pre-flight cannot substitute for. Run the
standard ritual below on a `ci-selftest/unregister-red` branch, confirm `build` → **Install-smoke**
is RED and names the orphan key (`install-smoke: orphan registry key survived uninstall: ...`),
then replace row 22's "pending" with the URL here and in `35-VERIFICATION.md`. **Until that URL
exists, REL-03's post-uninstall half is delivered-in-code but not red-run-verified, and must not
be represented otherwise.**

## Honest gap: CI-02 (cross-target staging) — currently unexercisable

`cargo-cross-target.patch` breaks the `--target X → target/X/release/` branch in
`copy-nmhost-binary.mjs`. With the macOS build legs dropped from `ci.yml` and `release.yml`
(`5ecf8ae` — macOS hasn't compiled since Phase 14, see the native-host bridge's ungated Windows
named-pipe usage), **no CI leg passes `--target` at all**, so the patch is inert and cannot
produce a red run today. No URL was manufactured for it.

The code path *was* proven locally (33-03): verified with the host-matching triple
`x86_64-pc-windows-msvc`, confirming cargo still emits to `target/<triple>/release/` as expected.
The gate exists for the macOS restore path — **re-run this patch against a live red run as soon
as a macOS build leg returns to the pipeline** (see
`.planning/todos/pending/macos-native-host-bridge.md`). Until then, CI-02 is delivered-in-code
but not red-run-verified, and should not be represented otherwise.

## Bugs this pipeline found on its way to a green baseline

None introduced by Phase 33 — all were invisible *because the gates were never running*:

1. **`wxt prepare` never ran on install** (fixed, `a57ca3c`). `.npmrc`'s `ignore-scripts=true`
   (deliberate supply-chain hardening) also suppressed the extension's `postinstall: wxt prepare`,
   so `.wxt/tsconfig.json` existed only on machines that had happened to run a dev build. Fixed by
   making `typecheck` self-sufficient rather than re-enabling install scripts.
2. **4 dead typecheck errors in `packages/core`** (fixed, `45c9825` / `98b304f` / `11927f5`). One
   — `pairingCode.test.ts:153` — was a test whose assertion sat inside an always-true guard; had
   the guard ever flipped, the test would have passed with zero assertions.
3. **macOS has not compiled since Phase 14** (scoped out, `5ecf8ae`). The v3.0 extension bridge
   imports `tokio::net::windows::named_pipe` ungated on both sides, so `cargo build --target
   *-apple-darwin` fails with E0433. There is no macOS dev machine (CLAUDE.md), so CI was the only
   thing that could ever have caught this, and CI was dead. Build legs removed from `ci.yml` +
   `release.yml` in lockstep; macOS *source* support left intact and reversible.

## The ritual (per gate, as actually executed)

```bash
# 1. Branch from current main
git checkout -b ci-selftest/<gate> main

# 2. Apply the break-patch and commit it
git apply scripts/ci-selftest/<gate>.patch
git add -A
git commit -m "test(ci-selftest): deliberately break <gate> (CI-06 red-run capture)"

# 3. Push the scratch branch (never a v* tag — that fires the release pipeline)
git push origin ci-selftest/<gate>

# 4. Open https://github.com/jadrianports/cryptiq/actions, find the run for this push,
#    confirm the INTENDED gate step (and, for the aggregator gate, `ci-required` itself)
#    is RED. Copy the failing run's URL.

# 5. Record the failing-run URL in ../../.planning/phases/33-ci-resurrection-build-integrity-gate/
#    33-VERIFICATION.md, in that gate's Red-run column.

# 6. Revert: delete the scratch branch, confirm the same commit content reverted is
#    GREEN on a clean branch, and record that green-confirm URL too.
git push origin --delete ci-selftest/<gate>
git branch -D ci-selftest/<gate>
```

All 10 scratch branches created during the 2026-07-14 ritual have been deleted; `main` carries
none of the break-patch commits. Only the `.patch` files themselves (and this README plus
`33-VERIFICATION.md`) are committed artifacts.

**Re-run this ritual** whenever the pipeline shape changes materially (a job is renamed, split, or
its steps reordered) — re-apply the relevant `.patch` (updating it first if the target file moved)
and confirm it still turns the gate red. This is exactly the situation that will make CI-02 live
again once a macOS leg returns.

## Local pre-flight (available for the 5 lint-checkable gates)

Five of these ten patches assert a **local** Node-script lint, so they can be (and were) proven
locally without waiting for CI, in addition to the live-CI ritual above:

```bash
git apply scripts/ci-selftest/<gate>.patch
node scripts/lint/<the-lint-it-breaks>.mjs   # must exit 1
git checkout -- <the file the patch touched>  # revert
node scripts/lint/<the-lint-it-breaks>.mjs   # must exit 0 again
git status --short                            # must be empty
```

The other five patches touch behavior only a real `windows-2025`/`macos-latest` GitHub-hosted
runner can exercise (a real `cargo check` externalBin resolution, a real cross-compiled `cargo
build` output path, real `needs.*.result` semantics, real pwsh 7.6.3 exit-code propagation, a real
clean-clone `pnpm install && pnpm build`) — those were genuinely CI-only, proven only via the live
ritual above.

## Phase 34 local pre-flight: `eslint-extension-svelte.patch` (HARD-04)

Unlike the five `scripts/lint/lint-*.mjs` gates above, this patch's violation is checkable by
running ESLint itself (no custom lint script involved), so it was pre-flighted locally exactly
like them, on this machine, before authoring the placeholder ledger row:

```bash
git apply scripts/ci-selftest/eslint-extension-svelte.patch
pnpm exec eslint .   # exit 1 — confirmed: svelte/no-at-html-tags at Popup.svelte:754
git checkout -- apps/extension/entrypoints/popup/Popup.svelte   # revert
pnpm exec eslint .   # exit 0 — confirmed, clean
```

`gitleaks-minisign.patch`, `cargo-audit-tauri.patch`, and `cargo-audit-nativehost.patch` have
**no local pre-flight** — gitleaks isn't installed on this machine (CI downloads it fresh) and
`cargo audit` isn't installed locally either (CI installs it via `taiki-e/install-action`). Their
only proof is the live CI red-run in Task 2 below. Both cargo-audit patches WERE locally verified
to still `cargo check` clean (the planted yanked dependency, `once_cell = "1"` pinned to the
yanked `1.20.0`, compiles fine in both workspaces) — this isolates the eventual red to the
`cargo audit (Tauri)` / `cargo audit (native-host)` step specifically, not a build failure.
(An earlier attempt using a yanked `cfg-if 1.0.2` in `apps/desktop/src-tauri` was discarded
after it broke `curve25519-dalek`'s compilation outright — see `once_cell`'s selection instead,
chosen for being a genuinely unrelated, freshly-added leaf dependency in both workspaces.)

## The sharpest gate: `pwsh-exit-propagation.patch` (CI-08)

`ci.yml` is one-command-per-step by construction (the tiered-job rewrite, D-01, is itself the
structural fix for this bug class) — there is no genuinely multi-line pwsh `run:` block anywhere
in the pipeline for this bug class to hide in normally. So this patch **added** a temporary
multi-line pwsh step to the end of the `rust` job:

```yaml
- name: "CI-08 selftest: multi-line pwsh block, non-final cargo build failure must propagate"
  shell: pwsh
  run: |
    $PSNativeCommandUseErrorActionPreference = $true
    cargo build --release --manifest-path apps/native-host/Cargo.toml --this-flag-does-not-exist
    Write-Host "UNREACHABLE if propagation works — the cargo build above must have failed the step"
```

Line 1 sets the guard. Line 2 is a genuinely failing `cargo build` (an unrecognized CLI flag makes
`cargo` itself exit non-zero). Line 3 is a command that would otherwise succeed and, under
GitHub's pre-fix default behavior (only the LAST command's `$LASTEXITCODE` is checked), would have
made the whole step report green even though line 2 failed.

**The live red run confirmed:** the step reported RED, with `NativeCommandExitException` raised at
line 3's attempted execution — the cargo build failure at line 2 (not the last line) is what
aborted the step. See ledger row 9 above for the URL.

**This step is selftest-only scaffolding.** It lived only on the scratch branch
`ci-selftest/pwsh-exit-propagation`, was never merged to `main`, and that branch has since been
deleted. `main`'s `ci.yml` carries no "CI-08 selftest" step — verify with
`grep -n "CI-08 selftest" .github/workflows/ci.yml` (expect no match).

## Special ritual note: `ci-required-aggregator.patch` (CI-07)

This patch adds `if: false` to the `node` job, forcing it to be unconditionally skipped (not
failed) on every run. The live-CI red run confirmed both halves of the proof:
1. The `node` job itself showed as `Skipped` in the Actions UI.
2. The `ci-required` job (`needs: [rust, node, build]`, `if: always()`) still executed and then
   **failed**, because its own `contains(needs.*.result, 'skipped')` check caught the skip. A job
   merely being skipped is not automatically "red" in every GitHub UI surface — `ci-required`
   failing is the proof that closes exactly that masking class.

## Special ritual note: `clean-clone-smoke.patch` (CI-12)

Beyond the live-CI push (see "The fake gate" above), this gate's acceptance criteria also call for
a fresh clone:

```bash
git clone https://github.com/jadrianports/cryptiq.git /tmp/cryptiq-clean-clone-smoke
cd /tmp/cryptiq-clean-clone-smoke
pnpm install --frozen-lockfile
pnpm build     # must SUCCEED on the un-patched (fixed) tree, FAIL on the patched tree
```

The CI-hosted red/green runs above already exercise this exact scenario on a real GitHub-hosted
clean checkout, which is what makes the fake-gate discovery meaningful: the local re-run pattern
above is available for anyone verifying this gate again in the future.

## Phase 34-04 local pre-flight: the 4 CodeQL break-patches (HARD-03)

CodeQL is not installed locally (its extractor/query-pack toolchain is CI-only, downloaded
fresh by `codeql-action/init`), so none of these four can be pre-flighted by actually running
CodeQL on this machine. What WAS verified locally, on this machine, before authoring the
placeholder ledger rows above:

- **All four apply cleanly and revert cleanly** against current `main`:
  `git apply scripts/ci-selftest/codeql-<x>.patch` followed by
  `git apply -R scripts/ci-selftest/codeql-<x>.patch` leaves `git status --short` empty for
  every one (new-file patches are fully removed on revert, not just content-reverted).
- **Both Rust patches (`codeql-rust-tauri.patch`, `codeql-rust-nativehost.patch`) `cargo check`
  clean** in their respective workspace after applying: the planted sink is a genuine *semantic*
  vulnerability (a `log::info!` call that interpolates a local `password` literal — CodeQL's
  `rust/cleartext-logging` pattern, confirmed via Context7 against `codeql-query-help/rust/
  rust-cleartext-logging`), not a compile error. This isolates the eventual red to the CodeQL
  `rust` analyze step specifically, exactly the same discipline the two `cargo-audit-*.patch`
  files above already established for HARD-02. Both patches add `log = "=0.4.29"` as a direct
  dependency — already resolved transitively in `apps/desktop/src-tauri/Cargo.lock` at that exact
  version, so `codeql-rust-tauri.patch` pulls no new download; `codeql-rust-nativehost.patch`
  pins the SAME version deliberately, for a genuinely new (but trivial, dependency-free, widely
  audited) direct dependency in that workspace.
- **`codeql-jsts.patch`** plants `eval(location.hash)` in a new, never-imported fixture file
  (`scripts/ci-selftest/__fixtures__/codeql-jsts-sink.mjs`) — CodeQL's own canonical
  DOM-based `js/code-injection` demonstration pattern (mirrors the upstream test fixture at
  `javascript/ql/test/query-tests/Security/CWE-094/CodeInjection/webix/webix.html`, which uses
  the equivalent `document.location.hash` source into a dangerous sink).
- **`codeql-actions.patch`** adds a new scratch workflow file,
  `.github/workflows/ci-selftest-actions-scratch.yml` — NEVER `ci.yml`, `release.yml`, or
  `codeql.yml` — containing `echo '${{ github.event.comment.body }}'` in a `run:` block, the
  exact pattern CodeQL's `actions/code-injection/medium` query help documents as vulnerable.
  Its `issue_comment` trigger is never expected to fire on a selftest scratch branch; CodeQL's
  `actions` extractor analyzes the workflow's YAML definition statically on the push that
  triggers `codeql.yml`, independent of whether this workflow's own trigger ever fires.

All four query-pattern choices (severity/inclusion in CodeQL's DEFAULT query suite, not only
`security-extended`) were selected from current CodeQL documentation fetched live via Context7
(`/github/codeql` and `/websites/codeql_github`), not from training-data recall — per the plan's
critical guidance that `security-extended` is not enabled on this repo's `codeql.yml`.

The live CI red-run for all four (Task 3) is where each gets its actual proof and a real URL,
replacing the "pending" placeholders above.

## Phase 36-04 local pre-flight: `updater-signature.patch` / `updater-comparator.patch` / `updater-capability-diff.patch`

All three of this phase's gates are locally checkable (a Rust `#[test]` and two `lint-*.mjs`
scripts) — no live-CI-only surface (no `windows-2025` runner behavior, no gitleaks/CodeQL
toolchain) is involved, so all three were fully pre-flighted on this machine before authoring the
ledger rows above. **The live CI red-run URLs are still OUTSTANDING** — recorded honestly as
`pending` per rows 23-25, to be closed by `/gsd-verify-work` at phase close (repair→prove→arm; this
plan does not push a scratch branch or a `v*` tag).

**`updater-signature.patch`** (UPD-01) — makes the tamper a no-op (`^= 0x01` → `^= 0x00`), so the
"tampered" bytes are actually unchanged and the test's failure assertion no longer holds:
```bash
git apply scripts/ci-selftest/updater-signature.patch
cd apps/desktop/src-tauri && cargo test commands::update::tests::signature_verification_fails_on_tampered_byte -- --exact
# applied: exit 101 (FAILED — 0 passed; 1 failed), panic at the "first" position assertion
cd ../../.. && git checkout -- apps/desktop/src-tauri/src/commands/update.rs
cd apps/desktop/src-tauri && cargo test commands::update::tests::signature_verification_fails_on_tampered_byte -- --exact
# reverted: exit 0 (ok — 1 passed; 0 failed)
```

**`updater-comparator.patch`** (UPD-02) — deletes the `.version_comparator(` call from
`with_explicit_comparator`, reverting to the plugin's implicit default (the exact opt-out UPD-02
bans). Breaks the LINT layer, not `comparator_is_strictly_greater` itself (that test exercises
`is_strictly_newer` directly and is unaffected by this specific deletion) — the lint is the
cheaper, deterministic gate to pin the red run against, and it is the one that actually asserts
"the comparator call exists at all", which is the property this patch removes:
```bash
git apply scripts/ci-selftest/updater-comparator.patch
node scripts/lint/lint-updater-opt-outs.mjs
# applied: exit 1 — "no `.version_comparator(` call found outside comments"
git checkout -- apps/desktop/src-tauri/src/commands/update.rs
node scripts/lint/lint-updater-opt-outs.mjs
# reverted: exit 0 — "OK: updater opt-outs absent; version_comparator is explicit."
```

**`updater-capability-diff.patch`** (UPD-04) — adds a single benign-looking permission token
(`"updater:allow-check"`) to `capabilities/default.json`, simulating exactly the capability-surface
creep UPD-04 exists to catch:
```bash
git apply scripts/ci-selftest/updater-capability-diff.patch
node scripts/lint/lint-updater-capability-diff.mjs
# applied: exit 1 — "DRIFT DETECTED: capabilities/default.json" (SHA-256 mismatch)
git checkout -- apps/desktop/src-tauri/capabilities/default.json
node scripts/lint/lint-updater-capability-diff.mjs
# reverted: exit 0 — "OK: capability surface + production CSP byte-identical to the pre-updater snapshot."
```

`git status --short` was empty after every one of the three revert steps above.

## Phase 36-09 local pre-flight: `updater-rollback.patch`

The D-11 rollback mitigation (`high_water.rs`) is locally checkable (a Rust `#[test]`), no live-CI-
only surface involved — pre-flighted on this machine before authoring the ledger row above (row
26). **The live CI red-run URL is still OUTSTANDING** — recorded honestly as `pending`, to be
closed by `/gsd-verify-work` at phase close (repair→prove→arm; this plan does not push a scratch
branch or a `v*` tag).

**`updater-rollback.patch`** — flips `passes_high_water`'s `Unreadable` arm from `false` to `true`,
i.e. fail-OPEN on a corrupt high-water store. This is the highest-value break because it is the
most PLAUSIBLE regression: exactly what a well-meaning refactor does when it decides a corrupt
sidecar "shouldn't block the user from updating":

```bash
git apply scripts/ci-selftest/updater-rollback.patch
cd apps\desktop\src-tauri && cargo test commands::high_water::tests::unreadable_high_water_fails_closed -- --exact
# applied: exit 101 (FAILED — 0 passed; 1 failed), panic: "Unreadable must fail CLOSED regardless
# of how high the candidate claims to be"
cd ../../.. && git checkout -- apps/desktop/src-tauri/src/commands/high_water.rs
cd apps\desktop\src-tauri && cargo test commands::high_water::tests::unreadable_high_water_fails_closed -- --exact
# reverted: exit 0 (ok — 1 passed; 0 failed)
```

`git status --short` was empty after the revert step above (aside from the newly-authored, then
committed, `.patch` file itself).

## Phase 36-11 local pre-flight: `updater-consent-guard.patch`

Closes a coverage gap left by Plans 04/05: DEBT-01's consent guard was as novel and as
security-critical as the four properties already covered above, but had no break-patch proving
its gate could actually fail. Locally checkable (a Rust `#[test]`), no live-CI-only surface
involved — pre-flighted on this machine before authoring row 27 above. **The live CI red-run URL
is still OUTSTANDING** — recorded honestly as `pending`, to be closed by `/gsd-verify-work` at
phase close (repair→prove→arm; this plan does not push a scratch branch or a `v*` tag).

**`updater-consent-guard.patch`** — flips `HIBP_CONSENT_DEFAULT_IF_ABSENT` (the fail-direction the
DEBT-01/W-1 consent guard in `hibp_range_lookup` uses) from `false` to `true`, i.e. fail-OPEN. This
is the exact regression 36-PATTERNS.md warned about: a reviewer or executor copying
`extension_bridge_enabled`'s fail-OPEN analog verbatim silently reintroduces W-1. It is a one-word
change, it compiles clean, and every UI-level test still passes (the call sites keep their own
consent checks) — only the seam test catches it.

*Fake-gate finding, corrected before authoring this row:* the plan's originally-named target,
`consent_guard_blocks_when_disabled`, drove `config_guard::resolve_bool` with its own
independently-hardcoded `false` literal, not the real call site's value inside
`hibp_range_lookup` — flipping only the inline literal at the call site left every test in the
module green (confirmed by running that exact flip locally first, before authoring the patch).
Reworked per this plan's own "a patch whose applied run exits 0 is a fake-green gate" instruction:
extracted the fail-direction into a named constant (`HIBP_CONSENT_DEFAULT_IF_ABSENT`) that BOTH
the real call site and `consent_guard_blocks_when_disabled` now reference, so the test is provably
load-bearing on the same value the patch flips. That refactor landed as its own commit before the
patch was authored (`hibp.rs` is therefore modified by this plan beyond the three files in its
frontmatter — documented as a deviation in `36-11-SUMMARY.md`).

```bash
git apply scripts/ci-selftest/updater-consent-guard.patch
cd apps/desktop/src-tauri && cargo test commands::hibp::tests::consent_guard_blocks_when_disabled -- --exact
# applied: exit 101 (FAILED — 0 passed; 1 failed), panic at the None-branch assertion
cd ../../.. && git checkout -- apps/desktop/src-tauri/src/commands/hibp.rs
cd apps/desktop/src-tauri && cargo test commands::hibp::tests::consent_guard_blocks_when_disabled -- --exact
# reverted: exit 0 (ok — 1 passed; 0 failed)
```

`git status --short` was empty after the revert step above.

## Full ledger

The complete gate → patch → red-run-URL → attribution ledger, including the green baseline and
both honest exceptions (CI-02, the CI-12 fake-gate episode), lives in
`../../.planning/phases/33-ci-resurrection-build-integrity-gate/33-VERIFICATION.md`.
