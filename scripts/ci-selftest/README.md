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

Attribution was checked on every row — the gate had to fail at *its own step*, not incidentally.

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

## Full ledger

The complete gate → patch → red-run-URL → attribution ledger, including the green baseline and
both honest exceptions (CI-02, the CI-12 fake-gate episode), lives in
`../../.planning/phases/33-ci-resurrection-build-integrity-gate/33-VERIFICATION.md`.
