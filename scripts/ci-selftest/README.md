# CI Self-Test — Break-Patches (CI-06 / D-05)

**The milestone discipline this directory encodes: a gate is not landed until a RED-RUN URL is
recorded.** CI was green-looking and structurally dead (silently skipping the sidecar-dependent
gates) for four milestones before Phase 33. Green tests and a green lint suite are not proof a
gate can actually fail — only a live GitHub Actions run that goes RED, on purpose, is proof.

This is a **one-time manual ritual** (D-05), not an automated recurring meta-job. An automated
"break something every night and confirm it's still red" job is itself fragile, self-modifying CI
that burns minutes forever to re-prove a property that doesn't change. Instead: each gate gets a
committed `.patch` file that breaks it on purpose. The `.patch` files are **living, re-runnable
artifacts** — if the pipeline is ever restructured, re-run the same ritual against the new shape
and confirm the patch (or an updated version of it) still turns the gate red.

## The ritual (per gate)

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

# 6. Revert: delete the scratch branch (or reset it back to main's tip), confirm the same
#    commit content reverted is GREEN on a clean branch, and record that green-confirm URL too.
git push origin --delete ci-selftest/<gate>
git branch -D ci-selftest/<gate>
```

Do this for **every** patch below, in any order — `pwsh-exit-propagation.patch` is the sharpest
proof in the phase (see its own section) and is worth doing first.

## Local pre-flight (already done once, this session, for the 5 lint-checkable gates)

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
clean-clone `pnpm install && pnpm build`) — those are genuinely CI-only and are marked as such
below; they still pass `git apply --check` against the current tree.

## Gate ledger

| # | Gate (requirement) | Patch | Locally proven this session? | Live-CI status |
|---|---|---|---|---|
| 1 | CI-01 sidecar staging precedes `cargo check` | `sidecar.patch` | No (CI-only — needs a real `cargo check` externalBin resolution failure) | awaiting live red-run URL |
| 2 | CI-02 `--target` cross-compile output path | `cargo-cross-target.patch` | No (CI-only — needs a real macOS cross-compiled `cargo build`) | awaiting live red-run URL |
| 3 | CI-03/CI-05 version-consistency (byte-equality across 4 files) | `version-consistency.patch` | **Yes** — drifted `apps/native-host/Cargo.toml` to `3.2.1`; `node scripts/lint/lint-version-consistency.mjs` exited 1 reporting the exact mismatch; reverted, re-ran, exit 0 | awaiting live red-run URL |
| 4 | CI-11 `msi` dropped from `bundle.targets` | `msi-drop.patch` | **Yes** — re-added `"msi"` to `apps/desktop/src-tauri/tauri.conf.json`'s `bundle.targets`; the same `lint-version-consistency.mjs` (folds CI-11) exited 1; reverted, re-ran, exit 0 | awaiting live red-run URL |
| 5 | CI-04 sidecar-staging ORDER lint | `sidecar-staging-lint.patch` | **Yes** — added a stray `cargo check` step to the `node` job (no preceding staging step) in `ci.yml`; `node scripts/lint/lint-sidecar-staging.mjs` exited 1 pointing at the exact line; reverted, re-ran, exit 0 | awaiting live red-run URL |
| 6 | CI-10 Vite key-leak guard (envPrefix) | `vite-key-leak.patch` | **Yes** — set `envPrefix: ['VITE_', 'TAURI_']` (bare) in `apps/desktop/vite.config.ts`; `node scripts/lint/lint-vite-key-leak.mjs` exited 1 (GHSA-2rcp-jvr4-r259 message); reverted, re-ran, exit 0 | awaiting live red-run URL (Stage B dist-grep is additionally CI-only — needs a real post-build `dist/`) |
| 7 | CI-09 workspace-scripts (`typecheck` script presence) | `typecheck-skip.patch` | **Yes** — removed `scripts.typecheck` from `packages/core/package.json`; `node scripts/lint/lint-workspace-scripts.mjs` exited 1 naming the package; reverted, re-ran, exit 0 | awaiting live red-run URL |
| 8 | CI-07 `ci-required` aggregator (skip = fail) | `ci-required-aggregator.patch` | No (CI-only — needs real `needs.*.result` evaluation across live jobs) | awaiting live red-run URL |
| 9 | CI-08 pwsh non-final-line exit propagation | `pwsh-exit-propagation.patch` | No (CI-only — needs real pwsh 7.6.3 on `windows-2025`; see dedicated section below) | awaiting live red-run URL |
| 10 | CI-12 clean-clone `pnpm build` (root build routes through staging) | `clean-clone-smoke.patch` | No (CI-only — needs a real fresh clone + `pnpm install --frozen-lockfile` + `pnpm build`) | awaiting live red-run URL |

For every patch: `git apply --check scripts/ci-selftest/<name>.patch` exits 0 against current
`main`, and `git apply --check --reverse` after applying also exits 0 (cleanly revertible) — both
verified for all 10 patches during authoring.

## The sharpest gate: `pwsh-exit-propagation.patch` (CI-08)

`ci.yml` is now one-command-per-step by construction (the tiered-job rewrite, D-01, is itself the
structural fix for this bug class) — there is currently no genuinely multi-line pwsh `run:` block
anywhere in the pipeline for this bug to hide in. So this patch **adds** a temporary multi-line
pwsh step to the end of the `rust` job:

```yaml
- name: "CI-08 selftest: multi-line pwsh block, non-final cargo build failure must propagate"
  shell: pwsh
  run: |
    $PSNativeCommandUseErrorActionPreference = $true
    cargo build --release --manifest-path apps/native-host/Cargo.toml --this-flag-does-not-exist
    Write-Host "UNREACHABLE if propagation works — the cargo build above must have failed the step"
```

Line 1 sets the guard (required before any native command it should protect — a preference
variable can't retroactively apply to a command that already ran). Line 2 is a **genuinely
failing** `cargo build` (an unrecognized CLI flag makes `cargo` itself exit non-zero — no need to
introduce a Rust source-level syntax error elsewhere in the tree). Line 3 is a command that would
otherwise succeed and, under GitHub's pre-fix default behavior (only the LAST command's
`$LASTEXITCODE` is checked), would make the whole step **report green** even though line 2 failed.

**What the live red-run must show:** the step reports **RED**, and reading the step's log shows
the `cargo build` failure on line 2 (not the last line) as the reason — proving
`$PSNativeCommandUseErrorActionPreference = $true` propagates a non-final native-command failure
on a real `windows-2025` runner (which ships pwsh 7.6.3), closing the exact bug class that let a
`cargo build` failure hide behind a later `echo "done"` before this phase.

Delete this step from the scratch branch before merging anything back — it is selftest-only
scaffolding, not a permanent pipeline step.

## Special ritual note: `ci-required-aggregator.patch` (CI-07)

This patch adds `if: false` to the `node` job, forcing it to be unconditionally **skipped** (not
failed) on every run. The live-CI check must confirm TWO things, not one:
1. The `node` job itself shows as `Skipped` in the Actions UI.
2. The `ci-required` job (which `needs: [rust, node, build]` and runs `if: always()`) **still
   executes** (because of `if: always()`) and then **fails**, because its own
   `contains(needs.*.result, 'skipped')` check catches the skip. `ci-required` failing is the
   actual proof — a job merely being skipped is not automatically "red" in every GitHub UI
   surface, which is exactly the class of masking CI-07 exists to close.

## Special ritual note: `clean-clone-smoke.patch` (CI-12)

In addition to observing the live-CI push go red, this gate's acceptance criteria call for an
**actual fresh clone**:

```bash
git clone https://github.com/jadrianports/cryptiq.git /tmp/cryptiq-clean-clone-smoke
cd /tmp/cryptiq-clean-clone-smoke
pnpm install --frozen-lockfile
pnpm build     # must SUCCEED on the un-patched tree, FAIL on the patched tree
```

Record both outcomes (patched tree fails on missing staged sidecar; un-patched/fixed tree
succeeds) in `33-VERIFICATION.md`'s Notes column for this gate.
