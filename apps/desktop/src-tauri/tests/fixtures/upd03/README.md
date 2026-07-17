# UPD-03 rollback-experiment fixtures — provenance

This directory documents the provenance of the two inputs `upd03_rollback_experiment`
(`apps/desktop/src-tauri/src/commands/update.rs`, `#[cfg(test)] mod tests`) consumes. **Only
this README is committed.** The throwaway private key and the real signed artifact/`.sig` are
NOT committed — see "What is NOT committed" below.

## Why a throwaway key (D-09 / D-10)

The UPD-03 experiment tests whether Tauri's updater plugin binds the **unsigned** `version`
claim in `latest.json` to the **signed** artifact bytes. That property does not depend on
*which* key signs the artifact — only on whether `verify_signature(&buffer, &signature,
&pubkey)` (the plugin's own internal call, confirmed by reading
`tauri-apps/plugins-workspace`'s `updater.rs` source directly this session) is ever
cross-checked against the manifest's `version` field. A throwaway keypair proves the binding
property identically to the real one.

This is also what keeps the phase's own ordering intact: the real signing key does not exist
yet (KEY-01 generates it in a later plan of this phase) and **is not needed here** — running
this experiment before the real key exists is the GATE's entire point (prove the channel's
trust properties on inert objects before the real security boundary is ever exercised).

## What was generated

1. **Throwaway keypair**, generated via `tauri signer generate` — the exact same CLI the real
   KEY-01 ceremony will use later in this phase:

   ```bash
   pnpm --filter ./apps/desktop tauri signer generate --ci \
     -p "throwaway-test-password-upd03" \
     -w "<scratch-path-outside-the-repo>/cryptiq-upd03-throwaway.key" \
     -f
   ```

   Written to an OS temp directory **outside the repository** (never `apps/desktop/src-tauri/`
   or any tracked path). The private key file and its password exist only for the duration of
   this experiment and are disposable (D-09: this key signs nothing any real user ever trusts).

   **Throwaway PUBLIC key** (safe to publish — embedded as a Rust `const` in
   `update.rs`'s test module, not a secret):

   ```
   dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDI5MTEzQjBCRUFDNTQ5RUMKUldUc1NjWHFDenNSS1haTkhPdVRBWWNaWU93SnNPcWxocWRMWXFHR1JHTnZWQVMrZTNoQlBnWlkK
   ```

2. **A real, old, validly-signed artifact.** Per CONTEXT's discretion grant over "the exact
   real, old, validly-signed artifact", a fresh production build was produced this session
   (`pnpm build` at the repo root — this does NOT `cargo clean`; it re-uses the existing
   `target/` incrementally) rather than reusing a stale `Cryptiq_1.0.0_x64-setup.exe` already
   present on disk from a July 7 build, so the artifact's own embedded version genuinely
   matches the current `tauri.conf.json` (`3.2.0`). The artifact's *own* embedded version number
   is not actually load-bearing for the experiment (the experiment never inspects it — only
   `latest.json`'s claimed `"99.0.0"` and the artifact's *bytes* matter), but a current, real
   build was chosen over the stale one for honesty of the "old, real artifact" framing.

   Built NSIS installer:

   - **Filename:** `Cryptiq_3.2.0_x64-setup.exe`
   - **Path (build output, not committed):**
     `apps/desktop/src-tauri/target/release/bundle/nsis/Cryptiq_3.2.0_x64-setup.exe`
   - **SHA-256:** `BDF80AACAE51A333C134AF15E1E7602F4ADCA9F062466770D0FAE86E8FCBCB21`
     (computed via `Get-FileHash -Algorithm SHA256` after the build completed this session)

   Signed with the throwaway private key:

   ```bash
   pnpm --filter ./apps/desktop tauri signer sign \
     -f "<scratch-path>/cryptiq-upd03-throwaway.key" \
     -p "throwaway-test-password-upd03" \
     "apps/desktop/src-tauri/target/release/bundle/nsis/Cryptiq_3.2.0_x64-setup.exe"
   ```

   This produces `Cryptiq_3.2.0_x64-setup.exe.sig` next to the input file — a genuinely valid
   minisign signature for those exact bytes under the throwaway key. `tauri signer sign`
   operates on an arbitrary existing file (no rebuild), so the signed bytes are provably the
   built artifact's bytes.

## What is NOT committed (and why)

| Artifact | Committed? | Why |
|---|---|---|
| This README | Yes | Provenance record only — no secret material. |
| Throwaway private key | **No** | Never committed, ever — D-09 disposability does not mean "safe to publish"; the private key is deleted from the scratch path once this plan closes. |
| `Cryptiq_3.2.0_x64-setup.exe` (the built artifact) | **No** | Large binary build output; already excluded by the repo's existing `target/` `.gitignore` coverage — not specific to this experiment. |
| `Cryptiq_3.2.0_x64-setup.exe.sig` | **No** | Regenerable from the two commands above; not a secret, but not worth committing either — the test reads it from the build output path at run time and fails loudly with regeneration instructions if it is absent. |
| Throwaway **public** key | Embedded as a Rust `const` string literal directly in `update.rs`'s test module | It is not a secret (D-09) — inlining avoids a third fixture file for a non-secret value, per the plan's own guidance. |

## Regenerating these fixtures

```bash
# 1. Build a real, current artifact (repo root):
pnpm build

# 2. Generate a fresh throwaway keypair to a scratch path OUTSIDE the repo:
pnpm --filter ./apps/desktop tauri signer generate --ci \
  -p "<any-throwaway-password>" \
  -w "<scratch-path>/cryptiq-upd03-throwaway.key" -f

# 3. Sign the built artifact with the throwaway key:
pnpm --filter ./apps/desktop tauri signer sign \
  -f "<scratch-path>/cryptiq-upd03-throwaway.key" \
  -p "<any-throwaway-password>" \
  "apps/desktop/src-tauri/target/release/bundle/nsis/Cryptiq_<version>_x64-setup.exe"

# 4. Update THROWAWAY_PUBKEY in update.rs's test module with the new .key.pub contents,
#    and re-point update.rs's artifact_path/signature_path at the new filename if the
#    version changed.
```

## Harness shape (Task 1 spike result) — and why the FINAL test does not use it

See `36-02-SUMMARY.md` "Harness Spike / Environment Blocker" for the full account. Summary: the
plugin's own upstream integration test (`tauri-apps/plugins-workspace`,
`plugins/updater/tests/app-updater/src/main.rs`) drives `updater_builder()` from inside a
`.setup()` closure of a REAL, fully-run `tauri::Builder::default()` app, launched as a built
subprocess — not a bare `mock_app()` call. For a unit-test-shaped in-process test, the closest
sanctioned equivalent — confirmed directly from `tauri-apps/tauri`'s own `crates/tauri/src/
test/mod.rs` module-level doctest — is `tauri::test::mock_builder()` + `.plugin(...)` +
`tauri::generate_context!(...)`, requiring `tauri = { features = ["test"] }` in
`[dev-dependencies]`. The fixture config that harness needs still lives at
`tests/fixtures/upd03-harness/tauri.conf.json` (a SIBLING directory, kept for a future
follow-up), but **the shipped test does not use it**: every combination of constructing a live
`tauri::App`/`AppHandle` (MockRuntime or real Wry, in this crate's own unit-test binary or a
fully separate `tests/*.rs` integration-test binary, debug or release profile) reproducibly
fails to even LOAD on this machine (`STATUS_ENTRYPOINT_NOT_FOUND`, exit `0xc0000139`) — a
genuine, exhaustively-diagnosed environment blocker, not a logic bug. The shipped test instead
reproduces the plugin's own `verify_signature()` primitive directly via `minisign-verify`
(already a dev-dependency from Plan 01) against these SAME real fixtures. Driving `.check()` +
`.download()` against a live plugin instance end-to-end remains the stronger evidence and is
recorded as a Deferred Issue in `36-02-SUMMARY.md`, to revisit once this machine's `cargo test`
+ Tauri-App incompatibility is understood or a second environment becomes available.
