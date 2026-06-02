// apps/desktop/src/lib/import/csvWorker.ts
//
// Vite Web Worker for CSV parsing via papaparse (IMPORT-01).
//
// This file IS the Web Worker — Vite compiles it as a separate bundle when
// imported with the `?worker` suffix:
//   import CsvWorker from '../import/csvWorker?worker';
//
// CRITICAL (Pitfall 1 in RESEARCH.md — SCRIPT_PATH bundle detection failure):
// We use `worker: false` inside this manually-created worker. If `worker: true`
// were used here, papaparse would try to spawn yet another worker and auto-detect
// its own script path via `document.currentScript`, which fails in bundled ESM
// contexts (Vite, Tauri). `worker: false` avoids the SCRIPT_PATH issue entirely —
// we ARE already in a worker, so papaparse's step callback runs on this thread.
//
// CSP note: `worker-src 'self' blob:` is already present in tauri.conf.json's
// production CSP, which covers Vite-compiled workers loaded via blob URL.
// No CSP or capability change is required.
//
// Message protocol:
//   Incoming: { csvText: string }
//   Outgoing:
//     { type: 'row'; data: string[]; errors: Papa.ParseError[] }  — per step
//     { type: 'complete' }                                         — when done
//     { type: 'error'; message: string }                          — fatal parse error

import Papa from 'papaparse';

type WorkerIncoming = { csvText: string };
type WorkerOutgoing =
  | { type: 'row'; data: string[]; errors: Papa.ParseError[] }
  | { type: 'complete' }
  | { type: 'error'; message: string };

// Wire the message handler. We cast to any for the event parameter to avoid TypeScript
// overload resolution issues with DedicatedWorkerGlobalScope.addEventListener in the
// DOM lib (the 'message' string literal falls through to the unique-symbol overload).
// The actual event type is MessageEvent<WorkerIncoming> at runtime; the cast is safe.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).addEventListener('message', (event: MessageEvent<WorkerIncoming>) => {
  const { csvText } = event.data;

  Papa.parse<string[]>(csvText, {
    // worker: false — we ARE already in a worker (Pitfall 1 mitigation).
    // Using worker: true here would trigger SCRIPT_PATH detection which fails
    // under Vite bundling.
    worker: false,

    // step is called once per row (streaming — avoids loading the full CSV
    // into memory, keeping the main thread responsive for large files: IMPORT-01,
    // T-06-07 DoS-mitigation).
    step(result: Papa.ParseStepResult<string[]>) {
      const msg: WorkerOutgoing = {
        type: 'row',
        data: result.data,
        errors: result.errors,
      };
      postMessage(msg);
    },

    complete() {
      const msg: WorkerOutgoing = { type: 'complete' };
      postMessage(msg);
    },

    error(err: Error) {
      const msg: WorkerOutgoing = { type: 'error', message: err.message };
      postMessage(msg);
    },

    // Skip blank lines — they produce empty rows that mapRow would reject as
    // malformed (missing title). Skipping them here avoids unnecessary noise
    // in the malformed-rows report (P6-04).
    skipEmptyLines: true,
  });
});
