import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';

// D-02: dev-only boot self-test, stripped from production via Vite's tree-shaking
// on `import.meta.env.DEV` (a static replacement at build time).
if (import.meta.env.DEV) {
  // Dynamic import so the file is NEVER included in the production bundle.
  import('./lib/dev/boot-self-test').then(({ runBootSelfTest }) => runBootSelfTest());
}

const app = mount(App, { target: document.getElementById('app')! });
export default app;
