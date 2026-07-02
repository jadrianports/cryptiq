import { defineConfig } from 'wxt';

// apps/extension/wxt.config.ts
//
// D-15: `manifest.key` pins a stable, deterministic extension ID across
// reloads/machines so the native-host manifest's `allowed_origins` stays
// valid. The private key (`extension-key.pem`, gitignored) is never used at
// build time — only the derived base64 DER public key below is committed.
// Regenerate via (one-time, already done for this repo):
//   openssl genrsa -out extension-key.pem 2048
//   openssl rsa -in extension-key.pem -pubout -outform DER | openssl base64 -A
//
// D-17: permissions = nativeMessaging ONLY. No host_permissions, no
// content_scripts entry — Phase 14's extension surface is background SW +
// popup only; field detection/injection is Phase 17.
export default defineConfig({
  modules: ['@wxt-dev/module-svelte'],
  manifest: {
    name: 'Cryptiq',
    key: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA19vhX8XkzAUXKFy9ULbh3THq+EUESqEnurUFmD/qlyZNerlM0gxQeuXk61QW/MG9aTBTXnlUQ86+KPbBlORunAs6ST0Nn+AU1sX/UnfCZBlrPQVMY1Y57MRaRviLLwpwpa5W0LKafR0iZHkK4o/WwQzRexsbBlqnR4zu/1b+92d6vYnfEiXIqxYLuB3TF5fy4iGBbuE8CtG7gUD209c+jvJUwcJCBOtGNXAZ65Q8iv25gXBB2BE7Q68BQN7IBsVzt0shzid+PcjNx0zIpMzkyEjwCB29UrucOdJqGazhAfZaFp2AvKpIYHmb+FP1jJ/1duIPifxXyrAhfnQZj2gbdwIDAQAB',
    permissions: ['nativeMessaging'],
  },
});
