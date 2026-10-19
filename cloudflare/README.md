# NeonStudy cloud sync

GitHub Pages serves the study app, but it cannot run account or database code. This Cloudflare Worker is the small backend for accounts and cross-device progress sync. The PIN is sent only over HTTPS during sign-up/sign-in; it is salted and hashed by the Worker and is never saved in the browser. Sync requests use a revocable bearer token. Worker stores study progress, selected exams and theme, not question text or API keys.

## One-time Cloudflare setup

1. Install Node.js if needed and open a terminal.
2. In this folder run \`npx wrangler@latest login\` and approve Cloudflare access in the browser.
3. Create the database: \`npx wrangler@latest d1 create neonstudy-progress\`.
4. Copy the returned database ID into \`wrangler.jsonc\`, replacing \`REPLACE_WITH_D1_DATABASE_ID\`.
5. From this folder run \`npx wrangler@latest d1 migrations apply neonstudy-progress --remote\`.
6. Create a long random secret for the PIN hashing pepper: \`openssl rand -hex 32\`. Then run \`npx wrangler@latest secret put PIN_PEPPER\` and paste that generated value.
7. Deploy: \`npx wrangler@latest deploy\`.
8. Copy the Worker URL ending in \`.workers.dev\`. In NeonStudy open **Settings → Cloud sync**, paste the URL, then create/sign in to your account.

After the one-time deployment, normal study syncs automatically about every two minutes while the app is open, and also when leaving the page. The app shows the sync status and provides a **Sync now** action.

## Security and data

- The Worker accepts browser requests only from \`https://orbgamestudios.github.io\`.
- Account names are unique and case-insensitive. PINs are exactly four digits.
- PIN hashes use PBKDF2-SHA-256 with a per-account random salt and the private \`PIN_PEPPER\` Worker secret; raw PINs are not stored.
- Sessions expire after 30 days; **Sign out** revokes the current session.
- Login attempts are limited to five per account-and-IP digest every 15 minutes.
- Sync payloads are bounded and limited to study-guide mastery, calculation progress, topic progress, aggregate quiz counts, chosen exams and theme.
