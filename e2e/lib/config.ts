// Single source of truth for the URLs the tests rely on. The values mirror
// assets/realm/config.ts and docker-compose.yml; .env overrides them (see
// .env.example). play.sh sources .env before running the tests.

// The mock frontend (demo app) the browser drives through the whole journey.
export const APP_URL = `http://localhost:${process.env.MOCK_FE_HTTP_PORT ?? 14200}`;

// The test wallet's HTTP API (see lib/wallet.ts).
export const WALLET_BASE_URL = `http://localhost:${process.env.WALLET_HTTP_PORT ?? 18085}`;

// The public status-list server (mirrors assets/realm/config.ts).
export const STATUS_LIST_SERVER_URL =
  process.env.STATUS_LIST_SERVER_URL ?? "https://statuslist.eudi-adorsys.com";
