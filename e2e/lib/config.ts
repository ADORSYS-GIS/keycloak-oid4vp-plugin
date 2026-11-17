// Single source of truth for the URLs the tests rely on. The values mirror
// assets/realm/config.ts and docker-compose.yml; .env overrides them (see
// .env.example). play.sh sources .env before running the tests.

// The status-list-server URL is the very value the realm renders with,
// so it is read from in assets/realm/config.ts.
export { STATUS_LIST_SERVER_URL } from "../assets/realm/config.ts";

// The mock frontend (demo app) the browser drives through the whole journey.
export const APP_URL = `http://localhost:${process.env.MOCK_FE_HTTP_PORT ?? 14200}`;

// The test wallet's HTTP API (see lib/wallet.ts).
export const WALLET_BASE_URL = `http://localhost:${process.env.WALLET_HTTP_PORT ?? 18085}`;
