// Browser-side helpers that drive the mock frontend and the OpenID4VP login
// screen, and read protocol artifacts off the rendered pages.
import { expect, type Page } from "@playwright/test";
import jsQR from "jsqr";
import { PNG } from "pngjs";
import { APP_URL } from "./config";

export const USER = { username: "alice@localhost", password: "password" };

/** Wait until the browser lands back on the mock frontend (the app origin). */
export async function waitForApp(page: Page, timeout = 20_000) {
  await page.waitForURL((u) => u.origin === new URL(APP_URL).origin, { timeout });
}

/** Log Alice in with username and password via the Keycloak login page. */
export async function logInWithPassword(page: Page) {
  await page.goto(APP_URL);
  await page.getByRole("button", { name: "Login with Keycloak" }).click();
  await page.locator("#username").waitFor({ timeout: 20_000 });
  await page.locator("#username").fill(USER.username);
  await page.locator("#password").fill(USER.password);
  await page.getByRole("button", { name: "Sign In" }).click();
  await waitForApp(page, 20_000);
}

/** Log Alice out of the app. */
export async function logOut(page: Page) {
  await page.getByRole("button", { name: "Logout" }).click();
  await expect(
    page.getByRole("button", { name: "Login with Keycloak" }),
    "the app returns to its unauthenticated view",
  ).toBeVisible({ timeout: 30_000 });
}

/**
 * Open the Keycloak login page. The app first shows a landing page (or a
 * transient "#error=login_required" fragment while reconnecting); clicking
 * "Login with Keycloak" is what leads to Keycloak's authentication interface.
 * One retry handles races.
 */
export async function openTheLoginPage(page: Page) {
  for (let attempt = 0; attempt < 2; attempt++) {
    await page.goto(APP_URL);
    const login = page.getByRole("button", { name: "Login with Keycloak" });
    await expect(login, "the app offers the Keycloak login button").toBeVisible({
      timeout: 30_000,
    });
    await login.click();
    const username = page.locator("#username");
    const appears = await username
      .waitFor({ state: "visible", timeout: 15_000 })
      .then(() => true)
      .catch(() => false);
    if (appears) return;
  }
  expect.soft(false, "the Keycloak login page never appeared").toBe(true);
}

/**
 * Start the wallet presentation flow from the Keycloak login page and return
 * the cross-device OpenID4VP request the wallet must answer.
 */
export async function selectWalletSignIn(page: Page) {
  // The Keycloak login page lists the wallet sign-in option alongside the
  // classic identity-provider buttons.
  const walletButton = page.locator("a[id^='social-oid4vp']").first();
  await expect(
    walletButton,
    "the login page offers the presentation-with-wallet option",
  ).toBeVisible();
  await walletButton.click();
  // The plugin now shows the presentation page with the request QR code and
  // link, and starts polling the authentication status in the background.
  await expect(page.locator("#kc-oid4vp-qrcode"), "OpenID4VP request shown").toBeVisible();
  return crossDeviceRequestFromQrCode(page);
}

/**
 * The mock frontend renders the wallet deeplink next to the QR code as
 * <a title="Open offer link" href="openid-credential-offer://?...">.
 * Call it while the Credential Offer tab is open.
 */
export async function captureOfferLink(page: Page): Promise<string> {
  await expect(
    page.locator('a[title="Open offer link"]'),
    "the app shows a scannable credential offer",
  ).toBeVisible();
  return (await page.locator('a[title="Open offer link"]').getAttribute("href")) ?? "";
}

/**
 * The plugin's presentation page queues the completion of the browser flow on
 * the cross-device transaction, whose OpenID4VP request is only encoded in the
 * on-page QR code image. Decode it so the headless wallet can act on it.
 */
export async function crossDeviceRequestFromQrCode(page: Page): Promise<string> {
  const dataUri: string | null = await page.locator("#kc-oid4vp-qrcode").getAttribute("src");
  expect(dataUri, "the QR code for the cross-device flow is on the page").toContain("base64,");
  const png = PNG.sync.read(Buffer.from(dataUri!.split(",")[1], "base64"));
  const decoded = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  expect(decoded, "the QR code decodes to an OpenID4VP request").toBeTruthy();
  return decoded!.data;
}
