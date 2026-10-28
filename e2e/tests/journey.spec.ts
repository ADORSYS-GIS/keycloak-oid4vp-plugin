import { expect, test } from "@playwright/test";
import { TestWallet } from "../lib/wallet";
import { APP_URL, STATUS_LIST_SERVER_URL } from "../lib/config";
import {
  captureOfferLink,
  logInWithPassword,
  logOut,
  openTheLoginPage,
  selectWalletSignIn,
  waitForApp,
} from "../lib/pages";

// The eudi-dev test wallet, auto-accepting and reachable via its HTTP API.
const wallet = new TestWallet();

// ---------------------------------------------------------------------------
// The user journey, verbatim from docs/credential-revocation-demo setup.
// ---------------------------------------------------------------------------

test("Alice exercises the full credential lifecycle", async ({ page }) => {
  // Step 1 — log in with username and password.
  await test.step("Alice logs in to the app with her username and password", async () => {
    await logInWithPassword(page);
  });

  // Step 2 — obtain the identity credential in her wallet.
  let offerLink = "";
  await test.step("Alice requests an Identity VC, the wallet claims the offer", async () => {
    await page.getByText("Credential Offer", { exact: false }).first().click();
    offerLink = await captureOfferLink(page);
    const take = await wallet.takeOfferToWallet(offerLink);
    expect(take.status, "wallet redeemed the pre-authorized offer").toBeLessThan(300);

    // The token-status plugin injects a `status.status_list` claim into the
    // issued credential; that is what later lets Keycloak reject a revoked
    // presentation. Verify it landed in the wallet's stored SD-JWT.
    const stored = await wallet.getCredential(take.body.credential_id);
    const jwt = stored.body.raw.split("~")[0].split(".")[1];
    const payload = JSON.parse(Buffer.from(jwt, "base64url").toString());
    expect(
      payload.status?.status_list?.uri.startsWith(STATUS_LIST_SERVER_URL),
      "the credential carries the status list",
    ).toBe(true);
  });

  // Step 3 — log out, then log back in presenting the new credential.
  await test.step("Alice logs out", async () => {
    await logOut(page);
  });

  await test.step("Alice logs back in presenting her Identity VC", async () => {
    await openTheLoginPage(page);
    const authRequestLink = await selectWalletSignIn(page);
    expect(authRequestLink, "a wallet-presentation request link is present").toBeTruthy();

    // Hand the request to the headless wallet; it plays the entire OpenID4VP
    // protocol on her behalf and POSTs the presentation back to Keycloak.
    const presentation = await wallet.presentCredential(authRequestLink!);
    expect(presentation.status, "the wallet completed the presentation").toBeLessThan(300);

    // Keycloak accepts the (valid) presentation and auto-completes the flow
    // back to the app.
    await waitForApp(page);
  });

  // Step 4 — revoke the credential from the app.
  await test.step("She revokes her credential from the app", async () => {
    // TODO(plugin): the token-status plugin's revoke endpoint does not emit
    // CORS headers itself, so the browser blocks the cross-origin revoke call
    // from the mock frontend (localhost) to Keycloak (keycloak.localhost).
    // The app's own origin already lies within the client's webOrigins; the
    // missing headers should come from the plugin. Inject them here for now.
    // See https://github.com/ADORSYS-GIS/token-status-link/issues/171
    await page.route(/\/status-list\/revoke$/, async (route) => {
      const upstream = await route.fetch();
      const headers = upstream.headers();
      headers["access-control-allow-origin"] = APP_URL;
      headers["access-control-allow-credentials"] = "true";
      await route.fulfill({ response: upstream, headers });
    });

    await page.getByRole("button", { name: "Credentials" }).click();
    const revoke = page.getByRole("button", { name: "Revoke" }).first();
    await expect(revoke, "a revocable credential row is present").toBeVisible();
    await revoke.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog, "the revocation dialog opens").toBeVisible();
    await dialog.locator("#revocation-reason").fill("Revoke the first issued credential");
    await dialog.getByRole("button", { name: /revoke/i }).click();
    await expect(
      page.getByText("Revoked", { exact: true }).first(),
      "the credential shows as revoked",
    ).toBeVisible({ timeout: 30_000 });
  });

  // Step 5 — the revoked credential can no longer be used to log in.
  await test.step("Alice can no longer log in with the revoked VC", async () => {
    await logOut(page);
    await openTheLoginPage(page);
    const authRequestLink = await selectWalletSignIn(page);

    // The wallet presents the stored credential again, but Keycloak rejects
    // it, because the status claim now maps to `revoked` on the server.
    // Keycloak answers the presentation with an `invalid_presentation` error,
    // which the wallet surfaces on its /api/presentations response.
    const presentation = await wallet.presentCredential(authRequestLink!);
    // The wallet returns the verifier's response verbatim: `response` carries
    // the HTTP status and `response.body` is the raw JSON Keycloak sent back.
    const verifier = presentation.body?.response;
    const rejection = verifier?.body ? JSON.parse(verifier.body) : undefined;
    expect(
      rejection?.error,
      "Keycloak rejected the revoked presentation with an invalid-presentation error",
    ).toBe("vp_token_auth_error");
    expect(verifier?.status_code, "the rejection is an HTTP 401").toBe(401);
  });
});
