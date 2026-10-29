// Plain JSON result of a wallet API call: the tests decide what status is
// expected (e.g. presenting a *valid* credential vs a *revoked* one must
// succeed / fail respectively).
export type WalletResult = { status: number; body: any };

import { WALLET_BASE_URL } from "./config";

// Client for the eudi-dev test wallet HTTP API (see
// https://github.com/eudi-dev/eudi-dev — no auth needed on localhost).
export class TestWallet {
  constructor(readonly baseUrl = WALLET_BASE_URL) {}

  private async post(path: string, payload: unknown): Promise<WalletResult> {
    const res = await fetch(this.baseUrl + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    let parsed: any;
    const text = await res.text();
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
    return { status: res.status, body: parsed };
  }

  /** Ask the wallet to redeem a pre-authorized credential offer (OID4VCI). */
  async takeOfferToWallet(uri: string) {
    return this.post("/api/offers", { uri, interactive: false });
  }

  /** Fetch a stored credential, including its raw SD-JWT. */
  async getCredential(credentialId: string): Promise<WalletResult> {
    const res = await fetch(`${this.baseUrl}/api/credentials/${credentialId}`);
    let parsed: any;
    const text = await res.text();
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = {};
    }
    return { status: res.status, body: parsed };
  }

  /** Ask the wallet to present a credential to the verifier's OID4VP request. */
  async presentCredential(uri: string) {
    return this.post("/api/presentations", { uri });
  }
}
