// @ts-check

/**
 * Checks the authentication status periodically.
 *
 * @param {URL} statusUrl
 * @param {URL} codeRedemptionUrl
 * @param {string} transactionId
 * @param {string} codeVerifier
 * @param {number} period
 * @param {number} currentRetry
 * @param {number} maxRetries
 */
export async function checkAuthStatus(
  statusUrl,
  codeRedemptionUrl,
  transactionId,
  codeVerifier,
  period,
  currentRetry = 0,
  maxRetries = 30
) {
  if (currentRetry >= maxRetries) {
    return console.error("Polling timed out. Please reload to retry.");
  }

  try {
    const response = await fetch(statusUrl);
    if (response.status !== 200 && response.status !== 404) {
      throw new Error(`Unexpected response status: ${response.status}`);
    }

    const data = await response.json();

    if (data.status === "pending") {
      return setTimeout(
        () => checkAuthStatus(
          statusUrl, codeRedemptionUrl, transactionId, codeVerifier, period, 0, maxRetries
        ),
        period
      );
    }

    if (data.status !== "success") {
      return reportError(response.status, data.error_description);
    }

    const authorizationCode = await redeemAuthorizationCode(
      codeRedemptionUrl, transactionId, codeVerifier
    );
    submitForm(authorizationCode);
  } catch (error) {
    console.error("Error while polling:", error);
    setTimeout(
      () => checkAuthStatus(
        statusUrl, codeRedemptionUrl, transactionId, codeVerifier, period, currentRetry + 1, maxRetries
      ),
      period
    );
  }
}

/**
 * Redeems the authorization code using PKCE.
 *
 * @param {URL} url
 * @param {string} transactionId
 * @param {string} codeVerifier
 * @returns {Promise<string>}
 */
async function redeemAuthorizationCode(url, transactionId, codeVerifier) {
  const body = new URLSearchParams({
    transaction_id: transactionId,
    code_verifier: codeVerifier,
  });

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (response.status !== 200) {
    const data = await response.json();
    throw new Error(data.error_description || "Authorization code redemption failed");
  }

  const data = await response.json();
  return data.authorization_code;
}

/**
 * Handles submitting the authorization code.
 *
 * @param {string} code
 */
function submitForm(code) {
  const codeInput = document.getElementById("kc-oid4vp-code-input");
  const form = document.getElementById("kc-oid4vp-completion-form");
  if (!(codeInput instanceof HTMLInputElement) || !(form instanceof HTMLFormElement)) {
    throw new Error("OpenID4VP completion form elements are missing");
  }
  codeInput.value = code;
  form.submit();
}

/**
 * Handles reporting errors to the user.
 *
 * @param {number} httpStatus
 * @param {string} message
 */
function reportError(httpStatus, message) {
  if (httpStatus == 404) {
    console.warn("Session expired. Please reload to retry.");
  } else {
    console.error(message);
  }
}
