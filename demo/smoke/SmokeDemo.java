package demo.smoke;

import com.fasterxml.jackson.databind.JsonNode;
import demo.lib.CredentialScenario;
import demo.lib.DemoConfig;
import demo.lib.DemoRuntime;
import demo.lib.Oid4vpClient;
import demo.lib.WalletPresentationService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import java.net.http.HttpClient;
import java.time.Duration;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.AccessToken;

public final class SmokeDemo {

    private SmokeDemo() {}

    public static void main(String[] args) throws Exception {
        DemoRuntime.bootstrapCrypto();

        DemoConfig cfg = DemoConfig.fromEnv();
        HttpClient http = DemoRuntime.newHttpClient();
        Oid4vpClient oid4vpClient = new Oid4vpClient(http, cfg);
        WalletPresentationService walletPresentationService = new WalletPresentationService(cfg);

        log("Starting one-shot smoke flow");
        AuthorizationContext authContext = oid4vpClient.startAuthentication();
        log("Received authorization_request and transaction_id");

        RequestObject requestObject = oid4vpClient.resolveRequestObject(authContext);
        log("Resolved request object");

        String vpToken =
                walletPresentationService.buildPresentation(requestObject, CredentialScenario.VALID_ALICE);
        oid4vpClient.submitPresentation(requestObject, vpToken);
        log("Submitted OpenID4VP response");

        AuthorizationContext status =
                oid4vpClient.pollUntilTerminal(authContext.getTransactionId(), 30, Duration.ofSeconds(1));
        if (status.getStatus() != AuthorizationContextStatus.SUCCESS) {
            throw new IllegalStateException("Authentication failed: " + status.getErrorDescription());
        }
        log("Authentication succeeded. Received authorization_code");

        JsonNode tokenResponse = oid4vpClient.exchangeAuthorizationCode(status.getAuthorizationCode());
        String accessTokenStr = tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
        AccessToken accessToken = oid4vpClient.readAccessToken(accessTokenStr);

        log("Access token issued for user: " + accessToken.getPreferredUsername());
        log("Issuer: " + accessToken.getIssuer());
        log("Smoke flow complete.");
    }

    private static void log(String message) {
        System.out.println("[smoke] " + message);
    }
}
