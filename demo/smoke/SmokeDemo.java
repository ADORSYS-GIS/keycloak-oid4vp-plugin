package demo.smoke;

import com.fasterxml.jackson.databind.JsonNode;
import demo.lib.DemoSupport;
import demo.lib.DemoSupport.CredentialScenario;
import demo.lib.DemoSupport.DemoConfig;
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
        DemoSupport.bootstrapCrypto();

        DemoConfig cfg = DemoConfig.fromEnv();
        HttpClient http = DemoSupport.newHttpClient();

        log("Starting one-shot smoke flow");
        AuthorizationContext authContext = DemoSupport.requestAuthorizationContext(http, cfg);
        log("Received authorization_request and transaction_id");

        RequestObject requestObject = DemoSupport.resolveRequestObject(http, authContext);
        log("Resolved request object");

        String vpToken = DemoSupport.presentScenario(cfg, CredentialScenario.VALID_ALICE, requestObject);
        DemoSupport.submitPresentation(http, requestObject, vpToken);
        log("Submitted OpenID4VP response");

        AuthorizationContext status = DemoSupport.pollUntilTerminal(
                http, cfg, authContext.getTransactionId(), 30, Duration.ofSeconds(1));
        if (status.getStatus() != AuthorizationContextStatus.SUCCESS) {
            throw new IllegalStateException("Authentication failed: " + status.getErrorDescription());
        }
        log("Authentication succeeded. Received authorization_code");

        JsonNode tokenResponse = DemoSupport.exchangeAuthorizationCode(http, cfg, status.getAuthorizationCode());
        String accessTokenStr = tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
        AccessToken accessToken = DemoSupport.parseAccessToken(accessTokenStr);

        log("Access token issued for user: " + accessToken.getPreferredUsername());
        log("Issuer: " + accessToken.getIssuer());
        log("Smoke flow complete.");
    }

    private static void log(String message) {
        System.out.println("[smoke] " + message);
    }
}
