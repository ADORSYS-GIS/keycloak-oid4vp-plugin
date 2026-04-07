package demo.app;

import com.fasterxml.jackson.databind.JsonNode;
import demo.lib.DemoConfig;
import demo.lib.DemoRuntime;
import demo.lib.Oid4vpClient;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.AccessToken;

public final class AppCli {

    private static final Duration POLL_INTERVAL = Duration.ofSeconds(1);
    private static final int POLL_ATTEMPTS = 90;
    private static final String[] SPINNER = {"|", "/", "-", "\\"};

    private AppCli() {}

    public static void main(String[] args) throws Exception {
        DemoRuntime.bootstrapCrypto();

        DemoConfig cfg = DemoConfig.fromEnv();
        HttpClient http = DemoRuntime.newHttpClient();
        Oid4vpClient oid4vpClient = new Oid4vpClient(http, cfg);
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

        printBanner(cfg);

        while (true) {
            System.out.println();
            System.out.println("[app] Choose an action:");
            System.out.println("  1) Start an authentication flow");
            System.out.println("  q) Stop the app and tear everything down");

            String choice = prompt(input, "[app] > ").trim().toLowerCase();
            switch (choice) {
                case "1", "s", "start" -> startAuthenticationFlow(oid4vpClient, input);
                case "q", "quit", "exit" -> {
                    System.out.println("[app] Stopping app...");
                    return;
                }
                default -> System.out.println("[app] Unknown option. Choose '1' or 'q'.");
            }
        }
    }

    private static void startAuthenticationFlow(Oid4vpClient oid4vpClient, BufferedReader input) {
        try {
            AuthorizationContext authContext = oid4vpClient.startAuthentication();

            System.out.println();
            System.out.println("[app] Authentication flow started.");
            System.out.println("[app] Copy this offer link into the wallet terminal:");
            System.out.println();
            System.out.println(authContext.getAuthorizationRequest());
            System.out.println();
            System.out.println(
                    "[app] The app is now polling transaction status in the background...");

            // Poll asynchronously so the app can keep acting like a separate terminal from the wallet.
            CompletableFuture<AuthorizationContext> poller = CompletableFuture.supplyAsync(() -> {
                try {
                    return oid4vpClient.pollUntilTerminal(
                            authContext.getTransactionId(), POLL_ATTEMPTS, POLL_INTERVAL);
                } catch (Exception e) {
                    throw new CompletionException(e);
                }
            });

            int tick = 0;
            while (!poller.isDone()) {
                System.out.print("\r[app] Waiting for wallet presentation " + SPINNER[tick++ % SPINNER.length]);
                Thread.sleep(250);
            }
            System.out.print("\r");
            System.out.println(" ".repeat(70));
            System.out.print("\r");

            AuthorizationContext status = poller.join();
            if (status.getStatus() == AuthorizationContextStatus.ERROR) {
                System.out.println("[app] Authentication failed.");
                System.out.println("[app] error: " + status.getError());
                System.out.println("[app] details: " + status.getErrorDescription());
                return;
            }

            System.out.println("[app] Authentication succeeded.");
            System.out.println("[app] authorization_code: " + status.getAuthorizationCode());

            if (confirm(input, "[app] Retrieve an access token now? [Y/n] ", true)) {
                JsonNode tokenResponse =
                        oid4vpClient.exchangeAuthorizationCode(status.getAuthorizationCode());
                String accessTokenStr = tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
                AccessToken accessToken = oid4vpClient.readAccessToken(accessTokenStr);

                System.out.println("[app] Access token retrieved.");
                System.out.println(
                        "[app] preferred_username: " + accessToken.getPreferredUsername());
                System.out.println("[app] subject: " + accessToken.getSubject());
                System.out.println("[app] issuer: " + accessToken.getIssuer());
            }
        } catch (CompletionException e) {
            System.out.println("[app] Polling failed: " + DemoRuntime.rootCauseMessage(e));
        } catch (Exception e) {
            System.out.println("[app] Flow failed: " + DemoRuntime.rootCauseMessage(e));
        }
    }

    private static void printBanner(DemoConfig cfg) {
        System.out.println("OID4VP Demo App");
        System.out.println("================");
        System.out.println("[app] Keycloak: " + cfg.baseUrl());
        System.out.println("[app] Realm: " + cfg.realm());
        System.out.println("[app] OIDC client: " + cfg.clientId());
        System.out.println(
                "[app] Demo users in realm: " + cfg.aliceUsername() + ", " + cfg.bobUsername());
    }

    private static boolean confirm(BufferedReader input, String prompt, boolean defaultYes) throws Exception {
        String raw = prompt(input, prompt).trim().toLowerCase();
        if (raw.isEmpty()) {
            return defaultYes;
        }
        return switch (raw) {
            case "y", "yes" -> true;
            case "n", "no" -> false;
            default -> defaultYes;
        };
    }

    private static String prompt(BufferedReader input, String prompt) throws Exception {
        System.out.print(prompt);
        String line = input.readLine();
        return line == null ? "" : line;
    }
}
