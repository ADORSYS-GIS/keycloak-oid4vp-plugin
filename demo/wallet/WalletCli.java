package demo.wallet;

import demo.lib.CredentialScenario;
import demo.lib.DemoConfig;
import demo.lib.DemoRuntime;
import demo.lib.Oid4vpClient;
import demo.lib.Oid4vpResponseFactory;
import demo.lib.WalletPresentationService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.HttpClient;

public final class WalletCli {

    private WalletCli() {}

    public static void main(String[] args) throws Exception {
        DemoRuntime.bootstrapCrypto();

        DemoConfig cfg = DemoConfig.fromEnv();
        HttpClient http = DemoRuntime.newHttpClient();
        Oid4vpClient oid4vpClient = new Oid4vpClient(http, cfg);
        WalletPresentationService walletPresentationService = new WalletPresentationService(cfg);
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

        printBanner();

        while (true) {
            System.out.println();
            String offerLink =
                    prompt(input, "[wallet] Paste an OID4VP offer link (or 'q' to quit): ").trim();
            if (isExitCommand(offerLink)) {
                System.out.println("[wallet] Goodbye.");
                return;
            }
            if (offerLink.isBlank()) {
                System.out.println("[wallet] Please paste a non-empty offer link.");
                continue;
            }

            try {
                RequestObject requestObject = oid4vpClient.resolveRequestObject(offerLink);
                System.out.println("[wallet] Resolved request object.");
                System.out.println("[wallet] verifier client_id: " + requestObject.getClientId());
                System.out.println(
                        "[wallet] response format: "
                                + Oid4vpResponseFactory.describeResponseFormat(requestObject));

                CredentialScenario scenario = chooseScenario(input);
                if (scenario == null) {
                    System.out.println("[wallet] Returning to link prompt.");
                    continue;
                }

                try {
                    String vpToken = walletPresentationService.buildPresentation(requestObject, scenario);
                    oid4vpClient.submitPresentation(requestObject, vpToken);

                    System.out.println(
                            "[wallet] Sent presentation using scenario: " + scenario.label());
                    System.out.println("[wallet] " + scenario.outcome());
                    System.out.println("[wallet] The wallet's job is done for this request.");
                } catch (Exception e) {
                    System.out.println("[wallet] Presentation submission failed.");
                    System.out.println("[wallet] details: " + DemoRuntime.rootCauseMessage(e));
                }
            } catch (Exception e) {
                System.out.println(
                        "[wallet] Failed to resolve or parse the offer link: "
                                + DemoRuntime.rootCauseMessage(e));
            }
        }
    }

    private static void printBanner() {
        System.out.println("OID4VP Demo Wallet");
        System.out.println("==================");
        System.out.println("[wallet] This wallet is intentionally minimal and hardcoded for the demo.");
    }

    private static boolean isExitCommand(String value) {
        return value.equalsIgnoreCase("q")
                || value.equalsIgnoreCase("quit")
                || value.equalsIgnoreCase("exit");
    }

    private static CredentialScenario chooseScenario(BufferedReader input) throws Exception {
        System.out.println("[wallet] Choose a credential to present:");
        for (CredentialScenario scenario : CredentialScenario.values()) {
            System.out.println("  " + scenario.choice() + ") " + scenario.label());
            System.out.println("     " + scenario.outcome());
        }
        System.out.println("  b) Back");

        String choice = prompt(input, "[wallet] > ").trim().toLowerCase();
        if (choice.equals("b") || choice.equals("back")) {
            return null;
        }

        CredentialScenario scenario = CredentialScenario.fromChoice(choice);
        if (scenario == null) {
            System.out.println("[wallet] Unknown option. Try again.");
            return chooseScenario(input);
        }

        return scenario;
    }

    private static String prompt(BufferedReader input, String prompt) throws Exception {
        System.out.print(prompt);
        String line = input.readLine();
        return line == null ? "" : line;
    }
}
