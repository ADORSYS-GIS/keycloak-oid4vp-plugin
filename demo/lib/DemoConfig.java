package demo.lib;

// Small immutable view of the environment knobs the demo code actually needs.
public record DemoConfig(
        String baseUrl,
        String realm,
        String clientId,
        String clientSecret,
        String aliceUsername,
        String bobUsername,
        String unknownUsername,
        String vct,
        String issuer,
        String issuerJwkPath,
        String holderJwkPath) {

    public static DemoConfig fromEnv() {
        String baseUrl = env("DEMO_BASE_URL", "http://localhost:18080");
        String realm = env("DEMO_REALM", "oid4vp-demo");
        String clientId = env("DEMO_CLIENT_ID", "test-app");
        String clientSecret = env("DEMO_CLIENT_SECRET", "password");
        String aliceUsername = env("DEMO_ALICE_USERNAME", "alice@localhost");
        String bobUsername = env("DEMO_BOB_USERNAME", "bob@localhost");
        String unknownUsername = env("DEMO_UNKNOWN_USERNAME", "mallory@localhost");
        String vct = env("DEMO_VCT", "https://credentials.example.com/identity_credential");
        String issuerJwk = env("DEMO_ISSUER_JWK", "demo/keys/keycloak.json");
        String holderJwk = env("DEMO_HOLDER_JWK", "demo/keys/user-wallet-key.json");

        return new DemoConfig(
                baseUrl,
                realm,
                clientId,
                clientSecret,
                aliceUsername,
                bobUsername,
                unknownUsername,
                vct,
                baseUrl + "/realms/" + realm,
                issuerJwk,
                holderJwk);
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? defaultValue : value;
    }
}
