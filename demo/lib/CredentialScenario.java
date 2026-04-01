package demo.lib;

public enum CredentialScenario {
    VALID_ALICE(
            "1",
            "Valid credential issued to Alice",
            "Expected result: authentication succeeds for Alice"),
    VALID_BOB(
            "2",
            "Valid credential issued to Bob",
            "Expected result: authentication succeeds for Bob"),
    UNKNOWN_USER(
            "3",
            "Valid credential issued to an unknown user",
            "Expected result: presentation is accepted, user lookup fails"),
    INVALID_ALICE(
            "4",
            "Invalid credential issued to Alice (expired)",
            "Expected result: credential validation fails");

    private final String choice;
    private final String label;
    private final String outcome;

    CredentialScenario(String choice, String label, String outcome) {
        this.choice = choice;
        this.label = label;
        this.outcome = outcome;
    }

    public String choice() {
        return choice;
    }

    public String label() {
        return label;
    }

    public String outcome() {
        return outcome;
    }

    public String username(DemoConfig cfg) {
        return switch (this) {
            case VALID_ALICE, INVALID_ALICE -> cfg.aliceUsername();
            case VALID_BOB -> cfg.bobUsername();
            case UNKNOWN_USER -> cfg.unknownUsername();
        };
    }

    public long expirationOffsetSeconds(long validLifetimeSeconds) {
        return switch (this) {
            case INVALID_ALICE -> -30;
            default -> validLifetimeSeconds;
        };
    }

    public static CredentialScenario fromChoice(String choice) {
        for (CredentialScenario scenario : values()) {
            if (scenario.choice.equalsIgnoreCase(choice)) {
                return scenario;
            }
        }
        return null;
    }
}
