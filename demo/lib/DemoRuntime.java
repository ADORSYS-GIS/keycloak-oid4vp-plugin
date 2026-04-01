package demo.lib;

import java.net.http.HttpClient;
import java.time.Duration;
import org.keycloak.common.crypto.CryptoIntegration;

public final class DemoRuntime {

    private DemoRuntime() {}

    public static void bootstrapCrypto() {
        CryptoIntegration.init(DemoRuntime.class.getClassLoader());
    }

    public static HttpClient newHttpClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public static String rootCauseMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage();
    }
}
