package de.adorsys.gis.keycloak.protocol.oid4vc.crypto;

import de.adorsys.gis.keycloak.protocol.oid4vc.crypto.certificate.ExtendedBCCertificateUtilsProvider;
import de.adorsys.gis.keycloak.protocol.oid4vc.crypto.certificate.ExtendedCertificateUtilsProvider;
import org.jboss.logging.Logger;
import org.keycloak.crypto.def.DefaultCryptoProvider;

public class ExtendedDefaultCryptoProvider extends DefaultCryptoProvider {

    private static final Logger logger = Logger.getLogger(ExtendedDefaultCryptoProvider.class);

    @Override
    public int order() {
        // FIXME!!! This does not work. Need to find a way to override DefaultCryptoProvider.
        logger.debugf("Loading ExtendedDefaultCryptoProvider with high priority to override DefaultCryptoProvider");
        return 10000;
    }

    @Override
    public ExtendedCertificateUtilsProvider getCertificateUtils() {
        return new ExtendedBCCertificateUtilsProvider();
    }
}
