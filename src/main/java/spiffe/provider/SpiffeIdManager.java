package spiffe.provider;

import spiffe.api.svid.Fetcher;
import spiffe.api.svid.Workload.X509SVID;
import spiffe.api.svid.X509SVIDFetcher;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import static java.util.Collections.EMPTY_SET;

/**
 * Handles the instance of Spiffe SVID that represents the identity of a workload
 *
 * It gets SVID updates asynchronously from the Workload API
 *
 */
class SpiffeIdManager {

    private static final SpiffeIdManager INSTANCE = new SpiffeIdManager();

    static SpiffeIdManager getInstance() {
        return INSTANCE;
    }

    private SpiffeSVID spiffeSVID;

    /**
     * Private Constructor
     *
     * Registers a certificate updater callback to get the SVID updates from the WorkloadAPI
     *
     */
    private SpiffeIdManager() {
        Consumer<List<X509SVID>> certificateUpdater = certs -> {
            X509SVID svid  = certs.get(0);
            spiffeSVID = new SpiffeSVID(svid);
        };
        Fetcher<List<X509SVID>> svidFetcher = new X509SVIDFetcher();
        svidFetcher.registerListener(certificateUpdater);
    }

    X509Certificate getCertificate() {
        if (spiffeSVID != null) {
            return spiffeSVID.getCertificate();
        }
        return null;
    }

    PrivateKey getPrivateKey() {
        if (spiffeSVID != null) {
            return spiffeSVID.getPrivateKey();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    Set<X509Certificate> getTrustedCerts() {
        if (spiffeSVID != null) {
            return spiffeSVID.getBundle();
        }
        return EMPTY_SET;
    }
}
