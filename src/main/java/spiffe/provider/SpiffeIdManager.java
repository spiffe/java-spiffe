package spiffe.provider;

import spiffe.api.svid.Fetcher;
import spiffe.api.svid.Workload.X509SVID;
import spiffe.api.svid.X509SVIDFetcher;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

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

    /**
     * The Spiffe SVID handled by this manager
     */
    private SpiffeSVID spiffeSVID;

    /**
     * Used to synchronize spiffeSVID writes and reads
     */
    private final FunctionalReadWriteLock guard;

    /**
     * Private Constructor
     *
     * Registers a certificate updater callback to get the SVID updates from the WorkloadAPI
     *
     */
    private SpiffeIdManager() {
        guard = new FunctionalReadWriteLock();
        Fetcher<List<X509SVID>> svidFetcher = new X509SVIDFetcher();
        svidFetcher.registerListener(this::updateSVID);
    }

    /**
     * Method used as callback that gets executed whenever an SVID update is pushed by the Workload API
     * Uses a write lock to synchronize access to spiffeSVID
     */
    private void updateSVID(List<X509SVID> certs) {
        X509SVID svid  = certs.get(0);
        guard.write(() -> spiffeSVID = new SpiffeSVID(svid));
    }

    X509Certificate getCertificate() {
        return guard.read(() -> spiffeSVID != null ? spiffeSVID.getCertificate() : null);
    }

    PrivateKey getPrivateKey() {
        return guard.read(() -> spiffeSVID != null ? spiffeSVID.getPrivateKey() : null);
    }

    @SuppressWarnings("unchecked")
    Set<X509Certificate> getTrustedCerts() {
        return guard.read(() -> spiffeSVID != null ? spiffeSVID.getBundle() : EMPTY_SET);
    }
}
