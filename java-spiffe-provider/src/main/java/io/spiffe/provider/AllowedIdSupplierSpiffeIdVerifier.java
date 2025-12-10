package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Supplier;

public class AllowedIdSupplierSpiffeIdVerifier implements SpiffeIdVerifier {

    private final Supplier<Set<SpiffeId>> allowedSpiffeIdsSupplier;

    public AllowedIdSupplierSpiffeIdVerifier(Supplier<Set<SpiffeId>> allowedSpiffeIdsSupplier) {
        this.allowedSpiffeIdsSupplier = allowedSpiffeIdsSupplier;
    }

    @Override
    public void verify(SpiffeId spiffeId, X509Certificate[] verifiedChain) throws SpiffeVerificationException {
        Set<SpiffeId> allowedSpiffeIds = allowedSpiffeIdsSupplier.get();
        if (!allowedSpiffeIds.contains(spiffeId)) {
            throw new SpiffeVerificationException(String.format("SPIFFE ID %s in X.509 certificate is not accepted", spiffeId));
        }
    }
}
