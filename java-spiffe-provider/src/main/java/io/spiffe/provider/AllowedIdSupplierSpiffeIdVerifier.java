package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Supplier;

public class AllowedIdSupplierSpiffeIdVerifier implements SpiffeIdVerifier {

    private final Supplier<Set<SpiffeId>> allowedSpiffeIdsSupplier;

    public AllowedIdSupplierSpiffeIdVerifier(@NonNull Supplier<Set<SpiffeId>> allowedSpiffeIdsSupplier) {
        this.allowedSpiffeIdsSupplier = allowedSpiffeIdsSupplier;
    }

    @Override
    public boolean verify(SpiffeId spiffeId, X509Certificate[] verifiedChain) {
        Set<SpiffeId> allowedSpiffeIds = allowedSpiffeIdsSupplier.get();
        return allowedSpiffeIds.contains(spiffeId);
    }
}
