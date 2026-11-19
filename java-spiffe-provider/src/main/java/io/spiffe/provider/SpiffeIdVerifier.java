package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies the SPIFFE ID of a peer's X.509-SVID during a TLS handshake.
 * <p>
 * A verifier is called after the peer's certificate chain has been verified against the X.509 bundles, and decides
 * whether the peer is authorized. The static factory methods return verifiers for the common cases: accepting any
 * SPIFFE ID, a specific SPIFFE ID, one of a set of SPIFFE IDs, or any SPIFFE ID in a trust domain.
 */
public interface SpiffeIdVerifier {
    /**
     * Verify that an X509-SVID is acceptable. This method receives the SPIFFE ID of the SVID and the certificate
     * chain.
     *
     * @param spiffeId the SPIFFE ID of the SVID
     * @param verifiedChain the certificate chain with the X509-SVID certificate back to an X.509 root for the trust domain.
     * @throws SpiffeVerificationException if there was an error verifying the SPIFFE ID or it wasn't considered valid.
     */
    public void verify(SpiffeId spiffeId, X509Certificate[] verifiedChain) throws SpiffeVerificationException;

    /**
     * Returns a verifier that accepts any SPIFFE ID.
     *
     * @return a {@link SpiffeIdVerifier} that accepts any SPIFFE ID
     */
    static SpiffeIdVerifier acceptAny() {
        return (spiffeId, verifiedChain) -> {
        };
    }

    /**
     * Returns a verifier that accepts only the given SPIFFE ID.
     *
     * @param allowedSpiffeId the SPIFFE ID to accept
     * @return a {@link SpiffeIdVerifier} that accepts only {@code allowedSpiffeId}
     * @throws NullPointerException if {@code allowedSpiffeId} is null
     */
    static SpiffeIdVerifier acceptId(final SpiffeId allowedSpiffeId) {
        Objects.requireNonNull(allowedSpiffeId, "allowedSpiffeId must not be null");
        return (spiffeId, verifiedChain) -> {
            if (!allowedSpiffeId.equals(spiffeId)) {
                throw new SpiffeVerificationException(
                        String.format("SPIFFE ID %s in X.509 certificate is not accepted", spiffeId));
            }
        };
    }

    /**
     * Returns a verifier that accepts any of the given SPIFFE IDs.
     * <p>
     * The SPIFFE IDs are copied, so later changes to the array don't affect the verifier. A verifier created without
     * SPIFFE IDs rejects every SPIFFE ID.
     *
     * @param allowedSpiffeIds the SPIFFE IDs to accept
     * @return a {@link SpiffeIdVerifier} that accepts only the SPIFFE IDs in {@code allowedSpiffeIds}
     * @throws NullPointerException if {@code allowedSpiffeIds} or any of its elements is null
     */
    static SpiffeIdVerifier acceptOneOf(final SpiffeId... allowedSpiffeIds) {
        Objects.requireNonNull(allowedSpiffeIds, "allowedSpiffeIds must not be null");
        return acceptOneOf(Arrays.asList(allowedSpiffeIds));
    }

    /**
     * Returns a verifier that accepts any of the given SPIFFE IDs.
     * <p>
     * The SPIFFE IDs are copied, so later changes to the collection don't affect the verifier. To accept a set of
     * SPIFFE IDs that changes over time, create a {@link SpiffeTrustManager} with a {@link java.util.function.Supplier}
     * of SPIFFE IDs, or set {@code acceptedSpiffeIdsSupplier} in the
     * {@link SpiffeSslContextFactory.SslContextOptions}. A verifier created with an empty collection rejects every
     * SPIFFE ID.
     *
     * @param allowedSpiffeIds the SPIFFE IDs to accept
     * @return a {@link SpiffeIdVerifier} that accepts only the SPIFFE IDs in {@code allowedSpiffeIds}
     * @throws NullPointerException if {@code allowedSpiffeIds} or any of its elements is null
     */
    static SpiffeIdVerifier acceptOneOf(final Collection<SpiffeId> allowedSpiffeIds) {
        Objects.requireNonNull(allowedSpiffeIds, "allowedSpiffeIds must not be null");
        final Set<SpiffeId> allowed = new HashSet<>();
        for (SpiffeId allowedSpiffeId : allowedSpiffeIds) {
            allowed.add(Objects.requireNonNull(allowedSpiffeId, "allowedSpiffeIds must not contain null elements"));
        }
        return (spiffeId, verifiedChain) -> {
            if (!allowed.contains(spiffeId)) {
                throw new SpiffeVerificationException(
                        String.format("SPIFFE ID %s in X.509 certificate is not accepted", spiffeId));
            }
        };
    }

    /**
     * Returns a verifier that accepts any SPIFFE ID in the given trust domain.
     *
     * @param trustDomain the trust domain whose SPIFFE IDs are accepted
     * @return a {@link SpiffeIdVerifier} that accepts only SPIFFE IDs that are members of {@code trustDomain}
     * @throws NullPointerException if {@code trustDomain} is null
     */
    static SpiffeIdVerifier acceptMemberOf(final TrustDomain trustDomain) {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        return (spiffeId, verifiedChain) -> {
            if (spiffeId == null || !spiffeId.memberOf(trustDomain)) {
                throw new SpiffeVerificationException(String.format(
                        "SPIFFE ID %s in X.509 certificate is not a member of trust domain %s", spiffeId, trustDomain));
            }
        };
    }
}
