package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509SvidException;
import lombok.val;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.grpc.Workload;

import java.security.KeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for converting GRPC objects to JAVA-SPIFFE domain objects.
 */
class GrpcConversionUtils {

    private GrpcConversionUtils() {}

    static X509Context toX509Context(final Workload.X509SVIDResponse x509SVIDResponse)
            throws CertificateException, X509SvidException {

        val  x509SvidList = getListOfX509Svid(x509SVIDResponse);
        val x509BundleList = getListOfX509Bundles(x509SVIDResponse);
        val bundleSet = X509BundleSet.of(x509BundleList);
        return new X509Context(x509SvidList, bundleSet);
    }

    static List<X509Bundle> getListOfX509Bundles(final Workload.X509SVIDResponse x509SVIDResponse)
            throws CertificateException {

        final List<X509Bundle> x509BundleList = new ArrayList<>();
        for (Workload.X509SVID x509Svid : x509SVIDResponse.getSvidsList()) {
            val spiffeId = SpiffeId.parse(x509Svid.getSpiffeId());
            val bundle = X509Bundle.parse(spiffeId.getTrustDomain(), x509Svid.getBundle().toByteArray());
            x509BundleList.add(bundle);
        }

        // Process federated bundles
        for (Map.Entry<String, ByteString> bundleEntry : x509SVIDResponse.getFederatedBundlesMap().entrySet()) {
            val bundle = X509Bundle.parse(TrustDomain.of(bundleEntry.getKey()), bundleEntry.getValue().toByteArray());
            x509BundleList.add(bundle);
        }

        return x509BundleList;
    }

    private static List<X509Svid> getListOfX509Svid(final Workload.X509SVIDResponse x509SVIDResponse)
            throws X509SvidException {

        final List<X509Svid> x509SvidList = new ArrayList<>();

        for (Workload.X509SVID x509SVID : x509SVIDResponse.getSvidsList()) {
            val svid = X509Svid.parseRaw(x509SVID.getX509Svid().toByteArray(), x509SVID.getX509SvidKey().toByteArray());
            x509SvidList.add(svid);

            if (!x509SVID.getSpiffeId().equals(svid.getSpiffeId().toString())) {
                val format = "SPIFFE ID in X509SVIDResponse (%s) does not match SPIFFE ID in X.509 certificate (%s)";
                throw new X509SvidException(String.format(format, x509SVID.getSpiffeId(), svid.getSpiffeId()));
            }
        }
        return x509SvidList;
    }

    public static JwtBundleSet toBundleSet(final Workload.JWTBundlesResponse bundlesResponse) throws KeyException, JwtBundleException {
        final List<JwtBundle> jwtBundles = new ArrayList<>();
        for (Map.Entry<String, ByteString> entry : bundlesResponse.getBundlesMap().entrySet()) {
            val jwtBundle = JwtBundle.parse(TrustDomain.of(entry.getKey()), entry.getValue().toByteArray());
            jwtBundles.add(jwtBundle);
        }
        return JwtBundleSet.of(jwtBundles);
    }
}
