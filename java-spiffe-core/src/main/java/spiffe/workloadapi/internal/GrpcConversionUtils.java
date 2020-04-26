package spiffe.workloadapi.internal;

import lombok.val;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSet;
import spiffe.exception.X509SvidException;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.x509svid.X509Svid;
import spiffe.workloadapi.X509Context;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility methods for converting GRPC objects to JAVA-SPIFFE domain objects.
 */
public class GrpcConversionUtils {

    public static X509Context toX509Context(Workload.X509SVIDResponse x509SVIDResponse) throws CertificateException, X509SvidException {
        List<X509Svid> x509SvidList = getListOfX509Svid(x509SVIDResponse);
        List<X509Bundle> x509BundleList = getListOfX509Bundles(x509SVIDResponse);
        X509BundleSet bundleSet = X509BundleSet.of(x509BundleList);
        return new X509Context(x509SvidList, bundleSet);
    }

    private static List<X509Bundle> getListOfX509Bundles(Workload.X509SVIDResponse x509SVIDResponse) throws CertificateException {
        List<X509Bundle> x509BundleList = new ArrayList<>();
        for (Workload.X509SVID x509SVID : x509SVIDResponse.getSvidsList()) {
            SpiffeId spiffeId = SpiffeId.parse(x509SVID.getSpiffeId());

            X509Bundle bundle = X509Bundle.parse(
                    spiffeId.getTrustDomain(),
                    x509SVID.getBundle().toByteArray());
            x509BundleList.add(bundle);
        }
        return x509BundleList;
    }

    private static List<X509Svid> getListOfX509Svid(Workload.X509SVIDResponse x509SVIDResponse) throws X509SvidException {
        List<X509Svid> x509SvidList = new ArrayList<>();
        for (Workload.X509SVID x509SVID : x509SVIDResponse.getSvidsList()) {
            val svid = X509Svid.parse(
                    x509SVID.getX509Svid().toByteArray(),
                    x509SVID.getX509SvidKey().toByteArray());
            x509SvidList.add(svid);
        }
        return x509SvidList;
    }
}
