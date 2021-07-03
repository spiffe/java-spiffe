package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.grpc.Workload;
import lombok.val;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Utility methods for converting GRPC objects to JAVA-SPIFFE domain objects.
 */
final class GrpcConversionUtils {

    private GrpcConversionUtils() {
    }

    static X509Context toX509Context(final Iterator<Workload.X509SVIDResponse> x509SvidResponseIterator) throws X509ContextException {
        if (!x509SvidResponseIterator.hasNext()) {
            throw new X509ContextException("X.509 Context response from the Workload API is empty");
        }

        val x509SvidResponse = x509SvidResponseIterator.next();
        return toX509Context(x509SvidResponse);
    }

    static X509Context toX509Context(final Workload.X509SVIDResponse x509SvidResponse) throws X509ContextException {
        if (x509SvidResponse.getSvidsList() == null || x509SvidResponse.getSvidsList().isEmpty()) {
            throw new X509ContextException("X.509 Context response from the Workload API is empty");
        }

        val x509SvidList = getListOfX509Svid(x509SvidResponse);
        val x509BundleList = getListOfX509Bundles(x509SvidResponse);
        val bundleSet = X509BundleSet.of(x509BundleList);
        return X509Context.of(x509SvidList, bundleSet);
    }

    public static X509BundleSet toX509BundleSet(Iterator<Workload.X509BundlesResponse> bundlesResponseIterator) throws X509BundleException {
        if (!bundlesResponseIterator.hasNext()) {
            throw new X509BundleException("X.509 Bundle response from the Workload API is empty");
        }

        val bundlesResponse = bundlesResponseIterator.next();
        return toX509BundleSet(bundlesResponse);
    }

    static X509BundleSet toX509BundleSet(final Workload.X509BundlesResponse bundlesResponse) throws X509BundleException {
        val bundlesCount = bundlesResponse.getBundlesCount();
        if (bundlesCount == 0) {
            throw new X509BundleException("X.509 Bundle response from the Workload API is empty");
        }

        final List<X509Bundle> x509Bundles = new ArrayList<>(bundlesCount);
        for (Map.Entry<String, ByteString> entry : bundlesResponse.getBundlesMap().entrySet()) {
            X509Bundle x509Bundle = createX509Bundle(entry);
            x509Bundles.add(x509Bundle);
        }
        return X509BundleSet.of(x509Bundles);
    }

    static JwtBundleSet toJwtBundleSet(final Iterator<Workload.JWTBundlesResponse> bundlesResponseIterator) throws JwtBundleException {
        if (!bundlesResponseIterator.hasNext()) {
            throw new JwtBundleException("JWT Bundle response from the Workload API is empty");
        }

        val bundlesResponse = bundlesResponseIterator.next();
        return toJwtBundleSet(bundlesResponse);
    }

    static JwtBundleSet toJwtBundleSet(final Workload.JWTBundlesResponse bundlesResponse) throws JwtBundleException {
        if (bundlesResponse.getBundlesMap().size() == 0) {
            throw new JwtBundleException("JWT Bundle response from the Workload API is empty");
        }

        final List<JwtBundle> jwtBundles = new ArrayList<>();
        for (Map.Entry<String, ByteString> entry : bundlesResponse.getBundlesMap().entrySet()) {
            JwtBundle jwtBundle = createJwtBundle(entry);
            jwtBundles.add(jwtBundle);
        }
        return JwtBundleSet.of(jwtBundles);
    }

    static X509Bundle parseX509Bundle(TrustDomain trustDomain, byte[] bundleBytes) throws X509ContextException {
        try {
            return X509Bundle.parse(trustDomain, bundleBytes);
        } catch (X509BundleException e) {
            throw new X509ContextException("X.509 Bundles could not be processed", e);
        }
    }


    private static List<X509Bundle> getListOfX509Bundles(final Workload.X509SVIDResponse x509SvidResponse) throws X509ContextException {
        final List<X509Bundle> x509BundleList = new ArrayList<>();
        for (Workload.X509SVID x509Svid : x509SvidResponse.getSvidsList()) {
            X509Bundle bundle = createX509Bundle(x509Svid);
            x509BundleList.add(bundle);
        }

        // Process federated bundles
        Set<Map.Entry<String, ByteString>> federatedBundles = x509SvidResponse.getFederatedBundlesMap().entrySet();
        for (Map.Entry<String, ByteString> bundleEntry : federatedBundles) {
            TrustDomain trustDomain = TrustDomain.parse(bundleEntry.getKey());
            byte[] bundleBytes = bundleEntry.getValue().toByteArray();
            val bundle = parseX509Bundle(trustDomain, bundleBytes);
            x509BundleList.add(bundle);
        }

        return x509BundleList;
    }

    private static X509Bundle createX509Bundle(Workload.X509SVID x509Svid) throws X509ContextException {
        val spiffeId = SpiffeId.parse(x509Svid.getSpiffeId());
        TrustDomain trustDomain = spiffeId.getTrustDomain();
        byte[] bundleBytes = x509Svid.getBundle().toByteArray();
        return parseX509Bundle(trustDomain, bundleBytes);
    }

    private static List<X509Svid> getListOfX509Svid(final Workload.X509SVIDResponse x509SvidResponse) throws X509ContextException{

        final List<X509Svid> result = new ArrayList<>();

        for (Workload.X509SVID x509SVID : x509SvidResponse.getSvidsList()) {
            val svid = createAndValidateX509Svid(x509SVID);
            result.add(svid);
        }
        return result;
    }

    private static X509Svid createAndValidateX509Svid(Workload.X509SVID x509SVID) throws X509ContextException {
        byte[] certsBytes = x509SVID.getX509Svid().toByteArray();
        byte[] privateKeyBytes = x509SVID.getX509SvidKey().toByteArray();

        X509Svid svid = null;
        try {
            svid = X509Svid.parseRaw(certsBytes, privateKeyBytes);
        } catch (X509SvidException e) {
            throw new X509ContextException("X.509 SVID response could not be processed", e);
        }

        val spiffeIdResponse = x509SVID.getSpiffeId();
        val spiffeIdSvid = svid.getSpiffeId();
        validateSpiffeId(spiffeIdSvid.toString(), spiffeIdResponse);
        return svid;
    }

    private static void validateSpiffeId(String spiffeIdSvid, String spiffeIdResponse) throws X509ContextException {
        if (!spiffeIdSvid.equals(spiffeIdResponse.trim())) {
            val format = "SPIFFE ID in X509SVIDResponse (%s) does not match SPIFFE ID in X.509 certificate (%s)";
            throw new X509ContextException(String.format(format, spiffeIdResponse, spiffeIdSvid));
        }
    }

    private static JwtBundle createJwtBundle(Map.Entry<String, ByteString> entry) throws JwtBundleException {
        TrustDomain trustDomain = TrustDomain.parse(entry.getKey());
        byte[] bundleBytes = entry.getValue().toByteArray();
        return JwtBundle.parse(trustDomain, bundleBytes);
    }

    private static X509Bundle createX509Bundle(Map.Entry<String, ByteString> bundleEntry) throws X509BundleException {
        TrustDomain trustDomain = TrustDomain.parse(bundleEntry.getKey());
        byte[] bundleBytes = bundleEntry.getValue().toByteArray();
        return X509Bundle.parse(trustDomain, bundleBytes);
    }
}
