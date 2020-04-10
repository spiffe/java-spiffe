package spiffe.workloadapi.internal;

import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSet;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;
import spiffe.workloadapi.X509Context;

public class GrpcConversionUtils {

    private static int DEFAULT_SVID = 0;

    public static Result<X509Context, Throwable> toX509Context(Workload.X509SVIDResponse x509SVIDResponse) {

        //TODO: complete this implementation

        Result<X509Svid, Throwable> svid = X509Svid.parse(
                x509SVIDResponse.getSvids(DEFAULT_SVID).getX509Svid().toByteArray(),
                x509SVIDResponse.getSvids(DEFAULT_SVID).getX509SvidKey().toByteArray());

        if (svid.isError()){
            return Result.error(svid.getError());
        }

        TrustDomain trustDomain = svid.getValue().getSpiffeId().getTrustDomain();
        Result<X509Bundle, Throwable> bundle = X509Bundle.parse(
                trustDomain,
                x509SVIDResponse.getSvids(DEFAULT_SVID).getBundle().toByteArray());

        if (bundle.isError()) {
            return Result.error(bundle.getError());
        }

        X509BundleSet bundleSet = X509BundleSet.of(trustDomain, bundle.getValue());
        X509Context result = new X509Context(svid.getValue(), bundleSet);
        return Result.ok(result);
    }
}
