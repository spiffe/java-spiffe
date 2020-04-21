package spiffe.workloadapi.internal;

import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSet;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.x509svid.X509Svid;
import spiffe.workloadapi.X509Context;

import java.util.ArrayList;
import java.util.List;

public class GrpcConversionUtils {

    public static Result<X509Context, String> toX509Context(Workload.X509SVIDResponse x509SVIDResponse) {
        Result<List<X509Svid>, String> x509SvidListResult = getListOfX509Svid(x509SVIDResponse);
        if (x509SvidListResult.isError()) {
            return Result.error(x509SvidListResult.getError());
        }

        Result<List<X509Bundle>, String> x509BundleListResult = getListOfX509Bundles(x509SVIDResponse);
        if (x509BundleListResult.isError()) {
            return Result.error(x509BundleListResult.getError());
        }

        X509BundleSet bundleSet = X509BundleSet.of(x509BundleListResult.getValue());
        X509Context result = new X509Context(x509SvidListResult.getValue(), bundleSet);
        return Result.ok(result);
    }

    private static Result<List<X509Bundle>, String> getListOfX509Bundles(Workload.X509SVIDResponse x509SVIDResponse) {
        List<X509Bundle> x509BundleList = new ArrayList<>();
        for (Workload.X509SVID x509SVID : x509SVIDResponse.getSvidsList()) {
            Result<SpiffeId, String> spiffeId = SpiffeId.parse(x509SVID.getSpiffeId());
            if (spiffeId.isError()) {
                return Result.error(spiffeId.getError());
            }

            Result<X509Bundle, String> bundle = X509Bundle.parse(
                    spiffeId.getValue().getTrustDomain(),
                    x509SVID.getBundle().toByteArray());
            if (bundle.isError()) {
                return Result.error(bundle.getError());
            }
            x509BundleList.add(bundle.getValue());
        }
        return Result.ok(x509BundleList);
    }

    private static Result<List<X509Svid>, String> getListOfX509Svid(Workload.X509SVIDResponse x509SVIDResponse) {
        List<X509Svid> x509SvidList = new ArrayList<>();
        for (Workload.X509SVID x509SVID : x509SVIDResponse.getSvidsList()) {
            Result<X509Svid, String> svid = X509Svid.parse(
                    x509SVID.getX509Svid().toByteArray(),
                    x509SVID.getX509SvidKey().toByteArray());
            if (svid.isError()){
                return Result.error(svid.getError());
            }
            x509SvidList.add(svid.getValue());
        }
        return Result.ok(x509SvidList);
    }
}
