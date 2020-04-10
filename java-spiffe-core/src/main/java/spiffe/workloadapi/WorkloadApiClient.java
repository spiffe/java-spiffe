package spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.bundle.jwtbundle.JwtBundleSet;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.workloadapi.internal.GrpcConversionUtils;
import spiffe.workloadapi.internal.GrpcManagedChannelFactory;
import spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;

import java.nio.file.Path;
import java.util.Iterator;

import static spiffe.workloadapi.internal.Workload.X509SVIDRequest;
import static spiffe.workloadapi.internal.Workload.X509SVIDResponse;

/**
 * A <code>WorkloadApiClient</code> represents a client to interact with the Workload API.
 * Supports one-shot calls and watch updates for X509 and JWT SVIDS and Bundles.
 * <p>
 * Multiple WorkloadApiClients can be created for the same SPIFFE Socket Path,
 * they will share a common ManagedChannel.
 */
public class WorkloadApiClient {

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;

    private WorkloadApiClient(SpiffeWorkloadAPIStub workloadApiAsyncStub, SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
    }

    /**
     * Creates a new Workload API Client.
     *
     * @param spiffeSocketPath where the WorkloadAPI is listening.
     */
    public static Result<WorkloadApiClient, Throwable> newClient(Path spiffeSocketPath) {
        Result<ManagedChannel, Throwable> managedChannel = GrpcManagedChannelFactory.getManagedChannel(spiffeSocketPath);
        if (managedChannel.isError()) {
            return Result.error(managedChannel.getError());
        }

        SpiffeWorkloadAPIStub workloadAPIAsyncStub = SpiffeWorkloadAPIGrpc
                                        .newStub(managedChannel.getValue())
                                        .withInterceptors(new SecurityHeaderInterceptor());

        SpiffeWorkloadAPIBlockingStub workloadAPIBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(managedChannel.getValue())
                .withInterceptors(new SecurityHeaderInterceptor());

        return Result.ok(
                new WorkloadApiClient(workloadAPIAsyncStub, workloadAPIBlockingStub));
    }

    /**
     * One-shot fetch call to get an X509 Context (SPIFFE X509-SVID and Bundles).
     */
    public Result<X509Context, Throwable> fetchX509Context() {
        Context.CancellableContext cancellableContext;
        cancellableContext = Context.current().withCancellation();
        Result<X509Context, Throwable> result;
        try {
            result = cancellableContext.call(this::processX509Context);
        } catch (Exception e) {
            return Result.error(e);
        }
        // close connection
        cancellableContext.close();
        return result;
    }

    private Result<X509Context, Throwable> processX509Context() {
        try {
            Iterator<X509SVIDResponse> x509SVIDResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
            if (x509SVIDResponse.hasNext()) {
                return GrpcConversionUtils.toX509Context(x509SVIDResponse.next());
            }
        } catch (Exception e) {
            return Result.error(e);
        }
        return Result.error(new RuntimeException("Could not get X509Context"));
    }

    /**
     * Watches for updates to the X509 Context.
     *
     * @param watcher receives the update X509 context.
     */
    public void watchX509Context(Watcher<X509Context> watcher) {
        StreamObserver<X509SVIDResponse> streamObserver = new StreamObserver<X509SVIDResponse>() {
            @Override
            public void onNext(X509SVIDResponse value) {
                Result<X509Context, Throwable> x509Context = GrpcConversionUtils.toX509Context(value);
                if (x509Context.isError()) {
                    watcher.OnError(Result.error(x509Context.getError()));
                }
                watcher.OnUpdate(x509Context.getValue());
            }

            @Override
            public void onError(Throwable t) {
                watcher.OnError(Result.error(t));
            }

            @Override
            public void onCompleted() {
                watcher.OnError(Result.error(new RuntimeException("Unexpected completed stream.")));
            }
        };
        workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), streamObserver);
    }

    /**
     * One-shot fetch call to get a SPIFFE JWT-SVID.
     *
     * @param subject a SPIFFE ID
     * @param audience the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return an Optional containing the JWT SVID.
     */
    public Result<JwtSvid, Throwable> fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) {
       throw new NotImplementedException("Not implemented");
    }

    /**
     * Fetches the JWT bundles for JWT-SVID validation, keyed
     * by a SPIFFE ID of the trust domain to which they belong.
     *
     * @return an Optional containing the JwtBundleSet.
     */
    public Result<JwtBundleSet, Throwable> fetchJwtBundles() {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Validates the JWT-SVID token. The parsed and validated
     * JWT-SVID is returned.
     *
     * @param token JWT token
     * @param audience audience of the JWT
     *
     * @return the JwtSvid if the token and audience could be validated.
     */
    public Result<JwtSvid, Throwable> validateJwtSvid(String token, String audience) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Watches for updates to the JWT Bundles.
     *
     * @param jwtBundlesWatcher receives the update for JwtBundles.
     */
    public void watchJwtBundles(Watcher<JwtBundleSet> jwtBundlesWatcher) {
        throw new NotImplementedException("Not implemented");
    }

    private X509SVIDRequest newX509SvidRequest() {
        return X509SVIDRequest.newBuilder().build();
    }
}
