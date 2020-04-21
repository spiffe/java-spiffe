package spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.exception.ExceptionUtils;
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

import java.io.Closeable;
import java.net.URI;
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
public class WorkloadApiClient implements Closeable {

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;
    private final ManagedChannel managedChannel;

    private WorkloadApiClient(SpiffeWorkloadAPIStub workloadApiAsyncStub, SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub, ManagedChannel managedChannel) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.managedChannel = managedChannel;
    }

    /**
     * Creates a new Workload API Client.
     *
     * @param spiffeSocketPath where the WorkloadAPI is listening.
     */
    public static WorkloadApiClient newClient(URI spiffeSocketPath) {
        ManagedChannel managedChannel = GrpcManagedChannelFactory.newChannel(spiffeSocketPath);

        SpiffeWorkloadAPIStub workloadAPIAsyncStub = SpiffeWorkloadAPIGrpc
                                        .newStub(managedChannel)
                                        .withInterceptors(new SecurityHeaderInterceptor());

        SpiffeWorkloadAPIBlockingStub workloadAPIBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(managedChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        return new WorkloadApiClient(workloadAPIAsyncStub, workloadAPIBlockingStub, managedChannel);
    }

    /**
     * One-shot fetch call to get an X509 Context (SPIFFE X509-SVID and Bundles).
     */
    public Result<X509Context, String> fetchX509Context() {
        Context.CancellableContext cancellableContext;
        cancellableContext = Context.current().withCancellation();
        Result<X509Context, String> result;
        try {
            result = cancellableContext.call(this::processX509Context);
        } catch (Exception e) {
            return Result.error("Error fetching X509Context: %s", e.getMessage());
        }
        // close connection
        cancellableContext.close();
        return result;
    }

    private Result<X509Context, String> processX509Context() {
        try {
            Iterator<X509SVIDResponse> x509SVIDResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
            if (x509SVIDResponse.hasNext()) {
                return GrpcConversionUtils.toX509Context(x509SVIDResponse.next());
            }
        } catch (Exception e) {
            return Result.error("Error processing X509Context: %s", e.getMessage());
        }
        return Result.error("Could not get X509Context");
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
                Result<X509Context, String> x509Context = GrpcConversionUtils.toX509Context(value);
                if (x509Context.isError()) {
                    watcher.OnError(Result.error(x509Context.getError()));
                }
                watcher.OnUpdate(x509Context.getValue());
            }

            @Override
            public void onError(Throwable t) {
                String error = String.format("Error getting X509Context update: %s", ExceptionUtils.getStackTrace(t));
                watcher.OnError(Result.error(error));
            }

            @Override
            public void onCompleted() {
                watcher.OnError(Result.error("Unexpected completed stream."));
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
     * @return an {@link spiffe.result.Ok} containing the JWT SVID, or an {@link spiffe.result.Error}
     * if the JwtSvid could not be fetched.
     */
    public Result<JwtSvid, String> fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) {
       throw new NotImplementedException("Not implemented");
    }

    /**
     * Fetches the JWT bundles for JWT-SVID validation, keyed
     * by a SPIFFE ID of the trust domain to which they belong.
     *
     * @return an {@link spiffe.result.Ok} containing the JwtBundleSet.
     */
    public Result<JwtBundleSet, String> fetchJwtBundles() {
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
    public Result<JwtSvid, String> validateJwtSvid(String token, String audience) {
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

    @Override
    public void close() {
        managedChannel.shutdown();
    }
}
