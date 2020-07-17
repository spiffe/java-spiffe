package io.spiffe.workloadapi;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import io.spiffe.workloadapi.retry.ExponentialBackoffPolicy;

import java.io.IOException;
import java.time.Duration;

public class WorkloadApiClientTestUtil {

    static DefaultWorkloadApiClient create(SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase fakeWorkloadApi, GrpcCleanupRule grpcCleanup) throws IOException {
        // Generate a unique in-process server name.
        String serverName = InProcessServerBuilder.generateName();

        Server server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeWorkloadApi).build().start();
        grpcCleanup.register(server);

        // Create WorkloadApiClient using Stubs that will connect to the fake WorkloadApiService.
        final ManagedChannel inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
        grpcCleanup.register(inProcessChannel);

        SecurityHeaderInterceptor securityHeaderInterceptor = new SecurityHeaderInterceptor();
        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(inProcessChannel)
                .withInterceptors(securityHeaderInterceptor);

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadAPIStub = SpiffeWorkloadAPIGrpc
                .newStub(inProcessChannel)
                .withInterceptors(securityHeaderInterceptor);

        return new DefaultWorkloadApiClient(workloadAPIStub,
                workloadApiBlockingStub,
                new ManagedChannelWrapper(inProcessChannel),
                ExponentialBackoffPolicy.builder().maxRetries(1).maxDelay(Duration.ofMillis(1)).build());
    }
}
