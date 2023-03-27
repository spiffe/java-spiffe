package io.spiffe.workloadapi;


import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;

import java.time.Duration;

/**
 * Options to configure a {@link JwtSource}.
 * <p>
 * <code>spiffeSocketPath</code> Address to the Workload API, if it is not set, the default address will be used.
 * <p>
 * <code>initTimeout</code> Timeout for initializing the instance. If it is not defined, the timeout is read
 * from the System property `spiffe.newJwtSource.timeout'. If this is also not defined, no default timeout is applied.
 * <p>
 * <code>workloadApiClient</code> A custom instance of a {@link WorkloadApiClient}, if it is not set,
 * a new client will be created.
 */
@Data
public class JwtSourceOptions {

    @Setter(AccessLevel.PUBLIC)
    private String spiffeSocketPath;

    @Setter(AccessLevel.PUBLIC)
    private Duration initTimeout;

    @Setter(AccessLevel.PUBLIC)
    private WorkloadApiClient workloadApiClient;

    @Builder
    public JwtSourceOptions(
            final String spiffeSocketPath,
            final WorkloadApiClient workloadApiClient,
            final Duration initTimeout) {
        this.spiffeSocketPath = spiffeSocketPath;
        this.workloadApiClient = workloadApiClient;
        this.initTimeout = initTimeout;
    }
}
