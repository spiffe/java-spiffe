package io.spiffe.workloadapi;

import java.time.Duration;
import java.util.Objects;

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
public class JwtSourceOptions {

    private String spiffeSocketPath;
    private Duration initTimeout;
    private WorkloadApiClient workloadApiClient;

    public JwtSourceOptions(String spiffeSocketPath,
                            WorkloadApiClient workloadApiClient,
                            Duration initTimeout) {
        this.spiffeSocketPath = spiffeSocketPath;
        this.workloadApiClient = workloadApiClient;
        this.initTimeout = initTimeout;
    }

    public String getSpiffeSocketPath() {
        return spiffeSocketPath;
    }

    public Duration getInitTimeout() {
        return initTimeout;
    }

    public WorkloadApiClient getWorkloadApiClient() {
        return workloadApiClient;
    }

    public void setSpiffeSocketPath(String spiffeSocketPath) {
        this.spiffeSocketPath = spiffeSocketPath;
    }

    public void setInitTimeout(Duration initTimeout) {
        this.initTimeout = initTimeout;
    }

    public void setWorkloadApiClient(WorkloadApiClient workloadApiClient) {
        this.workloadApiClient = workloadApiClient;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String spiffeSocketPath;
        private Duration initTimeout;
        private WorkloadApiClient workloadApiClient;

        public Builder spiffeSocketPath(String spiffeSocketPath) {
            this.spiffeSocketPath = spiffeSocketPath;
            return this;
        }

        public Builder initTimeout(Duration initTimeout) {
            this.initTimeout = initTimeout;
            return this;
        }

        public Builder workloadApiClient(WorkloadApiClient workloadApiClient) {
            this.workloadApiClient = workloadApiClient;
            return this;
        }

        public JwtSourceOptions build() {
            return new JwtSourceOptions(
                    spiffeSocketPath,
                    workloadApiClient,
                    initTimeout
            );
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwtSourceOptions)) return false;
        JwtSourceOptions that = (JwtSourceOptions) o;
        return Objects.equals(spiffeSocketPath, that.spiffeSocketPath) &&
                Objects.equals(initTimeout, that.initTimeout) &&
                Objects.equals(workloadApiClient, that.workloadApiClient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(spiffeSocketPath, initTimeout, workloadApiClient);
    }

    @Override
    public String toString() {
        return "JwtSourceOptions{" +
                "spiffeSocketPath='" + spiffeSocketPath + '\'' +
                ", initTimeout=" + initTimeout +
                ", workloadApiClient=" + workloadApiClient +
                '}';
    }
}
