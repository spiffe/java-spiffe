package io.spiffe.workloadapi.internal.macos.aarch64;

import io.spiffe.workloadapi.internal.GrpcChannelProvider;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MacOsAarch64GrpcChannelProviderTest {

    @Test
    void isRegisteredAsAServiceProvider() {
        List<GrpcChannelProvider> providers = new ArrayList<>();
        for (GrpcChannelProvider provider : ServiceLoader.load(GrpcChannelProvider.class)) {
            providers.add(provider);
        }

        assertEquals(1, providers.size());
        assertEquals(MacOsAarch64GrpcChannelProvider.class, providers.get(0).getClass());
    }

    @Test
    void newChannel_tcpAddress() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            ManagedChannelWrapper wrapper = new MacOsAarch64GrpcChannelProvider().newChannel(URI.create("tcp://127.0.0.1:8000"), executor);

            wrapper.close();
            assertTrue(wrapper.getChannel().isShutdown());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void newChannel_unsupportedScheme() {
        assertThrows(IllegalArgumentException.class,
                () -> new MacOsAarch64GrpcChannelProvider().newChannel(URI.create("http://127.0.0.1:8000"), null));
    }

    @Test
    void newChannel_unixAddressOnAnUnsupportedPlatform() {
        MacOsAarch64GrpcChannelProvider provider = new MacOsAarch64GrpcChannelProvider();
        if (provider.isSupported()) {
            return;
        }

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> provider.newChannel(URI.create("unix:/tmp/spire-agent/public/api.sock"), null));
        assertEquals("Operating System is not supported.", e.getMessage());
    }
}
