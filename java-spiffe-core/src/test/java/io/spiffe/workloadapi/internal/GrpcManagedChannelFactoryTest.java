package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GrpcManagedChannelFactoryTest {

    @Test
    void selectProvider_picksTheProviderSupportingThePlatform() {
        FakeProvider unsupported = new FakeProvider(false);
        FakeProvider supported = new FakeProvider(true);

        GrpcChannelProvider result =
                GrpcManagedChannelFactory.selectProvider(Arrays.<GrpcChannelProvider>asList(unsupported, supported).iterator());

        assertSame(supported, result);
    }

    @Test
    void selectProvider_fallsBackToTheFirstProviderWhenNoneSupportsThePlatform() {
        FakeProvider first = new FakeProvider(false);
        FakeProvider second = new FakeProvider(false);

        GrpcChannelProvider result =
                GrpcManagedChannelFactory.selectProvider(Arrays.<GrpcChannelProvider>asList(first, second).iterator());

        assertSame(first, result);
    }

    @Test
    void selectProvider_skipsProvidersThatFailToLoad() {
        FakeProvider supported = new FakeProvider(true);
        List<Object> entries = new ArrayList<>();
        entries.add(new ServiceConfigurationError("broken provider"));
        entries.add(supported);

        GrpcChannelProvider result = GrpcManagedChannelFactory.selectProvider(new FailingIterator(entries));

        assertSame(supported, result);
    }

    @Test
    void selectProvider_failsWhenNoProviderIsOnTheClasspath() {
        Iterator<GrpcChannelProvider> none = Collections.<GrpcChannelProvider>emptyList().iterator();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> GrpcManagedChannelFactory.selectProvider(none));

        assertTrue(e.getMessage().startsWith("No gRPC channel provider found on the classpath"));
    }

    @Test
    void serviceLoader_findsTheGrpcNettyModuleOnTheTestClasspath() {
        List<GrpcChannelProvider> providers = new ArrayList<>();
        for (GrpcChannelProvider provider : ServiceLoader.load(GrpcChannelProvider.class)) {
            providers.add(provider);
        }

        assertEquals(1, providers.size());
        assertTrue(providers.get(0).isSupported());
        assertFalse(providers.get(0).getClass().getPackage().getName().equals(GrpcChannelProvider.class.getPackage().getName()),
                "the provider must not share a package with core");
    }

    @Test
    void newChannel_usesTheProviderFromTheClasspath() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            ManagedChannelWrapper wrapper =
                    GrpcManagedChannelFactory.newChannel(URI.create("tcp://127.0.0.1:8000"), executor);

            assertNotNull(wrapper.getChannel());
            wrapper.close();
            assertTrue(wrapper.getChannel().isShutdown());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void newChannel_nullAddress() {
        NullPointerException e = assertThrows(NullPointerException.class,
                () -> GrpcManagedChannelFactory.newChannel(null, null));

        assertEquals("address must not be null", e.getMessage());
    }

    @Test
    void managedChannelWrapper_closeRunsTheHookAndShutsDownTheChannel() {
        ManagedChannel channel = InProcessChannelBuilder.forName("wrapper-test").build();
        AtomicBoolean hookCalled = new AtomicBoolean();

        new ManagedChannelWrapper(channel, () -> hookCalled.set(true)).close();

        assertTrue(hookCalled.get());
        assertTrue(channel.isShutdown());
    }

    @Test
    void managedChannelWrapper_closeWithoutHook() {
        ManagedChannel channel = InProcessChannelBuilder.forName("wrapper-test-no-hook").build();

        new ManagedChannelWrapper(channel).close();

        assertTrue(channel.isShutdown());
    }

    private static final class FakeProvider implements GrpcChannelProvider {
        private final boolean supported;

        FakeProvider(boolean supported) {
            this.supported = supported;
        }

        @Override
        public boolean isSupported() {
            return supported;
        }

        @Override
        public ManagedChannelWrapper newChannel(URI address, ExecutorService executorService) {
            throw new UnsupportedOperationException();
        }
    }

    // Mimics a ServiceLoader iterator whose next() throws for a provider that can't be instantiated.
    private static final class FailingIterator implements Iterator<GrpcChannelProvider> {
        private final Iterator<Object> entries;

        FailingIterator(List<Object> entries) {
            this.entries = entries.iterator();
        }

        @Override
        public boolean hasNext() {
            return entries.hasNext();
        }

        @Override
        public GrpcChannelProvider next() {
            if (!entries.hasNext()) {
                throw new NoSuchElementException();
            }
            Object next = entries.next();
            if (next instanceof ServiceConfigurationError) {
                throw (ServiceConfigurationError) next;
            }
            return (GrpcChannelProvider) next;
        }
    }
}
