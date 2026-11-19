package io.spiffe.workloadapi.internal.linux;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import java.io.File;
import java.lang.module.Configuration;
import java.lang.module.FindException;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Puts java-spiffe-core, this transport module and their runtime dependencies on the module path, in a
 * layer of their own, and opens a channel through core. Defining the layer fails if two modules contain the
 * same package, which is what happened when core and the transport modules shared
 * io.spiffe.workloadapi.internal. The channel is created through core, so the provider is also found by
 * ServiceLoader in that layer.
 */
@EnabledForJreRange(min = JRE.JAVA_9)
class ModulePathTest {

    private static final String FACTORY = "io.spiffe.workloadapi.internal.GrpcManagedChannelFactory";

    @Test
    void channelCanBeCreatedAndClosedFromTheModulePath() throws Exception {
        Path[] jars = Arrays.stream(System.getProperty("spiffe.modulepath").split(File.pathSeparator))
                .map(Paths::get)
                .toArray(Path[]::new);
        ModuleFinder finder = ModuleFinder.of(jars);
        Set<String> roots = finder.findAll().stream()
                .map(ModuleReference::descriptor)
                .map(descriptor -> descriptor.name())
                .collect(Collectors.toSet());

        Configuration configuration;
        try {
            configuration = ModuleLayer.boot().configuration()
                    .resolve(finder, ModuleFinder.of(), roots);
        } catch (FindException e) {
            // nimbus-jose-jwt still requires jdk.crypto.ec, which JDK 24 folded into java.base
            Assumptions.assumeFalse(e.getMessage().contains("jdk.crypto.ec"), e.getMessage());
            throw e;
        }
        // the platform loader as parent, so the classes of this test's own class path can't be picked up
        ModuleLayer layer = ModuleLayer.boot()
                .defineModulesWithOneLoader(configuration, ClassLoader.getPlatformClassLoader());

        ClassLoader loader = layer.modules().stream()
                .filter(module -> module.getPackages().contains("io.spiffe.workloadapi.internal"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("java-spiffe-core is not in the layer"))
                .getClassLoader();
        Class<?> factory = loader.loadClass(FACTORY);
        Method newChannel = factory.getMethod("newChannel", URI.class, ExecutorService.class);

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Object wrapper = newChannel.invoke(null, URI.create("tcp://127.0.0.1:8000"), executor);
            assertNotNull(wrapper);

            Object channel = wrapper.getClass().getMethod("getChannel").invoke(wrapper);
            Method isShutdown = loader.loadClass("io.grpc.ManagedChannel").getMethod("isShutdown");
            assertFalse((Boolean) isShutdown.invoke(channel));

            wrapper.getClass().getMethod("close").invoke(wrapper);
            assertTrue((Boolean) isShutdown.invoke(channel));
        } finally {
            executor.shutdownNow();
        }
    }
}
