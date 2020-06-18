package io.spiffe.helper.keystore;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.WorkloadApiClient;
import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreHelperTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private WorkloadApiClient workloadApiClient;
    private Path keyStoreFilePath;
    private Path trustStoreFilePath;

    @BeforeEach
    void setUp() throws IOException {
        // Generate a unique in-process server name.
        String serverName = InProcessServerBuilder.generateName();

        // Create a server, add service, start, and register for automatic graceful shutdown.
        FakeWorkloadApi fakeWorkloadApi = new FakeWorkloadApi();
        Server server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeWorkloadApi).build().start();
        grpcCleanup.register(server);

        // Create WorkloadApiClient using Stubs that will connect to the fake WorkloadApiService.
        ManagedChannel inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
        grpcCleanup.register(inProcessChannel);

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadAPIStub = SpiffeWorkloadAPIGrpc
                .newStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        workloadApiClient = new WorkloadApiClient(workloadAPIStub, workloadApiBlockingStub, new ManagedChannelWrapper(inProcessChannel));
    }

    @Test
    void testNewHelper_certs_are_stored_successfully() throws KeyStoreException, SocketEndpointAddressException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException {

        val keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        val trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        val trustStorePass = "truststore123";
        val keyStorePass = "keystore123";
        val keyPass = "keypass123";
        val alias = "other_alias";
        val keyStoreType = KeyStoreType.JKS;

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStoreType(keyStoreType)
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias)
                .client(workloadApiClient)
                .build();

        // run KeyStoreHelper
        new KeyStoreHelper(options);

        checkPrivateKeyEntry(keyStoreFilePath, keyStorePass, keyPass, keyStoreType, alias);
        val authority1Alias = "example.org.0";
        checkBundleEntries(trustStoreFilePath, trustStorePass, keyStoreType, authority1Alias);
    }

    @Test
    void testNewHelper_use_default_type_and_alias() throws KeyStoreException, SocketEndpointAddressException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException {

        val keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        val trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        val trustStorePass = "truststore123";
        val keyStorePass = "keystore123";
        val keyPass = "keypass123";

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .client(workloadApiClient)
                .build();

        // run KeyStoreHelper
        new KeyStoreHelper(options);

        checkPrivateKeyEntry(keyStoreFilePath, keyStorePass, keyPass, KeyStoreType.getDefaultType(), KeyStoreHelper.DEFAULT_ALIAS);
        val authority1Alias = "example.org.0";
        checkBundleEntries(trustStoreFilePath, trustStorePass, KeyStoreType.getDefaultType(), authority1Alias);
    }

    @Test
    void testNewHelper_keyStore_trustStore_same_file_throwsException() throws SocketEndpointAddressException {

        val keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        val trustStorePass = "truststore123";
        val keyStorePass = "keystore123";
        val keyPass = "keypass123";
        val alias = "other_alias";

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(keyStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias)
                .client(workloadApiClient)
                .build();

        try {
            new KeyStoreHelper(options);
            fail("expected exception: KeyStore and TrustStore should use different files");
        } catch (KeyStoreException e) {
            assertEquals("KeyStore and TrustStore should use different files", e.getMessage());
        }

    }

    @AfterEach
    void tearDown() throws IOException {
        deleteFile(keyStoreFilePath);
        deleteFile(trustStoreFilePath);
        workloadApiClient.close();
    }

    private void checkPrivateKeyEntry(Path keyStoreFilePath,
                                      String keyStorePassword,
                                      String privateKeyPassword,
                                      KeyStoreType keyStoreType,
                                      String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

        keyStore.load(new FileInputStream(new File(keyStoreFilePath.toUri())), keyStorePassword.toCharArray());
        val chain = keyStore.getCertificateChain(alias);
        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) chain[0]);
        val privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());

        assertEquals(1, chain.length);
        assertEquals("spiffe://example.org/workload-server", spiffeId.toString());
        assertNotNull(privateKey);
    }

    private void checkBundleEntries(Path keyStoreFilePath,
                                    String keyStorePassword,
                                    KeyStoreType keyStoreType,
                                    String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());
        keyStore.load(new FileInputStream(new File(keyStoreFilePath.toUri())), keyStorePassword.toCharArray());
        val certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate);

        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) certificate);
        Assertions.assertEquals(SpiffeId.parse("spiffe://example.org"), spiffeId);
    }

    private void deleteFile(Path file) {
        try {
            Files.delete(file);
        } catch (Exception e) {
            //ignore
        }
    }

}