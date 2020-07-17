package io.spiffe.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

class SpiffeSslSocketFactoryTest {

    @Mock
    SSLSocketFactory sslSocketFactoryMock;

    private SpiffeSslSocketFactory spiffeSslSocketFactory;
    private SSLSocketFactory socketFactory;

    @BeforeEach
    void setup() throws NoSuchAlgorithmException, KeyManagementException {
        X509SourceStub x509Source = new X509SourceStub();
        SpiffeSslContextFactory.SslContextOptions options = SpiffeSslContextFactory.SslContextOptions.builder().x509Source(x509Source).build();
        spiffeSslSocketFactory = new SpiffeSslSocketFactory(options);
        SSLContext sslContext = SpiffeSslContextFactory.getSslContext(options);
        socketFactory = sslContext.getSocketFactory();
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void getDefaultCipherSuites() {
        String[] defaultCipherSuites = spiffeSslSocketFactory.getDefaultCipherSuites();
        String[] expected = socketFactory.getDefaultCipherSuites();
        assertArrayEquals(expected, defaultCipherSuites);
    }

    @Test
    void getSupportedCipherSuites() {
        String[] supportedCipherSuites = spiffeSslSocketFactory.getSupportedCipherSuites();
        String[] expected = socketFactory.getSupportedCipherSuites();
        assertArrayEquals(expected, supportedCipherSuites);
    }

    @Test
    void createSocket() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        when(sslSocketFactoryMock.createSocket()).thenReturn(expected);
        Socket socket = socketFactory.createSocket();

        assertEquals(expected, socket);
    }

    @Test
    void testCreateSocket_HostParameter() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        when(sslSocketFactoryMock.createSocket("string", 1)).thenReturn(expected);
        Socket socket = socketFactory.createSocket("string", 1);

        assertEquals(expected, socket);
    }

    @Test
    void testCreateSocket_InetAddressParameter() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        when(sslSocketFactoryMock.createSocket(InetAddress.getLocalHost(), 1)).thenReturn(expected);
        Socket socket = socketFactory.createSocket(InetAddress.getLocalHost(), 1);

        assertEquals(expected, socket);
    }

    @Test
    void testCreateSocket_StringInetAddressParameter() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        when(sslSocketFactoryMock.createSocket("string", 1, InetAddress.getLocalHost(), 2)).thenReturn(expected);
        Socket socket = socketFactory.createSocket("string", 1, InetAddress.getLocalHost(), 2);

        assertEquals(expected, socket);
    }

    @Test
    void testCreateSocket_InetAddressPortInetAddressPortParameters() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        when(sslSocketFactoryMock.createSocket(InetAddress.getLocalHost(), 1, InetAddress.getLocalHost(), 2)).thenReturn(expected);
        Socket socket = socketFactory.createSocket(InetAddress.getLocalHost(), 1, InetAddress.getLocalHost(), 2);

        assertEquals(expected, socket);
    }

    @Test
    void testCreateSocket_parametersSocketStringPortAutoClose() throws IOException {
        SpiffeSslSocketFactory socketFactory = new SpiffeSslSocketFactory(sslSocketFactoryMock);

        Socket expected = new Socket();
        Socket s = new Socket();
        when(sslSocketFactoryMock.createSocket(s, "string", 1, true)).thenReturn(expected);
        Socket socket = socketFactory.createSocket(s, "string",  1, true);

        assertEquals(expected, socket);
    }
}