package io.spiffe.provider.examples.mtls;

import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.X509Source;
import lombok.extern.java.Log;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

@Log
class WorkloadThread extends Thread {

    private final X509Source x509Source;
    private SSLSocket sslSocket;

    WorkloadThread(SSLSocket sslSocket, X509Source x509Source) {
        this.sslSocket = sslSocket;
        this.x509Source = x509Source;
    }


    @Override
    public void run() {
        try {
            sslSocket.startHandshake();
            SSLSession sslSession = sslSocket.getSession();

            log.info("SSLSession :\n");
            log.info("\tProtocol : \n" + sslSession.getProtocol());
            log.info("\tCipher suite \n: " + sslSession.getCipherSuite());

            // Start handling application content
            InputStream inputStream = sslSocket.getInputStream();
            OutputStream outputStream = sslSocket.getOutputStream();

            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

            SpiffeId peerSpiffeId = CertificateUtils
                    .getSpiffeId((X509Certificate) sslSession.getPeerCertificates()[0]);

            SpiffeId mySpiffeId = CertificateUtils
                    .getSpiffeId((X509Certificate) sslSession.getLocalCertificates()[0]);

            // Send message to peer
            printWriter.printf("Hello %s, I'm %s", peerSpiffeId, mySpiffeId);
            printWriter.println();
            printWriter.flush();

            // Read message from peer
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                log.info("Message received: " + line);
                break;
            }

            x509Source.close();
            sslSocket.close();
        } catch (Exception e) {
            log.log(Level.SEVERE, e.getMessage());
        }
    }
}
