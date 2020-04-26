package spiffe.provider.examples;

import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;
import spiffe.workloadapi.X509Source;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.cert.X509Certificate;

class WorkloadThread extends Thread {

    private final X509Source x509Source;
    private SSLSocket sslSocket;

    WorkloadThread(SSLSocket sslSocket, X509Source x509Source) {
        this.sslSocket = sslSocket;
        this.x509Source = x509Source;
    }

    public void run() {
        try {
            sslSocket.startHandshake();
            SSLSession sslSession = sslSocket.getSession();

            System.out.println("SSLSession :");
            System.out.println("\tProtocol : " + sslSession.getProtocol());
            System.out.println("\tCipher suite : " + sslSession.getCipherSuite());
            System.out.println();

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
                System.out.println("Message received: " + line);
                break;
            }

            x509Source.close();
            sslSocket.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
