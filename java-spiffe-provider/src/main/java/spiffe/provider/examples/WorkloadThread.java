package spiffe.provider.examples;

import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.cert.X509Certificate;

class WorkloadThread extends Thread {

    private SSLSocket sslSocket;

    WorkloadThread(SSLSocket sslSocket) {
        this.sslSocket = sslSocket;
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
                    .getSpiffeId((X509Certificate) sslSession.getPeerCertificates()[0]).getValue();

            SpiffeId mySpiffeId = CertificateUtils
                    .getSpiffeId((X509Certificate) sslSession.getLocalCertificates()[0]).getValue();

            // Send message to peer
            printWriter.printf("Hello %s, I'm %s", peerSpiffeId, mySpiffeId);
            printWriter.println();
            printWriter.flush();

            // Read message from peer
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println("Message received: " + line);
            }

            sslSocket.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
