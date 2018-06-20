package spiffe.api.svid.examples;

import spiffe.api.svid.Fetcher;
import spiffe.api.svid.X509SvidFetcher;
import spiffe.api.svid.Workload.X509SVID;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Simple example of the use of X509SvidFetcher
 * It performs a synchronous call to obtain the certificates and then
 * performs an asynchronous call passing a consumer that acts as a callback
 * that is executed every time a new response is got from the Workload API
 *
 */
public class ClientExample {

    public static void main(String[] args)  {

        Fetcher<List<X509SVID>> svidFetcher = new X509SvidFetcher("/tmp/agent.sock");

        AtomicBoolean completed = new AtomicBoolean(false);

        System.out.println("Fetching the SVIDs asynchronously");
        //A simple consumer of the SVIDs that just logs the SpiffeIDs received
        Consumer<List<X509SVID>> certificateUpdater;
        certificateUpdater = certs -> {
            certs.forEach(svid -> {
                System.out.println("Spiffe ID fetched: " + svid.getSpiffeId());
            });
            completed.set(true);
        };

        //Calling the WorkloadAPI to obtain the certificates
        svidFetcher.registerListener(certificateUpdater);

        System.out.println("Waiting for certificates...");
        while (!completed.get()) {
            System.out.println("Doing other work...");
            doWait(100);
        };

        System.out.println("Exiting...");
        System.exit(0);
    }

    private static void doWait(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}

