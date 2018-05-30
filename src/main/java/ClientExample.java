import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spiffe.api.svid.Workload;
import spiffe.api.svid.Workload.X509SVID;
import spiffe.api.svid.WorkloadAPIClient;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Simple example of the use of WorkloadAPIClient
 * It performs a synchronous call to obtain the certificates and then
 * performs an asynchronous call passing a consumer that acts as a callback
 * that is executed every time a new response is got from the Workload API
 *
 */
public class ClientExample {

    private static Logger LOGGER = LoggerFactory.getLogger(ClientExample.class);

    public static void main(String[] args)  {

        WorkloadAPIClient workloadAPIClient = new WorkloadAPIClient("/tmp/agent.sock");


        LOGGER.info("Fetching the SVIDS synchronously");
        List<X509SVID> svids = workloadAPIClient.fetchX509SVIDs();
        svids.forEach(svid -> LOGGER.info("Spiffe ID fetched: " + svid.getSpiffeId()));

        AtomicBoolean completed = new AtomicBoolean(false);


        LOGGER.info("Fetching the SVIDs asynchronously");
        //A simple consumer of the SVIDs that just logs the SpiffeIDs received
        Consumer<List<X509SVID>> certificateUpdater;
        certificateUpdater = certs -> {
            certs.forEach(svid -> {
                LOGGER.info("Spiffe ID fetched: " + svid.getSpiffeId());
            });
            completed.set(true);
        };

        //Calling the WorkloadAPI to obtain the certificates
        workloadAPIClient.fetchX509SVIDs(certificateUpdater);

        LOGGER.info("Waiting for certificates...");
        while (!completed.get()) {
            LOGGER.info("Doing other work...");
            doWait(100);
        };

        LOGGER.info("Exiting...");
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

