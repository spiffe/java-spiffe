import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spiffe.api.svid.Workload;
import spiffe.api.svid.WorkloadAPIClient;

import java.util.List;

public class ClientExample {

    private static Logger LOGGER = LoggerFactory.getLogger(ClientExample.class);

    public static void main(String[] args) {
        WorkloadAPIClient workloadAPIClient = new WorkloadAPIClient("/tmp/agent.sock");
        List<Workload.X509SVID> svids = workloadAPIClient.fetchX509SVIDs();
        svids.forEach(svid -> LOGGER.info("Spiffe ID fetched: " + svid.getSpiffeId()));
        System.exit(0);
    }
}

