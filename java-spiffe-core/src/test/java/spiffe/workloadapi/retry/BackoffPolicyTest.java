package spiffe.workloadapi.retry;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class BackoffPolicyTest {

    @Test
    void testNextDelayDefaultPolicy_returnsDouble() {
        BackoffPolicy backoffPolicy = new BackoffPolicy();
        assertEquals(Duration.ofSeconds(10), backoffPolicy.nextDelay(Duration.ofSeconds(5)));
    }

    @Test
    void testNextDelayDefaultPolicy_exceedsMaxDelay_returnsMaxDelay() {
        BackoffPolicy backoffPolicy = BackoffPolicy
                .builder()
                .initialDelay(Duration.ofSeconds(1))
                .maxDelay(Duration.ofSeconds(60))
                .build();

        assertEquals(Duration.ofSeconds(60), backoffPolicy.nextDelay(Duration.ofSeconds(50)));
    }

    @Test
    void testNextDelayCustomPolicy() {
        BackoffPolicy backoffPolicy = BackoffPolicy
                .builder()
                .maxDelay(Duration.ofSeconds(60))
                .backoffFunction(d -> d.multipliedBy(5))
                .build();

        assertEquals(Duration.ofSeconds(50), backoffPolicy.nextDelay(Duration.ofSeconds(10)));
    }

    @Test
    void testDidNotReachMaxRetries() {
        BackoffPolicy backoffPolicy = BackoffPolicy
                .builder()
                .maxRetries(5)
                .build();

        assertTrue(backoffPolicy.didNotReachMaxRetries(4));
    }

    @Test
    void testDidNotReachMaxRetries_retriesCountEqualsMaxRetries_returnsFalse() {
        BackoffPolicy backoffPolicy = BackoffPolicy
                .builder()
                .maxRetries(5)
                .build();

        assertFalse(backoffPolicy.didNotReachMaxRetries(5));
    }

    @Test
    void testDidNotReachMaxRetries_UnlimitedRetries() {
        BackoffPolicy backoffPolicy = new BackoffPolicy();
        assertTrue(backoffPolicy.didNotReachMaxRetries(Integer.MAX_VALUE));
    }
}