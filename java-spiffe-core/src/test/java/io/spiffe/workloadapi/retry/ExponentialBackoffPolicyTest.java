package io.spiffe.workloadapi.retry;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExponentialBackoffPolicyTest {

    @Test
    void testNextDelayDefaultPolicy_returnsDouble() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        assertEquals(Duration.ofSeconds(10), exponentialBackoffPolicy.nextDelay(Duration.ofSeconds(5)));
    }

    @Test
    void testNextDelayDefaultPolicy_exceedsMaxDelay_returnsMaxDelay() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy
                .builder()
                .initialDelay(Duration.ofSeconds(1))
                .maxDelay(Duration.ofSeconds(60))
                .build();

        assertEquals(Duration.ofSeconds(60), exponentialBackoffPolicy.nextDelay(Duration.ofSeconds(50)));
    }

    @Test
    void testNextDelayDefaultPolicy_currentDelayExceedsMaxDelay_returnsMaxDelay() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy
                .builder()
                .initialDelay(Duration.ofSeconds(1))
                .maxDelay(Duration.ofSeconds(60))
                .build();

        assertEquals(Duration.ofSeconds(60), exponentialBackoffPolicy.nextDelay(Duration.ofSeconds(70)));
    }

    @Test
    void testNextDelayCustomPolicy() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy
                .builder()
                .maxDelay(Duration.ofSeconds(60))
                .backoffMultiplier(5)
                .build();

        assertEquals(Duration.ofSeconds(50), exponentialBackoffPolicy.nextDelay(Duration.ofSeconds(10)));
    }

    @Test
    void testDidNotReachMaxRetries() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy
                .builder()
                .maxRetries(5)
                .build();

        assertFalse(exponentialBackoffPolicy.reachedMaxRetries(4));
    }

    @Test
    void testDidNotReachMaxRetries_retriesCountEqualsMaxRetries_returnsFalse() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy
                .builder()
                .maxRetries(5)
                .build();

        assertTrue(exponentialBackoffPolicy.reachedMaxRetries(5));
    }

    @Test
    void testDidNotReachMaxRetries_UnlimitedRetries() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        assertFalse(exponentialBackoffPolicy.reachedMaxRetries(Integer.MAX_VALUE));
    }
}