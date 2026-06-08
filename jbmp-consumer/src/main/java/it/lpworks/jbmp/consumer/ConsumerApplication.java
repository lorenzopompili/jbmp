package it.lpworks.jbmp.consumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the jBMP consumer service.
 *
 * <p>The consumer reads parsed messages from Kafka, accumulates them into batches
 * and writes them to a time-series store using bulk-copy for the high-volume path
 * and idempotent upserts for routing-state tables. Kafka offsets are committed only
 * after a successful store write to avoid data loss on rebalance.
 */
@SpringBootApplication
public class ConsumerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConsumerApplication.class, args);
    }
}
