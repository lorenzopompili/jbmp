package it.lpworks.jbmp.collector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the jBMP collector service.
 *
 * <p>The collector listens for BMP sessions over TCP, parses each BMP/BGP message,
 * optionally enriches it and publishes the result to Kafka. The TCP listener uses
 * one virtual thread per connected router, mirroring a blocking-read model while
 * scaling to large numbers of concurrent sessions.
 */
@SpringBootApplication
public class CollectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(CollectorApplication.class, args);
    }
}
