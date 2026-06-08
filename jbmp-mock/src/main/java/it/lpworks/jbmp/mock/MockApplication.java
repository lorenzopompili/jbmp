package it.lpworks.jbmp.mock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the jBMP mock service.
 *
 * <p>The mock opens one or more BMP sessions to a collector and emits RFC-conformant
 * BMP/BGP traffic according to configurable scenarios (initial table dump, incremental
 * updates, peer up/down, statistics). It is used for end-to-end tests, conformance
 * checks and throughput benchmarking.
 */
@SpringBootApplication
@EnableConfigurationProperties(MockProperties.class)
public class MockApplication {

    public static void main(String[] args) {
        SpringApplication.run(MockApplication.class, args);
    }
}
