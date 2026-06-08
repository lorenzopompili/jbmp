package it.lpworks.jbmp.launcher;

import java.util.Arrays;

import it.lpworks.jbmp.collector.CollectorApplication;
import it.lpworks.jbmp.consumer.ConsumerApplication;
import it.lpworks.jbmp.mock.MockApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Single-binary launcher that boots one jBMP role selected via the first CLI
 * argument or the {@code jbmp.role} system property.
 *
 * <pre>{@code
 *   java -jar jbmp-all.jar collector [args...]
 *   java -jar jbmp-all.jar consumer  [args...]
 *   java -jar jbmp-all.jar mock      [args...]
 * }</pre>
 *
 * <p>Intended for development, demos and single-host deployments. Production
 * deployments run each role as its own service so they can scale and fail
 * independently.
 *
 * <p>Because every role's auto-configuration is present on this jar's classpath,
 * the launcher narrows auto-configuration to the selected role (see
 * {@link #autoConfigExclusions(String)}) before starting the context.
 */
public final class Launcher {

    private Launcher() {
    }

    public static void main(String[] args) {
        String role = resolveRole(args);
        Class<?> app = switch (role) {
            case "collector" -> CollectorApplication.class;
            case "consumer" -> ConsumerApplication.class;
            case "mock" -> MockApplication.class;
            default -> throw new IllegalArgumentException(
                "Unknown role '" + role + "'. Use one of: collector, consumer, mock.");
        };

        String exclusions = autoConfigExclusions(role);
        if (!exclusions.isEmpty()) {
            System.setProperty("spring.autoconfigure.exclude", exclusions);
        }

        new SpringApplicationBuilder(app).run(stripRole(args, role));
    }

    private static String resolveRole(String[] args) {
        if (args.length > 0 && !args[0].startsWith("-")) {
            return args[0];
        }
        String prop = System.getProperty("jbmp.role");
        if (prop != null && !prop.isBlank()) {
            return prop;
        }
        throw new IllegalArgumentException(
            "No role specified. Usage: java -jar jbmp-all.jar <collector|consumer|mock> [args...]");
    }

    /**
     * Auto-configurations to disable for a given role when all roles share one
     * classpath. Only the consumer needs JDBC / Flyway / a datasource.
     */
    private static String autoConfigExclusions(String role) {
        return switch (role) {
            case "collector", "mock" -> String.join(",",
                "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
                "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration");
            default -> "";
        };
    }

    private static String[] stripRole(String[] args, String role) {
        if (args.length > 0 && args[0].equals(role)) {
            return Arrays.copyOfRange(args, 1, args.length);
        }
        return args;
    }
}
