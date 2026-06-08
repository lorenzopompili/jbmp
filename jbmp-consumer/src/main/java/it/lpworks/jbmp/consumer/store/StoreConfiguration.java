package it.lpworks.jbmp.consumer.store;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Selects which {@link StoreWriter} implementation backs the consumer.
 *
 * <p>The default is the {@link InMemoryStoreWriter}, which lets the service start and run
 * locally (and in tests) with no database. The PostgreSQL-backed {@link JdbcStoreWriter} is
 * activated when the property {@code jbmp.consumer.store=jdbc} is set (so opting into a real
 * database is explicit); selecting it requires a {@link DataSource}, which Spring Boot
 * auto-configures from {@code spring.datasource.*}. When the JDBC writer is active it takes
 * precedence; otherwise the in-memory writer is registered as the sole {@link StoreWriter}.
 */
@Configuration
public class StoreConfiguration {

    /**
     * The PostgreSQL-backed writer, active only when explicitly opted into and a data source
     * exists.
     *
     * @param dataSource the configured data source
     * @return a JDBC store writer
     */
    @Bean
    @ConditionalOnProperty(name = "jbmp.consumer.store", havingValue = "jdbc")
    public StoreWriter jdbcStoreWriter(DataSource dataSource) {
        return new JdbcStoreWriter(dataSource);
    }

    /**
     * The default in-memory writer, used whenever no other {@link StoreWriter} bean (i.e. the
     * JDBC writer) has been registered.
     *
     * @return an in-memory store writer
     */
    @Bean
    @ConditionalOnMissingBean(StoreWriter.class)
    public StoreWriter inMemoryStoreWriter() {
        return new InMemoryStoreWriter();
    }
}
