package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import org.jboss.logging.Logger;
import org.jspecify.annotations.NonNull;

/**
 * Samples the Keycloak container's JVM heap via JMX while a Gatling simulation runs and records the
 * real heap figures (used / committed / max, in MB) to a {@code memory-monitor.csv} under the simulation's
 * Gatling report directory.
 *
 * <p>The heap is read from the Keycloak JVM ({@code java.lang:type=Memory}) through the JMX port
 * exposed by {@link LoadTestContainer}. Each sample is appended to
 * {@code target/gatling/<simulation>-<timestamp>/memory-monitor.csv}. Start the sampler from a
 * simulation's {@code before} hook and stop it from {@code after}.
 */
public final class MemoryMonitor {

    private static final Logger logger = Logger.getLogger(MemoryMonitor.class);
    private static final String SAMPLER_TAG = "memory-monitor";

    private static final String MEMORY_BEAN = "java.lang:type=Memory";
    private static final String HEAP_USAGE_ATTR = "HeapMemoryUsage";
    private static final String HEAP_USED = "used";
    private static final String HEAP_COMMITTED = "committed";
    private static final String HEAP_MAX = "max";
    private static final long MB = 1024L * 1024L;

    private final String simulationName;
    private final long intervalMillis;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private Path output;
    private Thread samplerThread;

    public MemoryMonitor(Class<?> simulation) {
        this(simulation.getSimpleName(), 1000L);
    }

    public MemoryMonitor(String simulationName, long intervalMillis) {
        this.simulationName = simulationName;
        this.intervalMillis = intervalMillis;
    }

    /**
     * Starts the sampling thread. Safe to call multiple times (no-op if already running).
     */
    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            samplerThread = new Thread(this::loop, SAMPLER_TAG);
            samplerThread.setDaemon(true);
            samplerThread.start();
        }
    }

    /**
     * Stops the sampling thread and waits for it to terminate.
     */
    public synchronized void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }

        Thread thread = samplerThread;
        if (thread != null) {
            thread.interrupt();

            try {
                thread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            if (thread.isAlive()) {
                logger.warn("Sampler thread did not stop within 2 seconds");
            } else {
                samplerThread = null;
            }
        }

        logger.info("Stopped. Full time series: " + outputPath().toAbsolutePath());
    }

    private void loop() {
        JMXConnector jmxConnector = null;

        try {
            while (running.get()) {
                try {
                    if (jmxConnector == null) {
                        jmxConnector = JMXConnectorFactory.connect(LoadTestContainer.getJmxServiceUrl(), null);
                    }

                    HeapSample sample = sampleHeap(jmxConnector.getMBeanServerConnection());
                    ensureHeader();
                    writeRow(sample);
                    logger.info("Sampled heap: " + sample);
                } catch (Exception e) {
                    logger.error("Sampling error: " + e.getMessage(), e);

                    closeConnector(jmxConnector);
                    jmxConnector = null;
                }

                try {
                    // noinspection BusyWait
                    Thread.sleep(intervalMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {
            closeConnector(jmxConnector);
        }
    }

    private HeapSample sampleHeap(MBeanServerConnection conn) throws Exception {
        ObjectName name = new ObjectName(MEMORY_BEAN);
        CompositeData heap = (CompositeData) conn.getAttribute(name, HEAP_USAGE_ATTR);

        return new HeapSample(
                System.currentTimeMillis(), (Long) heap.get(HEAP_USED), (Long) heap.get(HEAP_COMMITTED), (Long)
                        heap.get(HEAP_MAX));
    }

    private static void closeConnector(JMXConnector connector) {
        if (connector != null) {
            try {
                connector.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private void ensureHeader() {
        if (!Files.exists(outputPath())) {
            writeHeader();
        }
    }

    private void writeHeader() {
        try {
            Path target = outputPath();
            Files.createDirectories(target.getParent());

            Files.writeString(
                    target,
                    "timestamp_epoch_ms,heap_used_mb,heap_committed_mb,heap_max_mb\n",
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            logger.error("Cannot write header: " + e.getMessage(), e);
        }
    }

    private void writeRow(HeapSample sample) {
        try {
            Files.writeString(outputPath(), sample.toCsv() + "\n", StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException e) {
            logger.error("Cannot write row: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves the CSV path inside the current simulation's Gatling report folder.
     */
    private Path outputPath() {
        if (output == null) {
            output = resolveReportDir().resolve(SAMPLER_TAG + ".csv");
            logger.info("Writing to " + output.toAbsolutePath());
        }

        return output;
    }

    /**
     * Picks the current simulation's Gatling results directory, using the timestamp embedded in the
     * folder name ({@code <simulation>-<yyyyMMddHHmmssSSS>}).
     */
    private Path resolveReportDir() {
        Path base = Path.of("target", "gatling");
        String prefix = simulationName.toLowerCase();

        try (Stream<Path> dirs = Files.list(base)) {
            return dirs.filter(Files::isDirectory)
                    .filter(dir -> dir.getFileName().toString().startsWith(prefix))
                    .max(Comparator.comparingLong(MemoryMonitor::runTimestamp))
                    .orElse(base);
        } catch (IOException e) {
            return base;
        }
    }

    /**
     * Parses the {@code <timestamp>} suffix of a Gatling results dir name, else falls back to mtime.
     */
    private static long runTimestamp(Path dir) {
        String name = dir.getFileName().toString();
        int dash = name.lastIndexOf('-');

        if (dash >= 0) {
            try {
                return Long.parseLong(name.substring(dash + 1));
            } catch (NumberFormatException ignored) {
                // not a Gatling results dir; fall through
            }
        }

        return dir.toFile().lastModified();
    }

    private record HeapSample(long timestampMillis, long usedBytes, long committedBytes, long maxBytes) {

        String toCsv() {
            return String.join(
                    ",",
                    Long.toString(timestampMillis),
                    Long.toString(usedBytes / MB),
                    Long.toString(committedBytes / MB),
                    Long.toString(maxBytes / MB));
        }

        @Override
        public @NonNull String toString() {
            return String.format(
                    "used=%d MB, committed=%d MB, max=%d MB", usedBytes / MB, committedBytes / MB, maxBytes / MB);
        }
    }
}
