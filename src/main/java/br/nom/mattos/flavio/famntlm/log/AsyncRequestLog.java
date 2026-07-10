package br.nom.mattos.flavio.famntlm.log;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Non-blocking console log for processed requests. Producers enqueue onto a
 * bounded ring; a single daemon consumer drains it to the console. When the
 * buffer is full the newest entry is dropped rather than blocking the request
 * threads, so logging never becomes a throughput bottleneck under load. The
 * number of dropped entries is tracked and reported.
 */
public final class AsyncRequestLog {

    private static final SimpleDateFormat TIME = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    private final BlockingQueue<String> queue;
    private final Thread consumer;
    private final PrintStream out;
    private final AtomicLong dropped = new AtomicLong();
    private volatile boolean running = true;

    public AsyncRequestLog(int capacity, PrintStream out) {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.out = out;
        this.consumer = new Thread(this::drain, "famntlm-log");
        this.consumer.setDaemon(true);
        this.consumer.start();
    }

    /** Enqueue a line. Never blocks; drops the entry if the buffer is saturated. */
    public void log(String line) {
        String stamped;
        synchronized (TIME) {
            stamped = TIME.format(new Date()) + "  " + line;
        }
        if (!queue.offer(stamped)) {
            dropped.incrementAndGet();
        }
    }

    private void drain() {
        while (running || !queue.isEmpty()) {
            try {
                String line = queue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (line != null) {
                    out.println(line);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    public long droppedCount() {
        return dropped.get();
    }

    public void shutdown() {
        running = false;
        consumer.interrupt();
        try {
            consumer.join(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        long d = dropped.get();
        if (d > 0) {
            out.println("[log] " + d + " entries dropped under load");
        }
    }
}
