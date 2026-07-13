package br.nom.mattos.flavio.famntlm.log;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Non-blocking console log for processed requests. Producers enqueue onto an
 * unbounded queue; a single daemon consumer drains it to the console. No entry
 * is ever dropped: under load the backlog grows and then shrinks again as the
 * consumer catches up.
 *
 * <p>Producers stay off the request-processing critical path: {@link #log} only
 * captures the current time as a cheap {@code long} and hands the line to a
 * lock-free enqueue. The (non-thread-safe) date formatting happens later, on the
 * single consumer thread, so producers never contend on a shared formatter.
 */
public final class AsyncRequestLog {

    /** One pending line: capture the time cheaply now, render it later. */
    private static final class Entry {
        final long epochMillis;
        final String line;

        Entry(long epochMillis, String line) {
            this.epochMillis = epochMillis;
            this.line = line;
        }
    }

    private final BlockingQueue<Entry> queue = new LinkedBlockingQueue<>();
    private final Thread consumer;
    private final PrintStream out;
    // Only ever touched by the single consumer thread -> no synchronization needed.
    private final SimpleDateFormat time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private final AtomicLong peakBacklog = new AtomicLong();
    private volatile boolean running = true;

    public AsyncRequestLog(PrintStream out) {
        this.out = out;
        this.consumer = new Thread(this::drain, "famntlm-log");
        this.consumer.setDaemon(true);
        this.consumer.start();
    }

    /**
     * Enqueue a line. Never blocks and never drops: the unbounded queue grows if
     * the consumer falls behind and drains again once it catches up.
     */
    public void log(String line) {
        queue.add(new Entry(System.currentTimeMillis(), line));
        // Best-effort high-water mark for observability; size() is O(1) here.
        peakBacklog.accumulateAndGet(queue.size(), Math::max);
    }

    private void drain() {
        while (running || !queue.isEmpty()) {
            try {
                Entry e = queue.poll(200, TimeUnit.MILLISECONDS);
                if (e != null) {
                    write(e);
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void write(Entry e) {
        out.println(time.format(new Date(e.epochMillis)) + "  " + e.line);
    }

    /** Lines currently waiting to be written (0 when the log is caught up). */
    public int backlog() {
        return queue.size();
    }

    /** Largest backlog observed so far, i.e. the peak number of pending lines. */
    public long peakBacklog() {
        return peakBacklog.get();
    }

    public void shutdown() {
        running = false;
        consumer.interrupt();
        try {
            consumer.join(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // The consumer has stopped; flush anything still queued so nothing is lost.
        Entry e;
        while ((e = queue.poll()) != null) {
            write(e);
        }
    }
}
