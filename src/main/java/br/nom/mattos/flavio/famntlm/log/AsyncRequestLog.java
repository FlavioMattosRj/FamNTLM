package br.nom.mattos.flavio.famntlm.log;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Non-blocking console log for processed requests. Producers enqueue onto a
 * <b>bounded</b> queue; a single daemon consumer drains it to the console. The
 * bound caps memory use so a slow console or a request burst can never exhaust
 * the heap.
 *
 * <p>Two overflow policies are supported:
 * <ul>
 *   <li><b>drop-and-count</b> (default): when the queue is full the newest line
 *       is dropped and counted, so request threads never block;</li>
 *   <li><b>backpressure</b> ({@code fullLog}, enabled by {@code --full-log}):
 *       when the queue is full the producer waits for room, so no line is ever
 *       lost — at the cost of briefly slowing a request thread only in the
 *       pathological case where logging cannot keep up.</li>
 * </ul>
 *
 * <p>Producers stay off the formatting path either way: {@link #log} captures
 * the time as a cheap {@code long} and the date is rendered later on the single
 * consumer thread.
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

    private final BlockingQueue<Entry> queue;
    private final Thread consumer;
    private final PrintStream out;
    private final boolean blockWhenFull;
    // Only ever touched by the single consumer thread -> no synchronization needed.
    private final SimpleDateFormat time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong peakBacklog = new AtomicLong();
    private volatile boolean running = true;

    /**
     * @param out           where lines are written
     * @param capacity      maximum lines buffered before the overflow policy kicks in
     * @param blockWhenFull {@code true} to apply backpressure (never drop);
     *                      {@code false} to drop-and-count on overflow
     */
    public AsyncRequestLog(PrintStream out, int capacity, boolean blockWhenFull) {
        this.out = out;
        this.blockWhenFull = blockWhenFull;
        this.queue = new LinkedBlockingQueue<>(Math.max(1, capacity));
        this.consumer = new Thread(this::drain, "famntlm-log");
        this.consumer.setDaemon(true);
        this.consumer.start();
    }

    /**
     * Enqueue a line. In drop-and-count mode this never blocks; in backpressure
     * mode it may briefly wait for room but never drops.
     */
    public void log(String line) {
        Entry e = new Entry(System.currentTimeMillis(), line);
        if (blockWhenFull) {
            try {
                queue.put(e); // waits for capacity; never drops
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt(); // shutting down; give up this line
                return;
            }
        } else if (!queue.offer(e)) {
            dropped.incrementAndGet();
            return;
        }
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

    /** Number of lines dropped under overflow (always 0 in backpressure mode). */
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
        // The consumer has stopped; flush anything still queued so nothing is lost.
        Entry e;
        while ((e = queue.poll()) != null) {
            write(e);
        }
        long d = dropped.get();
        if (d > 0) {
            out.println("[log] " + d + " entries dropped under load (use --full-log to never drop)");
        }
    }
}
