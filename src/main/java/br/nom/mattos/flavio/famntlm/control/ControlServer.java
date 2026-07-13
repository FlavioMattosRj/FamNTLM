package br.nom.mattos.flavio.famntlm.control;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A small loopback control channel. The running proxy listens for one-line
 * commands ("STOP", "STATUS") so a second invocation of the program can stop it
 * cleanly across platforms without relying on POSIX signals.
 */
public final class ControlServer {

    public static final int DEFAULT_PORT = 3129;

    /** A control command is tiny; anything larger is treated as hostile. */
    private static final int MAX_COMMAND_LEN = 256;
    /** A legitimate client sends its line immediately after connecting. */
    private static final int READ_TIMEOUT_MS = 2000;
    /** Cap on concurrent control connections; excess connections are shed. */
    private static final int MAX_WORKERS = 8;

    public interface Handler {
        String handle(String command);
    }

    private final int port;
    private final Handler handler;
    private ServerSocket serverSocket;
    private Thread thread;
    private ThreadPoolExecutor workers;
    private volatile boolean running = true;

    public ControlServer(int port, Handler handler) {
        this.port = port;
        this.handler = handler;
    }

    public static int port() {
        String env = System.getenv("FAMNTLM_CONTROL_PORT");
        if (env != null) {
            try {
                return Integer.parseInt(env.trim());
            } catch (NumberFormatException ignore) {
            }
        }
        return DEFAULT_PORT;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        workers = new ThreadPoolExecutor(0, MAX_WORKERS, 15, TimeUnit.SECONDS,
                new SynchronousQueue<>(), daemonFactory());
        thread = new Thread(this::loop, "famntlm-control");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop() {
        while (running) {
            Socket s;
            try {
                s = serverSocket.accept();
            } catch (IOException e) {
                continue; // socket closed on shutdown, or a transient failure
            }
            try {
                // Handle off the accept thread so a silent/slow client can never
                // block the channel; shed load if too many are already in flight.
                workers.execute(() -> handle(s));
            } catch (RejectedExecutionException reject) {
                closeQuietly(s);
            }
        }
    }

    private void handle(Socket s) {
        try (Socket sock = s) {
            // A silent or slow client must not tie up a worker indefinitely, and
            // an oversized line must not exhaust memory.
            sock.setSoTimeout(READ_TIMEOUT_MS);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream(), StandardCharsets.US_ASCII));
            String command = readCommand(in);
            if (command == null) {
                return;
            }
            String reply = handler.handle(command.trim());
            OutputStream out = sock.getOutputStream();
            out.write((reply + "\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
        } catch (IOException | RuntimeException e) {
            // Includes SocketTimeoutException from a client that never sent a line
            // and any handler fault: drop this connection, keep serving.
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignore) {
        }
    }

    private static ThreadFactory daemonFactory() {
        final AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, "famntlm-control-worker-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    /**
     * Read a single command line, bounded in length so a client cannot exhaust
     * memory by sending an endless line. Returns {@code null} on EOF with nothing
     * read, or when the line exceeds {@link #MAX_COMMAND_LEN}.
     */
    private static String readCommand(BufferedReader in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                break;
            }
            if (c == '\r') {
                continue;
            }
            if (sb.length() >= MAX_COMMAND_LEN) {
                return null; // oversized: reject without reading further
            }
            sb.append((char) c);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignore) {
        }
        if (workers != null) {
            workers.shutdownNow();
        }
    }

    /** Send a command to a running instance and return its reply, or null if none. */
    public static String send(int port, String command) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 2000);
            s.setSoTimeout(3000);
            s.getOutputStream().write((command + "\n").getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().flush();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            return in.readLine();
        } catch (IOException e) {
            return null;
        }
    }
}
