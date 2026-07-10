package br.nom.mattos.flavio.famntlm.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/** Bidirectional byte pump between two sockets; returns when either side ends. */
public final class Relay {

    private Relay() {
    }

    public static void pump(Socket a, Socket b) throws IOException {
        Thread t = new Thread(() -> copyQuietly(a, b), "famntlm-relay");
        t.setDaemon(true);
        t.start();
        copyQuietly(b, a);
        try {
            t.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void copyQuietly(Socket from, Socket to) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignore) {
            // Connection closed by one side; propagate shutdown below.
        } finally {
            shutdown(from);
            shutdown(to);
        }
    }

    private static void shutdown(Socket s) {
        try {
            if (!s.isClosed()) {
                s.shutdownOutput();
            }
        } catch (IOException ignore) {
        }
    }
}
