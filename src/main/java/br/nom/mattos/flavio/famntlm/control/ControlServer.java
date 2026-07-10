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

/**
 * A small loopback control channel. The running proxy listens for one-line
 * commands ("STOP", "STATUS") so a second invocation of the program can stop it
 * cleanly across platforms without relying on POSIX signals.
 */
public final class ControlServer {

    public static final int DEFAULT_PORT = 3129;

    public interface Handler {
        String handle(String command);
    }

    private final int port;
    private final Handler handler;
    private ServerSocket serverSocket;
    private Thread thread;
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
        thread = new Thread(this::loop, "famntlm-control");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop() {
        while (running) {
            try (Socket s = serverSocket.accept()) {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
                String command = in.readLine();
                if (command == null) {
                    continue;
                }
                String reply = handler.handle(command.trim());
                OutputStream out = s.getOutputStream();
                out.write((reply + "\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } catch (IOException e) {
                if (running) {
                    // Transient accept failure; keep serving.
                }
            }
        }
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignore) {
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
