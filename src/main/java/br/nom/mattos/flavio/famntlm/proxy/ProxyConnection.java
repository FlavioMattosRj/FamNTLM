package br.nom.mattos.flavio.famntlm.proxy;

import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.log.AsyncRequestLog;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Handles a single client connection: parses the HTTP request and forwards it
 * through the parent proxy chain, authenticating with NTLM. Supports CONNECT
 * tunnels (HTTPS/any TCP) and plain absolute-URI HTTP requests.
 */
public final class ProxyConnection implements Runnable {

    private static final int MAX_BUFFERED_BODY = 4 * 1024 * 1024;

    private final Socket client;
    private final Config config;
    private final NtlmProxyClient proxyClient;
    private final AsyncRequestLog log;

    public ProxyConnection(Socket client, Config config, NtlmProxyClient proxyClient, AsyncRequestLog log) {
        this.client = client;
        this.config = config;
        this.proxyClient = proxyClient;
        this.log = log;
    }

    @Override
    public void run() {
        String peer = client.getRemoteSocketAddress() != null
                ? client.getRemoteSocketAddress().toString() : "?";
        try {
            client.setSoTimeout(60000);
            InputStream rawIn = new BufferedInputStream(client.getInputStream());
            HttpHead head = HttpHead.read(rawIn);
            String[] parts = head.firstLine.split(" ");
            if (parts.length < 3) {
                writeStatus(client, 400, "Bad Request");
                return;
            }
            String method = parts[0];
            String target = parts[1];

            if (method.equalsIgnoreCase("CONNECT")) {
                handleConnect(peer, target);
            } else {
                handlePlain(peer, head, rawIn, method, target);
            }
        } catch (IOException e) {
            log.log("ERR   " + peer + "  " + e.getMessage());
        } finally {
            closeQuietly(client);
        }
    }

    private void handleConnect(String peer, String target) throws IOException {
        if (config.proxies.isEmpty()) {
            writeStatus(client, 502, "No parent proxy configured");
            log.log("502   " + peer + "  CONNECT " + target + "  (no proxy)");
            return;
        }
        IOException last = null;
        for (Config.Proxy proxy : config.proxies) {
            try {
                Socket upstream = proxyClient.openTunnel(proxy, target);
                writeRaw(client, "HTTP/1.1 200 Connection established\r\n\r\n");
                log.log("200   " + peer + "  CONNECT " + target + "  via " + proxy);
                client.setSoTimeout(0);   // tunnels may idle for long periods
                upstream.setSoTimeout(0);
                Relay.pump(client, upstream);
                return;
            } catch (IOException e) {
                last = e;
            }
        }
        writeStatus(client, 502, "Bad Gateway");
        log.log("502   " + peer + "  CONNECT " + target + "  " + (last != null ? last.getMessage() : ""));
    }

    private void handlePlain(String peer, HttpHead head, InputStream in, String method, String target)
            throws IOException {
        byte[] body = readBody(head, in);
        if (body == null) {
            writeStatus(client, 413, "Request Entity Too Large");
            log.log("413   " + peer + "  " + method + " " + target + "  (body too large)");
            return;
        }
        if (config.proxies.isEmpty()) {
            writeStatus(client, 502, "No parent proxy configured");
            return;
        }
        IOException last = null;
        for (Config.Proxy proxy : config.proxies) {
            try {
                OutputStream clientOut = client.getOutputStream();
                proxyClient.forwardPlain(proxy, head.firstLine, head.headerLines, body, clientOut);
                log.log("200   " + peer + "  " + method + " " + target + "  via " + proxy);
                return;
            } catch (IOException e) {
                last = e;
            }
        }
        writeStatus(client, 502, "Bad Gateway");
        log.log("502   " + peer + "  " + method + " " + target + "  " + (last != null ? last.getMessage() : ""));
    }

    private static byte[] readBody(HttpHead head, InputStream in) throws IOException {
        long len = head.contentLength();
        if (len <= 0) {
            return new byte[0];
        }
        if (len > MAX_BUFFERED_BODY) {
            return null;
        }
        byte[] body = new byte[(int) len];
        int read = 0;
        while (read < body.length) {
            int n = in.read(body, read, body.length - read);
            if (n < 0) {
                break;
            }
            read += n;
        }
        return body;
    }

    private static void writeStatus(Socket socket, int code, String reason) {
        try {
            writeRaw(socket, "HTTP/1.1 " + code + " " + reason + "\r\n"
                    + "Content-Length: 0\r\nConnection: close\r\n\r\n");
        } catch (IOException ignore) {
        }
    }

    private static void writeRaw(Socket socket, String text) throws IOException {
        socket.getOutputStream().write(text.getBytes(StandardCharsets.ISO_8859_1));
        socket.getOutputStream().flush();
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignore) {
        }
    }
}
