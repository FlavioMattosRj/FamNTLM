package br.nom.mattos.flavio.famntlm.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Reaches an origin server <b>directly</b>, bypassing the parent proxy, for hosts
 * matched by {@code NoProxy}. It performs no NTLM authentication: a CONNECT target
 * becomes a raw TCP tunnel, and a plain absolute-URI request is rewritten to
 * origin form and sent straight to the server.
 */
final class DirectClient {

    private final int connectTimeoutMs;
    private final int soTimeoutMs;

    DirectClient(int connectTimeoutMs, int soTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.soTimeoutMs = soTimeoutMs;
    }

    /** Open a raw TCP tunnel to the CONNECT target for a NoProxy bypass. */
    Socket openDirectTunnel(HttpTarget target) throws IOException {
        Socket socket = new Socket();
        boolean ok = false;
        try {
            socket.connect(new InetSocketAddress(target.host, target.port), connectTimeoutMs);
            socket.setTcpNoDelay(true);
            ok = true;
            return socket;
        } finally {
            if (!ok) {
                try {
                    socket.close();
                } catch (IOException ignore) {
                }
            }
        }
    }

    /**
     * Forward a plain HTTP request straight to the origin server. The absolute-URI
     * request line is rewritten to origin form ({@code GET /path HTTP/1.1}), proxy
     * and hop-by-hop headers are dropped, a {@code Host} header is ensured, and the
     * response is streamed back to the client to EOF ({@code Connection: close}).
     */
    void forwardDirect(String method, HttpTarget target, List<String> headers,
                       byte[] body, OutputStream clientOut) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target.host, target.port), connectTimeoutMs);
            socket.setSoTimeout(soTimeoutMs);
            socket.setTcpNoDelay(true);
            OutputStream out = socket.getOutputStream();

            StringBuilder sb = new StringBuilder();
            sb.append(method).append(' ').append(target.originForm).append(" HTTP/1.1\r\n");
            boolean hasHost = false;
            for (String h : headers) {
                if (isProxyOrHopByHop(h)) {
                    continue;
                }
                if (startsWithIgnoreCase(h, "host:")) {
                    hasHost = true;
                }
                sb.append(h).append("\r\n");
            }
            if (!hasHost) {
                sb.append("Host: ").append(target.hostHeader()).append("\r\n");
            }
            sb.append("Content-Length: ").append(body == null ? 0 : body.length).append("\r\n");
            sb.append("Connection: close\r\n");
            sb.append("\r\n");
            out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
            if (body != null && body.length > 0) {
                out.write(body);
            }
            out.flush();

            copyToEof(socket.getInputStream(), clientOut);
        }
    }

    private static boolean isProxyOrHopByHop(String headerLine) {
        int colon = headerLine.indexOf(':');
        if (colon < 0) {
            return false;
        }
        String name = headerLine.substring(0, colon).trim().toLowerCase();
        return name.equals("proxy-authorization") || name.equals("proxy-connection")
                || name.equals("connection") || name.equals("content-length")
                || name.equals("transfer-encoding") || name.equals("keep-alive");
    }

    private static boolean startsWithIgnoreCase(String s, String prefix) {
        return s.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    private static void copyToEof(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        out.flush();
    }
}
