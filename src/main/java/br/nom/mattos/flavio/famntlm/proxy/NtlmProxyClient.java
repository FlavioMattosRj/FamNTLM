package br.nom.mattos.flavio.famntlm.proxy;

import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.ntlm.Credentials;
import br.nom.mattos.flavio.famntlm.ntlm.NtlmMessages;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Performs the NTLM authentication handshake against a parent proxy. Currently
 * implements the CONNECT (tunnel) flow, which covers HTTPS and any TCP tunnel:
 *
 *   1. CONNECT with Proxy-Authorization: NTLM &lt;Type1&gt;
 *   2. parent replies 407 with Proxy-Authenticate: NTLM &lt;Type2&gt;
 *   3. reissue CONNECT with Proxy-Authorization: NTLM &lt;Type3&gt; on the same socket
 *   4. parent replies 200 and the socket becomes a raw tunnel
 */
public final class NtlmProxyClient {

    private final Config config;
    private final Credentials credentials;
    private final int connectTimeoutMs;
    private final int soTimeoutMs;

    public NtlmProxyClient(Config config, Credentials credentials, int connectTimeoutMs, int soTimeoutMs) {
        this.config = config;
        this.credentials = credentials;
        this.connectTimeoutMs = connectTimeoutMs;
        this.soTimeoutMs = soTimeoutMs;
    }

    /** Open an authenticated CONNECT tunnel to {@code targetHostPort} via the parent proxy. */
    public Socket openTunnel(Config.Proxy proxy, String targetHostPort) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(proxy.host, proxy.port), connectTimeoutMs);
        socket.setSoTimeout(soTimeoutMs);
        socket.setTcpNoDelay(true);
        boolean ok = false;
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            byte[] type1 = NtlmMessages.type1(credentials.auth, config.flags);
            sendConnect(out, targetHostPort, "NTLM " + b64(type1));

            HttpHead resp = HttpHead.read(in);
            if (resp.statusCode() == 200) {
                ok = true;
                return socket;
            }
            if (resp.statusCode() != 407) {
                throw new IOException("Parent proxy refused CONNECT: " + resp.firstLine);
            }
            String challengeHeader = findNtlmChallenge(resp);
            if (challengeHeader == null) {
                throw new IOException("Parent proxy did not offer NTLM: " + resp.firstLine);
            }
            verbose("CONNECT %s: challenge %s (Content-Length=%s, Transfer-Encoding=%s)",
                    targetHostPort, resp.firstLine, resp.header("Content-Length"),
                    resp.header("Transfer-Encoding"));
            drainBody(in, resp);

            NtlmMessages.Challenge challenge = parseChallenge(challengeHeader);
            verbose("Type-2 flags=0x%08x targetInfoLen=%d -> Type-3 flags=0x%08x auth=%s user=%s\\%s",
                    challenge.flags, challenge.targetInfo.length,
                    NtlmMessages.authenticateFlags(challenge.flags, config.flags),
                    credentials.auth.label(), credentials.domain, credentials.username);
            byte[] type3 = NtlmMessages.type3(credentials, challenge, config.flags);
            sendConnect(out, targetHostPort, "NTLM " + b64(type3));

            HttpHead finalResp = HttpHead.read(in);
            if (finalResp.statusCode() == 200) {
                ok = true;
                return socket;
            }
            verbose("CONNECT %s: authentication rejected: %s", targetHostPort, finalResp.firstLine);
            throw new IOException("NTLM authentication failed: " + finalResp.firstLine);
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
     * Forward a plain (absolute-URI) HTTP request through the parent proxy with
     * NTLM auth and stream the response to {@code clientOut}. The negotiate leg
     * carries no body (Content-Length: 0, keep-alive); the authenticate leg
     * carries the real body and asks the parent to close, so the response can be
     * streamed to EOF.
     */
    public void forwardPlain(Config.Proxy proxy, String requestLine,
                             java.util.List<String> headers, byte[] body,
                             OutputStream clientOut) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(proxy.host, proxy.port), connectTimeoutMs);
            socket.setSoTimeout(soTimeoutMs);
            socket.setTcpNoDelay(true);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            byte[] type1 = NtlmMessages.type1(credentials.auth, config.flags);
            sendPlain(out, requestLine, headers, "NTLM " + b64(type1), 0, null, true);

            HttpHead resp = HttpHead.read(in);
            if (resp.statusCode() == 407) {
                String challengeHeader = findNtlmChallenge(resp);
                if (challengeHeader == null) {
                    throw new IOException("Parent proxy did not offer NTLM: " + resp.firstLine);
                }
                verbose("%s: challenge %s (Content-Length=%s, Transfer-Encoding=%s)",
                        proxy, resp.firstLine, resp.header("Content-Length"),
                        resp.header("Transfer-Encoding"));
                drainBody(in, resp);
                NtlmMessages.Challenge challenge = parseChallenge(challengeHeader);
                verbose("Type-2 flags=0x%08x targetInfoLen=%d -> Type-3 flags=0x%08x auth=%s user=%s\\%s",
                        challenge.flags, challenge.targetInfo.length,
                        NtlmMessages.authenticateFlags(challenge.flags, config.flags),
                        credentials.auth.label(), credentials.domain, credentials.username);
                byte[] type3 = NtlmMessages.type3(credentials, challenge, config.flags);
                sendPlain(out, requestLine, headers, "NTLM " + b64(type3),
                        body == null ? 0 : body.length, body, false);
                copyToEof(in, clientOut);
            } else {
                // Already authenticated or a direct answer; relay whatever came back.
                clientOut.write(resp.raw);
                drainToClient(in, resp, clientOut);
            }
        }
    }

    private void sendPlain(OutputStream out, String requestLine, java.util.List<String> headers,
                           String auth, int contentLength, byte[] body, boolean keepAlive)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(requestLine).append("\r\n");
        for (String h : headers) {
            if (isHopByHop(h)) {
                continue;
            }
            sb.append(h).append("\r\n");
        }
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Proxy-Connection: ").append(keepAlive ? "Keep-Alive" : "close").append("\r\n");
        sb.append("Connection: ").append(keepAlive ? "Keep-Alive" : "close").append("\r\n");
        sb.append("Proxy-Authorization: ").append(auth).append("\r\n");
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body != null && body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    /**
     * Decode and parse a parent proxy's NTLM Type-2 challenge, converting any
     * malformed input (bad Base64, truncated/oversized fields) into an
     * {@code IOException}. That way a hostile or broken parent triggers the
     * normal per-proxy failover path instead of an unchecked exception that would
     * kill the worker thread.
     */
    private NtlmMessages.Challenge parseChallenge(String challengeHeader) throws IOException {
        try {
            return NtlmMessages.parseType2(Base64.getDecoder().decode(challengeHeader));
        } catch (RuntimeException e) {
            throw new IOException("malformed NTLM challenge from parent proxy: " + e);
        }
    }

    /** Print an NTLM handshake diagnostic line to stderr when running with -v. */
    private void verbose(String fmt, Object... args) {
        if (config.verbose) {
            System.err.println("[ntlm] " + String.format(fmt, args));
        }
    }

    private static boolean isHopByHop(String headerLine) {
        int colon = headerLine.indexOf(':');
        if (colon < 0) {
            return false;
        }
        String name = headerLine.substring(0, colon).trim().toLowerCase();
        return name.equals("proxy-authorization") || name.equals("proxy-connection")
                || name.equals("connection") || name.equals("content-length")
                || name.equals("transfer-encoding")
                || name.equals("proxy-authenticate") || name.equals("keep-alive");
    }

    private static void copyToEof(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        out.flush();
    }

    private static void drainToClient(InputStream in, HttpHead head, OutputStream out) throws IOException {
        long remaining = head.contentLength();
        byte[] buf = new byte[16384];
        while (remaining > 0) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
            if (n < 0) {
                break;
            }
            out.write(buf, 0, n);
            remaining -= n;
        }
        out.flush();
    }

    private void sendConnect(OutputStream out, String hostPort, String auth) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("CONNECT ").append(hostPort).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(hostPort).append("\r\n");
        sb.append("Proxy-Connection: Keep-Alive\r\n");
        sb.append("Connection: Keep-Alive\r\n");
        sb.append("Proxy-Authorization: ").append(auth).append("\r\n");
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    private static String findNtlmChallenge(HttpHead resp) {
        for (String value : resp.headers("Proxy-Authenticate")) {
            String v = value.trim();
            if (v.regionMatches(true, 0, "NTLM ", 0, 5)) {
                return v.substring(5).trim();
            }
        }
        return null;
    }

    private static void drainBody(InputStream in, HttpHead head) throws IOException {
        long remaining = head.contentLength();
        byte[] buf = new byte[4096];
        while (remaining > 0) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
            if (n < 0) {
                break;
            }
            remaining -= n;
        }
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
