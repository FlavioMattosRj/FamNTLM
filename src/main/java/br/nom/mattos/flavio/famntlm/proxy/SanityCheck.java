package br.nom.mattos.flavio.famntlm.proxy;

import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.ntlm.Credentials;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Connectivity self-test: using the credentials resolved from the config
 * (reusing existing PassLM/PassNT/PassNTLMv2 hashes), try to reach an external
 * URL through the configured parent proxy. Reports PASS or throws with a clear
 * reason so the caller can exit non-zero on failure.
 */
public final class SanityCheck {

    private final Config config;
    private final Credentials credentials;

    public SanityCheck(Config config, Credentials credentials) {
        this.config = config;
        this.credentials = credentials;
    }

    /** Run the check against {@code url}; returns a human-readable success line or throws. */
    public String run(String url, PrintStream progress) throws IOException {
        Target target = Target.parse(url);
        if (config.proxies.isEmpty()) {
            throw new IOException("no parent Proxy configured — cannot test external access");
        }
        NtlmProxyClient client = new NtlmProxyClient(config, credentials, 10000, 20000);

        IOException last = null;
        for (Config.Proxy proxy : config.proxies) {
            progress.println("  trying " + target + " via " + proxy
                    + " as " + credentials.domain + "\\" + credentials.username
                    + " (auth=" + credentials.auth.label() + ") ...");
            try {
                if (target.tunnel) {
                    try (Socket s = client.openTunnel(proxy, target.host + ":" + target.port)) {
                        return "reached " + target + " via " + proxy + " (CONNECT tunnel established)";
                    }
                } else {
                    int status = httpGet(client, proxy, target);
                    if (status == 407) {
                        throw new IOException("proxy returned 407 after NTLM — credentials rejected");
                    }
                    if (status < 200 || status >= 400) {
                        throw new IOException("unexpected HTTP status " + status);
                    }
                    return "reached " + target + " via " + proxy + " (HTTP " + status + ")";
                }
            } catch (IOException e) {
                progress.println("    failed: " + e.getMessage());
                last = e;
            }
        }
        throw new IOException("all parent proxies failed; last error: "
                + (last != null ? last.getMessage() : "unknown"));
    }

    private int httpGet(NtlmProxyClient client, Config.Proxy proxy, Target target) throws IOException {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        String requestLine = "GET http://" + target.host
                + (target.port == 80 ? "" : ":" + target.port) + target.path + " HTTP/1.1";
        client.forwardPlain(proxy, requestLine,
                Arrays.asList("Host: " + target.host, "User-Agent: FamNTLM-test", "Accept: */*"),
                new byte[0], sink);
        return firstStatus(sink.toByteArray());
    }

    private static int firstStatus(byte[] response) {
        String head = new String(response, 0, Math.min(response.length, 64), StandardCharsets.ISO_8859_1);
        int nl = head.indexOf('\n');
        String line = nl >= 0 ? head.substring(0, nl) : head;
        String[] parts = line.trim().split(" ");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignore) {
            }
        }
        return -1;
    }

    /** A parsed test target: host, port, path, and whether to use CONNECT. */
    private static final class Target {
        final String host;
        final int port;
        final String path;
        final boolean tunnel; // https / host:port -> CONNECT; http -> GET

        Target(String host, int port, String path, boolean tunnel) {
            this.host = host;
            this.port = port;
            this.path = path;
            this.tunnel = tunnel;
        }

        static Target parse(String url) {
            String u = url.trim();
            boolean https = false;
            boolean http = false;
            if (u.regionMatches(true, 0, "https://", 0, 8)) {
                https = true;
                u = u.substring(8);
            } else if (u.regionMatches(true, 0, "http://", 0, 7)) {
                http = true;
                u = u.substring(7);
            }
            String path = "/";
            int slash = u.indexOf('/');
            if (slash >= 0) {
                path = u.substring(slash);
                u = u.substring(0, slash);
            }
            String host = u;
            int port = https ? 443 : 80;
            int colon = u.lastIndexOf(':');
            if (colon >= 0) {
                host = u.substring(0, colon);
                port = Integer.parseInt(u.substring(colon + 1));
            }
            // CONNECT tunnel for https or an explicit non-80 port; plain GET for http.
            boolean tunnel = https || (!http && port != 80);
            return new Target(host, port, path, tunnel);
        }

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }
}
