package br.nom.mattos.flavio.famntlm.proxy;

/**
 * A parsed request target: the destination {@code host} and {@code port}, plus —
 * for absolute-form HTTP requests — the {@code originForm} (path + query) used
 * when talking straight to the origin server. Parsing is lenient and returns
 * {@code null} for anything it cannot make sense of, so callers fall back to the
 * parent-proxy path rather than guessing.
 */
final class HttpTarget {

    final String host;        // lower-cased, no brackets
    final int port;
    final String originForm;  // e.g. "/path?query"; null for a CONNECT authority

    private HttpTarget(String host, int port, String originForm) {
        this.host = host;
        this.port = port;
        this.originForm = originForm;
    }

    /** Parse a CONNECT authority: {@code host:port} or {@code [ipv6]:port}. */
    static HttpTarget parseAuthority(String authority, int defaultPort) {
        if (authority == null || authority.isEmpty()) {
            return null;
        }
        String host;
        int port = defaultPort;
        if (authority.charAt(0) == '[') {                 // [ipv6]:port
            int end = authority.indexOf(']');
            if (end < 0) {
                return null;
            }
            host = authority.substring(1, end);
            int colon = authority.indexOf(':', end);
            if (colon >= 0) {
                port = parsePort(authority.substring(colon + 1), defaultPort);
            }
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                port = parsePort(authority.substring(colon + 1), defaultPort);
            } else {
                host = authority;
            }
        }
        if (host.isEmpty()) {
            return null;
        }
        return new HttpTarget(host.toLowerCase(), port, null);
    }

    /** Parse an absolute-form URI: {@code http://[user@]host[:port]/path?query}. */
    static HttpTarget parseAbsolute(String uri) {
        int schemeEnd = uri.indexOf("://");
        if (schemeEnd < 0) {
            return null;
        }
        String scheme = uri.substring(0, schemeEnd).toLowerCase();
        int defaultPort = scheme.equals("https") ? 443 : 80;

        int authStart = schemeEnd + 3;
        int authEnd = uri.length();
        for (int i = authStart; i < uri.length(); i++) {
            char c = uri.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                authEnd = i;
                break;
            }
        }
        String authority = uri.substring(authStart, authEnd);
        int at = authority.lastIndexOf('@');           // drop any user:pass@
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        HttpTarget base = parseAuthority(authority, defaultPort);
        if (base == null) {
            return null;
        }
        String origin = authEnd < uri.length() ? uri.substring(authEnd) : "/";
        if (origin.isEmpty() || origin.charAt(0) != '/') {
            origin = "/" + origin;                     // e.g. "?q" -> "/?q"
        }
        return new HttpTarget(base.host, base.port, origin);
    }

    /** Value for a synthesized {@code Host} header (port omitted when standard). */
    String hostHeader() {
        return (port == 80 || port == 443) ? host : host + ":" + port;
    }

    private static int parsePort(String s, int dflt) {
        try {
            int p = Integer.parseInt(s.trim());
            return (p > 0 && p <= 65535) ? p : dflt;
        } catch (NumberFormatException e) {
            return dflt;
        }
    }
}
