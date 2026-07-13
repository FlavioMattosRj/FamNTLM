package br.nom.mattos.flavio.famntlm.config;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Matches a request hostname against the {@code NoProxy} patterns. When a host
 * matches, the request is sent <b>directly</b> to the origin server instead of
 * through the parent proxy — the CNTLM {@code NoProxy} bypass.
 *
 * <p>Patterns use shell-style wildcards, like CNTLM: {@code *} matches any run of
 * characters and {@code ?} matches a single character; everything else is literal.
 * Matching is anchored (the whole host must match) and case-insensitive, so
 * {@code *.intranet.local} matches {@code host.intranet.local} but not the bare
 * {@code intranet.local}, and {@code 127.0.0.*} matches {@code 127.0.0.5}.
 */
public final class NoProxyMatcher {

    private final List<Pattern> patterns;

    private NoProxyMatcher(List<Pattern> patterns) {
        this.patterns = patterns;
    }

    public static NoProxyMatcher compile(List<String> specs) {
        List<Pattern> compiled = new ArrayList<>();
        for (String s : specs) {
            String spec = s == null ? "" : s.trim();
            if (!spec.isEmpty()) {
                compiled.add(Pattern.compile(globToRegex(spec), Pattern.CASE_INSENSITIVE));
            }
        }
        return new NoProxyMatcher(compiled);
    }

    /** Whether any NoProxy pattern is configured. */
    public boolean isEmpty() {
        return patterns.isEmpty();
    }

    /** True when {@code host} should bypass the parent proxy and be reached directly. */
    public boolean matches(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        for (Pattern p : patterns) {
            if (p.matcher(host).matches()) {
                return true;
            }
        }
        return false;
    }

    private static String globToRegex(String glob) {
        StringBuilder sb = new StringBuilder(glob.length() + 8);
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*':
                    sb.append(".*");
                    break;
                case '?':
                    sb.append('.');
                    break;
                default:
                    if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                        sb.append('\\');
                    }
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
