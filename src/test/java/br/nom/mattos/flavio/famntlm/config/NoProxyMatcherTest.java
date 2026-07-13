package br.nom.mattos.flavio.famntlm.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

/** CNTLM-style NoProxy glob matching: anchored, case-insensitive, {@code *}/{@code ?} wildcards. */
public class NoProxyMatcherTest {

    private static NoProxyMatcher of(String... specs) {
        return NoProxyMatcher.compile(Arrays.asList(specs));
    }

    @Test
    public void emptyMatcherMatchesNothing() {
        NoProxyMatcher m = NoProxyMatcher.compile(Collections.emptyList());
        assertTrue(m.isEmpty());
        assertFalse(m.matches("example.com"));
    }

    @Test
    public void wildcardSuffixMatchesSubdomains() {
        NoProxyMatcher m = of("*.intranet.local");
        assertTrue(m.matches("host.intranet.local"));
        assertTrue(m.matches("a.b.intranet.local"));
        // Anchored, like CNTLM: the bare domain does not match a "*." pattern.
        assertFalse(m.matches("intranet.local"));
        assertFalse(m.matches("intranet.local.evil.com"));
    }

    @Test
    public void ipWildcardMatchesRange() {
        NoProxyMatcher m = of("127.0.0.*");
        assertTrue(m.matches("127.0.0.1"));
        assertTrue(m.matches("127.0.0.255"));
        assertFalse(m.matches("127.0.1.1"));
    }

    @Test
    public void exactAndCaseInsensitive() {
        NoProxyMatcher m = of("localhost");
        assertTrue(m.matches("localhost"));
        assertTrue(m.matches("LOCALHOST"));
        assertFalse(m.matches("localhost.localdomain"));
    }

    @Test
    public void questionMarkMatchesSingleChar() {
        NoProxyMatcher m = of("host?.corp");
        assertTrue(m.matches("host1.corp"));
        assertTrue(m.matches("hostA.corp"));
        assertFalse(m.matches("host12.corp"));
    }

    @Test
    public void anyOfSeveralPatternsMatches() {
        NoProxyMatcher m = of("localhost", "*.intranet.local", "10.*");
        assertTrue(m.matches("localhost"));
        assertTrue(m.matches("wiki.intranet.local"));
        assertTrue(m.matches("10.1.2.3"));
        assertFalse(m.matches("example.com"));
    }
}
