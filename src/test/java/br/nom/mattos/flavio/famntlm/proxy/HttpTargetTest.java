package br.nom.mattos.flavio.famntlm.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/** Parsing of CONNECT authorities and absolute-form request URIs. */
public class HttpTargetTest {

    @Test
    public void connectAuthorityWithPort() {
        HttpTarget t = HttpTarget.parseAuthority("Example.COM:8443", 443);
        assertEquals("example.com", t.host);
        assertEquals(8443, t.port);
        assertNull(t.originForm);
    }

    @Test
    public void connectAuthorityDefaultPort() {
        HttpTarget t = HttpTarget.parseAuthority("example.com", 443);
        assertEquals("example.com", t.host);
        assertEquals(443, t.port);
    }

    @Test
    public void connectIpv6Authority() {
        HttpTarget t = HttpTarget.parseAuthority("[2001:db8::1]:993", 443);
        assertEquals("2001:db8::1", t.host);
        assertEquals(993, t.port);
    }

    @Test
    public void absoluteUriHostPortAndOrigin() {
        HttpTarget t = HttpTarget.parseAbsolute("http://example.com:8080/path/x?y=1");
        assertEquals("example.com", t.host);
        assertEquals(8080, t.port);
        assertEquals("/path/x?y=1", t.originForm);
    }

    @Test
    public void absoluteUriDefaultPortAndRootPath() {
        HttpTarget t = HttpTarget.parseAbsolute("http://example.com");
        assertEquals("example.com", t.host);
        assertEquals(80, t.port);
        assertEquals("/", t.originForm);
    }

    @Test
    public void absoluteUriStripsUserinfo() {
        HttpTarget t = HttpTarget.parseAbsolute("http://user:pass@example.com/a");
        assertEquals("example.com", t.host);
        assertEquals("/a", t.originForm);
    }

    @Test
    public void hostHeaderOmitsStandardPort() {
        assertEquals("example.com", HttpTarget.parseAbsolute("http://example.com/x").hostHeader());
        assertEquals("example.com:8080",
                HttpTarget.parseAbsolute("http://example.com:8080/x").hostHeader());
    }

    @Test
    public void nonAbsoluteReturnsNull() {
        assertNull(HttpTarget.parseAbsolute("/just/a/path"));
    }
}
