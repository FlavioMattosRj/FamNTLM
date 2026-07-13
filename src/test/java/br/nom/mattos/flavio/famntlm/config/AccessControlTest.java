package br.nom.mattos.flavio.famntlm.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/**
 * Verifies CNTLM-compatible Allow/Deny evaluation: first match wins, default is
 * allow when nothing matches, and the common subnet/host/wildcard spec forms.
 */
public class AccessControlTest {

    private static AccessControl acl(Config.AclRule... rules) {
        return acl(true, rules);
    }

    private static AccessControl acl(boolean defaultAllow, Config.AclRule... rules) {
        List<Config.AclRule> list = new ArrayList<>();
        for (Config.AclRule r : rules) {
            list.add(r);
        }
        return AccessControl.compile(list, defaultAllow, null);
    }

    private static Config.AclRule allow(String spec) {
        return new Config.AclRule(true, spec);
    }

    private static Config.AclRule deny(String spec) {
        return new Config.AclRule(false, spec);
    }

    private static boolean allowed(AccessControl acl, String ip) throws UnknownHostException {
        return acl.isAllowed(InetAddress.getByName(ip));
    }

    @Test
    public void emptyPolicyAllowsEverything() throws Exception {
        AccessControl acl = acl();
        assertTrue(acl.isEmpty());
        assertTrue(allowed(acl, "8.8.8.8"));
        assertTrue(allowed(acl, "192.168.1.1"));
    }

    @Test
    public void denyAllBlocksEverything() throws Exception {
        AccessControl acl = acl(deny("*"));
        assertFalse(allowed(acl, "127.0.0.1"));
        assertFalse(allowed(acl, "10.0.0.5"));
    }

    @Test
    public void whitelistPattern_allowSubnetThenDenyAll() throws Exception {
        // Classic hardening: permit the LAN, deny the rest.
        AccessControl acl = acl(allow("192.168.0.0/16"), deny("*"));
        assertTrue(allowed(acl, "192.168.1.50"));
        assertTrue(allowed(acl, "192.168.255.255"));
        assertFalse(allowed(acl, "192.169.0.1"));
        assertFalse(allowed(acl, "8.8.8.8"));
    }

    @Test
    public void firstMatchWins() throws Exception {
        // Deny a single host, but allow the surrounding /24 — order decides.
        AccessControl acl = acl(deny("10.0.0.7"), allow("10.0.0.0/24"), deny("*"));
        assertFalse(allowed(acl, "10.0.0.7"));
        assertTrue(allowed(acl, "10.0.0.8"));
        assertFalse(allowed(acl, "10.0.1.1"));
    }

    @Test
    public void cidrPrefixBoundaries() throws Exception {
        AccessControl acl = acl(allow("172.16.0.0/12"), deny("*"));
        assertTrue(allowed(acl, "172.16.0.1"));
        assertTrue(allowed(acl, "172.31.255.254"));
        assertFalse(allowed(acl, "172.32.0.1"));
        assertFalse(allowed(acl, "172.15.255.255"));
    }

    @Test
    public void dottedNetmaskEquivalentToCidr() throws Exception {
        AccessControl acl = acl(allow("192.168.0.0/255.255.255.0"), deny("*"));
        assertTrue(allowed(acl, "192.168.0.42"));
        assertFalse(allowed(acl, "192.168.1.42"));
    }

    @Test
    public void bareHostIsExactMatch() throws Exception {
        AccessControl acl = acl(allow("127.0.0.1"), deny("*"));
        assertTrue(allowed(acl, "127.0.0.1"));
        assertFalse(allowed(acl, "127.0.0.2"));
    }

    @Test
    public void familyMismatchedMaskIsReportedAndSkipped() throws Exception {
        // IPv4 address with an IPv6-length mask: must be rejected at compile time,
        // never producing a rule whose prefix overruns the address on match.
        List<String> errors = new ArrayList<>();
        List<Config.AclRule> rules = new ArrayList<>();
        rules.add(new Config.AclRule(true, "10.0.0.0/ffff:ffff:ffff::"));
        rules.add(deny("*"));
        AccessControl acl = AccessControl.compile(rules, true, errors::add);

        assertEquals(1, errors.size());
        // The bad rule was skipped and matching must not throw for any client.
        assertFalse(allowed(acl, "10.0.0.5"));
        assertFalse(allowed(acl, "192.168.1.1"));
    }

    @Test
    public void invalidSpecIsReportedAndSkipped() throws Exception {
        List<String> errors = new ArrayList<>();
        List<Config.AclRule> rules = new ArrayList<>();
        rules.add(new Config.AclRule(true, "192.168.0.0/999")); // prefix out of range
        rules.add(deny("*"));
        AccessControl acl = AccessControl.compile(rules, true, errors::add);

        assertEquals(1, errors.size());
        // The bad Allow was skipped, so Deny * governs and blocks everyone.
        assertFalse(allowed(acl, "192.168.1.1"));
    }

    @Test
    public void defaultDenyMakesWhitelistFailClosed() throws Exception {
        // A public listener (defaultAllow=false) with only an Allow rule must deny
        // everyone outside it even without a trailing Deny *.
        AccessControl acl = acl(false, allow("192.168.0.0/16"));
        assertTrue(allowed(acl, "192.168.1.1"));
        assertFalse(allowed(acl, "8.8.8.8"));
    }

    @Test
    public void defaultDenyWithEmptyPolicyBlocksEverything() throws Exception {
        AccessControl acl = acl(false);
        assertTrue(acl.isEmpty());
        assertFalse(allowed(acl, "127.0.0.1"));
        assertFalse(allowed(acl, "10.0.0.5"));
    }
}
