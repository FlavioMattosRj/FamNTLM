package br.nom.mattos.flavio.famntlm.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Enforces CNTLM {@code Allow}/{@code Deny} ACL rules against a connecting
 * client address.
 *
 * <p>Rules are evaluated in configuration order and the first one that matches
 * decides the outcome, matching CNTLM semantics. When no rule matches, the
 * connection is allowed — CNTLM's default — so legacy configurations that carry
 * no ACL keep behaving exactly as before. To build a whitelist, end the rule
 * list with {@code Deny *}.
 *
 * <p>A spec may be {@code *} (any address), a bare host/IP (exact match), a CIDR
 * such as {@code 192.168.0.0/16}, or an address with a dotted netmask such as
 * {@code 192.168.0.0/255.255.0.0}. Invalid specs are reported to the caller and
 * skipped rather than silently accepted.
 */
public final class AccessControl {

    private static final class Rule {
        final boolean allow;
        final boolean matchAll;
        final byte[] network;   // masked network bytes; null when matchAll
        final int prefixBits;

        Rule(boolean allow, boolean matchAll, byte[] network, int prefixBits) {
            this.allow = allow;
            this.matchAll = matchAll;
            this.network = network;
            this.prefixBits = prefixBits;
        }
    }

    private final List<Rule> rules;
    private final boolean defaultAllow;

    private AccessControl(List<Rule> rules, boolean defaultAllow) {
        this.rules = rules;
        this.defaultAllow = defaultAllow;
    }

    /**
     * Compile parsed ACL rules into a matcher. Each invalid spec is passed to
     * {@code onError} (may be {@code null}) with a human-readable reason and then
     * skipped, so one bad line does not disable the rest of the policy — callers
     * that require fail-closed behaviour should treat any reported error as fatal.
     *
     * @param defaultAllow the decision when no rule matches. Loopback-only
     *                     deployments pass {@code true} (CNTLM-compatible); public
     *                     listeners pass {@code false} so a whitelist without a
     *                     trailing {@code Deny *} still fails closed.
     */
    public static AccessControl compile(List<Config.AclRule> acl, boolean defaultAllow,
                                        Consumer<String> onError) {
        List<Rule> compiled = new ArrayList<>();
        for (Config.AclRule r : acl) {
            try {
                compiled.add(parse(r));
            } catch (IllegalArgumentException | UnknownHostException e) {
                if (onError != null) {
                    onError.accept((r.allow ? "Allow " : "Deny ") + r.spec + " - " + e.getMessage());
                }
            }
        }
        return new AccessControl(compiled, defaultAllow);
    }

    private static Rule parse(Config.AclRule r) throws UnknownHostException {
        String spec = r.spec == null ? "" : r.spec.trim();
        if (spec.isEmpty()) {
            throw new IllegalArgumentException("empty ACL spec");
        }
        if (spec.equals("*") || spec.equals("0/0") || spec.equals("0.0.0.0/0")) {
            return new Rule(r.allow, true, null, 0);
        }
        int slash = spec.indexOf('/');
        if (slash >= 0) {
            String host = spec.substring(0, slash).trim();
            String maskPart = spec.substring(slash + 1).trim();
            byte[] addr = InetAddress.getByName(host).getAddress();
            int prefix = parsePrefix(maskPart, addr.length * 8);
            return new Rule(r.allow, false, maskNetwork(addr, prefix), prefix);
        }
        byte[] addr = InetAddress.getByName(spec).getAddress();
        return new Rule(r.allow, false, addr.clone(), addr.length * 8);
    }

    private static int parsePrefix(String maskPart, int maxBits) throws UnknownHostException {
        if (maskPart.isEmpty()) {
            throw new IllegalArgumentException("missing prefix after '/'");
        }
        if (maskPart.indexOf('.') >= 0 || maskPart.indexOf(':') >= 0) {
            // Dotted netmask form, e.g. 255.255.0.0
            byte[] mask = InetAddress.getByName(maskPart).getAddress();
            if (mask.length * 8 != maxBits) {
                throw new IllegalArgumentException("netmask family does not match address");
            }
            return maskToPrefix(mask); // <= maxBits by construction
        }
        int bits;
        try {
            bits = Integer.parseInt(maskPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid prefix length: " + maskPart);
        }
        if (bits < 0 || bits > maxBits) {
            throw new IllegalArgumentException("prefix length out of range: " + bits);
        }
        return bits;
    }

    private static int maskToPrefix(byte[] mask) {
        int bits = 0;
        boolean zeroSeen = false;
        for (byte b : mask) {
            for (int i = 7; i >= 0; i--) {
                boolean set = ((b >> i) & 1) != 0;
                if (set) {
                    if (zeroSeen) {
                        throw new IllegalArgumentException("non-contiguous netmask");
                    }
                    bits++;
                } else {
                    zeroSeen = true;
                }
            }
        }
        return bits;
    }

    private static byte[] maskNetwork(byte[] addr, int prefixBits) {
        byte[] out = addr.clone();
        for (int i = 0; i < out.length; i++) {
            int bitStart = i * 8;
            if (bitStart >= prefixBits) {
                out[i] = 0;
            } else if (bitStart + 8 > prefixBits) {
                int keep = prefixBits - bitStart;              // 1..7
                out[i] &= (0xFF << (8 - keep)) & 0xFF;
            }
        }
        return out;
    }

    /** True when {@code addr} is permitted; first matching rule wins, else the default. */
    public boolean isAllowed(InetAddress addr) {
        byte[] a = addr.getAddress();
        for (Rule r : rules) {
            if (matches(r, a)) {
                return r.allow;
            }
        }
        return defaultAllow; // no rule matched
    }

    private static boolean matches(Rule r, byte[] addr) {
        if (r.matchAll) {
            return true;
        }
        if (r.network.length != addr.length) {
            return false; // different address family (IPv4 vs IPv6)
        }
        // Clamp defensively: a malformed rule must never index past the array.
        int prefix = Math.min(r.prefixBits, r.network.length * 8);
        int fullBytes = prefix / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (r.network[i] != addr[i]) {
                return false;
            }
        }
        int remBits = prefix % 8;
        if (remBits != 0) {
            int mask = (0xFF << (8 - remBits)) & 0xFF;
            return (r.network[fullBytes] & mask) == (addr[fullBytes] & mask);
        }
        return true;
    }

    /** Whether any rule is in force (used to decide open-proxy warnings). */
    public boolean isEmpty() {
        return rules.isEmpty();
    }
}
