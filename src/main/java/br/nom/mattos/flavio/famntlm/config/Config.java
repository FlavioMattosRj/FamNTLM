package br.nom.mattos.flavio.famntlm.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Full CNTLM configuration model. Every cntlm.conf directive and command-line
 * option maps onto a field here. Command-line values override values loaded
 * from the configuration file.
 */
public final class Config {

    /** A parent proxy endpoint. */
    public static final class Proxy {
        public final String host;
        public final int port;

        public Proxy(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }

    /** A local listening endpoint (optional bind address + port). */
    public static final class Listen {
        public final String bindAddress; // null => loopback (or all when gateway)
        public final int port;

        public Listen(String bindAddress, int port) {
            this.bindAddress = bindAddress;
            this.port = port;
        }
    }

    /** A transparent tunnel: local port -> remote host:port via parent proxy. */
    public static final class Tunnel {
        public final String bindAddress;
        public final int localPort;
        public final String remoteHost;
        public final int remotePort;

        public Tunnel(String bindAddress, int localPort, String remoteHost, int remotePort) {
            this.bindAddress = bindAddress;
            this.localPort = localPort;
            this.remoteHost = remoteHost;
            this.remotePort = remotePort;
        }
    }

    /** An ACL rule (allow/deny) over a CIDR or wildcard. */
    public static final class AclRule {
        public final boolean allow;
        public final String spec;

        public AclRule(boolean allow, String spec) {
            this.allow = allow;
            this.spec = spec;
        }
    }

    // Identity / credentials
    public String username;
    public String domain;
    public String workstation;
    public String password;      // plaintext (Password / -p / -I)
    public String passLM;        // hex
    public String passNT;        // hex
    public String passNTLMv2;    // hex

    // Auth behaviour
    public AuthType auth = AuthType.NTLMV2;
    public Integer flags;        // manual NTLM flag override (Flags / -F)
    public boolean ntlmToBasic;  // NTLMToBasic / -B

    // Networking
    public final List<Proxy> proxies = new ArrayList<>();
    public final List<String> noProxy = new ArrayList<>();
    public final List<Listen> listen = new ArrayList<>();
    public boolean gateway;      // Gateway / -g
    public final List<AclRule> acl = new ArrayList<>();
    public final List<String> headers = new ArrayList<>();
    public final List<Tunnel> tunnels = new ArrayList<>();

    // SOCKS5
    public final List<Listen> socks5 = new ArrayList<>();
    public final List<String> socks5Users = new ArrayList<>();

    // ISA scanner plugin
    public Integer isaScannerSize;
    public String isaScannerAgent;

    // Runtime / lifecycle
    public String configFile;
    public String pidFile;       // -P
    public String uid;           // -U
    public String traceFile;     // -T
    public boolean foreground;   // -f
    public boolean verbose;      // -v
    public boolean fullLog;      // --full-log (FamNTLM extension): never drop log lines,
                                 // apply backpressure instead of counted drops
    public boolean magicTest;    // -M
    public String magicTestUrl;

    public boolean hasHashCredentials() {
        return passNTLMv2 != null || passNT != null || passLM != null;
    }
}
