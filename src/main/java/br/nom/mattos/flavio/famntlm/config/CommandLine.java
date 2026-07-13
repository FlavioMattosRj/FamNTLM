package br.nom.mattos.flavio.famntlm.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses CNTLM-compatible command-line options. Every flag documented for the
 * original cntlm binary is accepted. Trailing non-option arguments are treated
 * as parent proxies (host:port), exactly like cntlm.
 *
 * Options that also exist as config directives are stored here and applied on
 * top of the loaded configuration file so that the command line always wins.
 */
public final class CommandLine {

    public String configFile;      // -c
    public boolean help;           // -h
    public boolean generateHashes; // -H
    public boolean interactive;    // -I
    public boolean serialize;      // -s
    public boolean foreground;     // -f
    public boolean verbose;        // -v
    public boolean gateway;        // -g
    public boolean ntlmToBasic;    // -B
    public boolean fullLog;        // --full-log (FamNTLM extension)
    public boolean allowOpenProxy; // --allow-open-proxy (FamNTLM extension)

    public String username;        // -u  (user[@domain])
    public String cliDomain;       // -d
    public String password;        // -p
    public String workstation;     // -w
    public String authType;        // -a
    public String flags;           // -F
    public String pidFile;         // -P
    public String uid;             // -U
    public String traceFile;       // -T
    public String isaSize;         // -S
    public String isaAgent;        // -G
    public String magicUrl;        // -M

    public final List<String> listen = new ArrayList<>();     // -l
    public final List<String> tunnels = new ArrayList<>();     // -L
    public final List<String> allow = new ArrayList<>();       // -A
    public final List<String> deny = new ArrayList<>();        // -D
    public final List<String> noProxy = new ArrayList<>();     // -N
    public final List<String> headers = new ArrayList<>();     // -r
    public final List<String> socks5 = new ArrayList<>();      // -O
    public final List<String> socks5Users = new ArrayList<>(); // -R
    public final List<String> proxies = new ArrayList<>();     // positional

    public static CommandLine parse(String[] args) {
        CommandLine c = new CommandLine();
        int i = 0;
        while (i < args.length) {
            String arg = args[i];
            if (arg.equals("--")) {
                i++;
                while (i < args.length) {
                    c.proxies.add(args[i++]);
                }
                break;
            }
            if (arg.startsWith("--")) {
                // Long options are FamNTLM extensions (cntlm has none). Note that
                // --list-config is intercepted earlier, before parse() is reached.
                if (arg.equals("--full-log")) {
                    c.fullLog = true;
                } else if (arg.equals("--allow-open-proxy")) {
                    c.allowOpenProxy = true;
                } else {
                    throw new IllegalArgumentException("Unknown option: " + arg);
                }
                i++;
                continue;
            }
            if (arg.length() < 2 || arg.charAt(0) != '-') {
                c.proxies.add(arg);
                i++;
                continue;
            }
            char opt = arg.charAt(1);
            String inline = arg.length() > 2 ? arg.substring(2) : null;
            switch (opt) {
                // Flags without arguments
                case 'h': c.help = true; i++; break;
                case 'H': c.generateHashes = true; i++; break;
                case 'I': c.interactive = true; i++; break;
                case 's': c.serialize = true; i++; break;
                case 'f': c.foreground = true; i++; break;
                case 'v': c.verbose = true; c.foreground = true; i++; break;
                case 'g': c.gateway = true; i++; break;
                case 'B': c.ntlmToBasic = true; i++; break;
                // Options taking one argument
                case 'c': c.configFile = takeArg(args, i, inline); i += step(inline); break;
                case 'u': c.username = takeArg(args, i, inline); i += step(inline); break;
                case 'd': c.cliDomain = takeArg(args, i, inline); i += step(inline); break;
                case 'p': c.password = takeArg(args, i, inline); i += step(inline); break;
                case 'w': c.workstation = takeArg(args, i, inline); i += step(inline); break;
                case 'a': c.authType = takeArg(args, i, inline); i += step(inline); break;
                case 'F': c.flags = takeArg(args, i, inline); i += step(inline); break;
                case 'P': c.pidFile = takeArg(args, i, inline); i += step(inline); break;
                case 'U': c.uid = takeArg(args, i, inline); i += step(inline); break;
                case 'T': c.traceFile = takeArg(args, i, inline); i += step(inline); break;
                case 'S': c.isaSize = takeArg(args, i, inline); i += step(inline); break;
                case 'G': c.isaAgent = takeArg(args, i, inline); i += step(inline); break;
                case 'M': c.magicUrl = takeArg(args, i, inline); i += step(inline); break;
                case 'l': c.listen.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'L': c.tunnels.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'A': c.allow.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'D': c.deny.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'N': c.noProxy.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'r': c.headers.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'O': c.socks5.add(takeArg(args, i, inline)); i += step(inline); break;
                case 'R': c.socks5Users.add(takeArg(args, i, inline)); i += step(inline); break;
                default:
                    throw new IllegalArgumentException("Unknown option: -" + opt);
            }
        }
        return c;
    }

    private static String takeArg(String[] args, int i, String inline) {
        if (inline != null) {
            return inline;
        }
        if (i + 1 >= args.length) {
            throw new IllegalArgumentException("Option -" + args[i].charAt(1) + " requires a value");
        }
        return args[i + 1];
    }

    private static int step(String inline) {
        return inline != null ? 1 : 2;
    }

    /** Apply command-line values on top of the loaded configuration. */
    public void applyOverrides(Config cfg) {
        if (username != null) {
            int at = username.indexOf('@');
            if (at >= 0) {
                cfg.username = username.substring(0, at);
                if (cliDomain == null) {
                    cfg.domain = username.substring(at + 1);
                }
            } else {
                cfg.username = username;
            }
        }
        if (cliDomain != null) cfg.domain = cliDomain;
        if (password != null) cfg.password = password;
        if (workstation != null) cfg.workstation = workstation;
        if (authType != null) cfg.auth = AuthType.parse(authType);
        if (flags != null) cfg.flags = (int) Long.decode(flags).longValue();
        if (pidFile != null) cfg.pidFile = pidFile;
        if (uid != null) cfg.uid = uid;
        if (traceFile != null) cfg.traceFile = traceFile;
        if (isaSize != null) cfg.isaScannerSize = Integer.parseInt(isaSize.trim());
        if (isaAgent != null) cfg.isaScannerAgent = isaAgent;
        if (magicUrl != null) {
            cfg.magicTest = true;
            cfg.magicTestUrl = magicUrl;
        }
        if (gateway) cfg.gateway = true;
        if (ntlmToBasic) cfg.ntlmToBasic = true;
        if (fullLog) cfg.fullLog = true;
        if (allowOpenProxy) cfg.allowOpenProxy = true;
        if (foreground) cfg.foreground = true;
        if (verbose) cfg.verbose = true;

        for (String p : proxies) cfg.proxies.add(ConfigParser.parseProxy(p));
        for (String l : listen) cfg.listen.add(ConfigParser.parseListen(l));
        for (String t : tunnels) cfg.tunnels.add(ConfigParser.parseTunnel(t));
        for (String a : allow) cfg.acl.add(new Config.AclRule(true, a));
        for (String d : deny) cfg.acl.add(new Config.AclRule(false, d));
        for (String h : headers) cfg.headers.add(h);
        for (String s : socks5) cfg.socks5.add(ConfigParser.parseListen(s));
        for (String s : socks5Users) cfg.socks5Users.add(s);
        for (String n : noProxy) {
            for (String part : n.split(",")) {
                String t = part.trim();
                if (!t.isEmpty()) cfg.noProxy.add(t);
            }
        }
    }
}
