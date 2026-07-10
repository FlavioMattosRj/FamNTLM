package br.nom.mattos.flavio.famntlm;

import br.nom.mattos.flavio.famntlm.config.CommandLine;
import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.config.ConfigParser;
import br.nom.mattos.flavio.famntlm.control.ControlServer;
import br.nom.mattos.flavio.famntlm.log.AsyncRequestLog;
import br.nom.mattos.flavio.famntlm.ntlm.Credentials;
import br.nom.mattos.flavio.famntlm.ntlm.NtlmCrypto;
import br.nom.mattos.flavio.famntlm.proxy.ProxyServer;
import br.nom.mattos.flavio.famntlm.proxy.SanityCheck;
import br.nom.mattos.flavio.famntlm.util.Hex;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

/**
 * FamNTLM — a Java re-implementation of CNTLM: an authenticating NTLM/NTLMv2
 * proxy that is configuration- and command-line-compatible with the original.
 */
public final class FamNTLM {

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException e) {
            System.err.println("famntlm: " + e.getMessage());
            System.exit(2);
        } catch (IOException e) {
            System.err.println("famntlm: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException {
        // Lifecycle subcommands (FamNTLM extension over CNTLM).
        if (args.length > 0 && (args[0].equalsIgnoreCase("stop") || args[0].equalsIgnoreCase("status"))) {
            String reply = ControlServer.send(ControlServer.port(), args[0].toUpperCase());
            if (reply == null) {
                System.err.println("famntlm: no running instance on control port " + ControlServer.port());
                System.exit(1);
            }
            System.out.println(reply);
            return;
        }
        if (args.length > 0 && args[0].equalsIgnoreCase("test")) {
            runSanityTest(Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        if (hasToken(args, "-list-config") || hasToken(args, "--list-config")) {
            runListConfig(args);
            return;
        }

        CommandLine cmd = CommandLine.parse(args);
        if (cmd.help) {
            printUsage(System.out);
            return;
        }
        if (cmd.generateHashes) {
            generateHashes(cmd);
            return;
        }

        Config cfg = new Config();
        File configFile = ConfigParser.resolve(cmd.configFile);
        if (configFile != null && configFile.isFile()) {
            ConfigParser.parseInto(configFile, cfg);
            cfg.configFile = configFile.getPath();
        } else if (cmd.configFile != null) {
            throw new IOException("Config file not found: " + cmd.configFile);
        }
        cmd.applyOverrides(cfg);

        if (cmd.interactive || (cfg.password == null && !cfg.hasHashCredentials())) {
            cfg.password = promptPassword("Password: ");
        }

        Credentials credentials = Credentials.from(cfg);
        String problem = credentials.validate();
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
        if (cfg.proxies.isEmpty()) {
            System.err.println("famntlm: warning — no parent Proxy configured; requests will fail");
        }

        startProxy(cfg, credentials);
    }

    private static void startProxy(Config cfg, Credentials credentials) throws IOException {
        AsyncRequestLog log = new AsyncRequestLog(8192, System.out);
        ProxyServer server = new ProxyServer(cfg, credentials, log);
        CountDownLatch stopLatch = new CountDownLatch(1);

        ControlServer control = new ControlServer(ControlServer.port(), command -> {
            if (command.equalsIgnoreCase("STOP")) {
                stopLatch.countDown();
                return "stopping";
            }
            if (command.equalsIgnoreCase("STATUS")) {
                return "running; dropped-log-entries=" + log.droppedCount();
            }
            return "unknown command: " + command;
        });

        server.start();
        control.start();
        writePidFile(cfg);

        log.log("[famntlm] started as " + credentials.domain + "\\" + credentials.username
                + " auth=" + credentials.auth.label()
                + (cfg.configFile != null ? "  config=" + cfg.configFile : "")
                + "  control-port=" + ControlServer.port());

        Runtime.getRuntime().addShutdownHook(new Thread(stopLatch::countDown, "famntlm-sigterm"));

        try {
            stopLatch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.log("[famntlm] shutting down");
        control.stop();
        server.shutdown();
        removePidFile(cfg);
        log.shutdown();
    }

    /**
     * `famntlm test [-c file] [-u user] [-d domain] [-p pass] [url]` — reuse the
     * credentials/hashes from the config and try to reach an external URL through
     * the parent proxy. Exits non-zero on failure.
     */
    private static void runSanityTest(String[] args) throws IOException {
        String configFile = null;
        String url = "https://example.com";
        String user = null, domain = null, password = null, auth = null;
        boolean urlSet = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("-c")) {
                configFile = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (a.startsWith("-u")) {
                user = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (a.startsWith("-d")) {
                domain = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (a.startsWith("-p")) {
                password = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (a.startsWith("-a")) {
                auth = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (!a.startsWith("-")) {
                url = a;
                urlSet = true;
            }
        }

        Config cfg = new Config();
        File file = ConfigParser.resolve(configFile);
        if (file != null && file.isFile()) {
            ConfigParser.parseInto(file, cfg);
            cfg.configFile = file.getPath();
        } else if (configFile != null) {
            throw new IOException("Config file not found: " + configFile);
        }
        if (user != null) cfg.username = user;
        if (domain != null) cfg.domain = domain;
        if (password != null) cfg.password = password;
        if (auth != null) cfg.auth = br.nom.mattos.flavio.famntlm.config.AuthType.parse(auth);

        System.out.println("[test] config: " + (cfg.configFile != null ? cfg.configFile : "(none)"));
        System.out.println("[test] identity: " + cfg.domain + "\\" + cfg.username
                + "  auth=" + cfg.auth.label()
                + "  credentials=" + describeCreds(cfg)
                + (urlSet ? "" : "  (default url)"));

        Credentials credentials = Credentials.from(cfg);
        String problem = credentials.validate();
        if (problem != null) {
            System.err.println("famntlm: test FAILED - " + problem);
            System.exit(1);
        }
        try {
            String ok = new SanityCheck(cfg, credentials).run(url, System.out);
            System.out.println("[test] PASS: " + ok);
        } catch (IOException e) {
            System.err.println("famntlm: test FAILED - " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * `-list-config [-c file] [url]` — locate the configuration, describe where
     * it came from, print every directive EXCEPT the secret keys (Pass* hashes /
     * plaintext password are masked), then run the connectivity self-test through
     * the proxy and report its result. Terminates the JVM at the end.
     */
    private static void runListConfig(String[] args) throws IOException {
        String configFile = null;
        String url = "https://example.com";
        boolean urlSet = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equalsIgnoreCase("-list-config") || a.equalsIgnoreCase("--list-config")) {
                continue;
            }
            if (a.startsWith("-c")) {
                configFile = optValue(a, args, i);
                i += a.length() > 2 ? 0 : 1;
            } else if (!a.startsWith("-")) {
                url = a;
                urlSet = true;
            }
        }

        PrintStream o = System.out;
        o.println("=== FamNTLM configuration report ===");

        File file = ConfigParser.resolve(configFile);
        if (configFile != null) {
            o.println("Source          : -c override");
            o.println("Location        : " + configFile + (file != null && file.isFile() ? "" : "  (NOT FOUND)"));
        } else if (file != null) {
            o.println("Source          : default search path");
            o.println("Location        : " + file.getPath());
        } else {
            o.println("Source          : default search path");
            o.println("Location        : (none found)");
        }
        o.println("Searched paths  : " + String.join(", ", ConfigParser.defaultLocations()));

        Config cfg = new Config();
        if (file != null && file.isFile()) {
            ConfigParser.parseInto(file, cfg);
            cfg.configFile = file.getPath();
        } else if (configFile != null) {
            System.err.println("famntlm: config file not found: " + configFile);
            System.exit(1);
        } else {
            System.err.println("famntlm: no configuration file found");
            System.exit(1);
        }

        o.println();
        o.println("--- Parameters (secret keys hidden) ---");
        printParameters(cfg, o);

        o.println();
        o.println("--- Connectivity self-test ---");
        Credentials credentials = Credentials.from(cfg);
        String problem = credentials.validate();
        int exit;
        if (problem != null) {
            o.println("Result          : SKIPPED (" + problem + ")");
            exit = 1;
        } else {
            try {
                String ok = new SanityCheck(cfg, credentials).run(url, o);
                o.println("Result          : PASS - " + ok);
                exit = 0;
            } catch (IOException e) {
                o.println("Result          : FAIL - " + e.getMessage());
                exit = 1;
            }
        }
        o.println("URL tested      : " + url + (urlSet ? "" : "  (default)"));
        o.flush();
        System.exit(exit);
    }

    private static void printParameters(Config cfg, PrintStream o) {
        line(o, "Username", cfg.username);
        line(o, "Domain", cfg.domain);
        line(o, "Workstation", cfg.workstation != null ? cfg.workstation
                : Credentials.defaultWorkstation() + " (auto)");
        line(o, "Auth", cfg.auth.label());
        line(o, "Flags", cfg.flags != null ? "0x" + Integer.toHexString(cfg.flags) : null);
        line(o, "NTLMToBasic", cfg.ntlmToBasic ? "yes" : "no");
        line(o, "Gateway", cfg.gateway ? "yes" : "no");
        line(o, "Credentials", describeCreds(cfg) + " (values hidden)");

        for (Config.Proxy p : cfg.proxies) {
            line(o, "Proxy", p.toString());
        }
        if (!cfg.noProxy.isEmpty()) {
            line(o, "NoProxy", String.join(", ", cfg.noProxy));
        }
        for (Config.Listen l : cfg.listen) {
            line(o, "Listen", (l.bindAddress != null ? l.bindAddress + ":" : "") + l.port);
        }
        for (Config.AclRule r : cfg.acl) {
            line(o, r.allow ? "Allow" : "Deny", r.spec);
        }
        for (String h : cfg.headers) {
            line(o, "Header", h);
        }
        for (Config.Tunnel t : cfg.tunnels) {
            line(o, "Tunnel", (t.bindAddress != null ? t.bindAddress + ":" : "")
                    + t.localPort + ":" + t.remoteHost + ":" + t.remotePort);
        }
        for (Config.Listen s : cfg.socks5) {
            line(o, "SOCKS5Proxy", (s.bindAddress != null ? s.bindAddress + ":" : "") + s.port);
        }
        for (String su : cfg.socks5Users) {
            int colon = su.indexOf(':');
            line(o, "SOCKS5User", (colon > 0 ? su.substring(0, colon) : su) + ":*** (password hidden)");
        }
        line(o, "ISAScannerSize", cfg.isaScannerSize != null ? String.valueOf(cfg.isaScannerSize) : null);
        line(o, "ISAScannerAgent", cfg.isaScannerAgent);
    }

    private static void line(PrintStream o, String name, String value) {
        if (value != null) {
            o.printf("%-16s: %s%n", name, value);
        }
    }

    private static boolean hasToken(String[] args, String token) {
        for (String a : args) {
            if (a.equalsIgnoreCase(token)) {
                return true;
            }
        }
        return false;
    }

    private static String describeCreds(Config cfg) {
        StringBuilder sb = new StringBuilder();
        if (cfg.passNTLMv2 != null) sb.append("PassNTLMv2 ");
        if (cfg.passNT != null) sb.append("PassNT ");
        if (cfg.passLM != null) sb.append("PassLM ");
        if (cfg.password != null) sb.append("Password ");
        return sb.length() == 0 ? "(none!)" : sb.toString().trim();
    }

    private static String optValue(String arg, String[] args, int i) {
        if (arg.length() > 2) {
            return arg.substring(2);
        }
        if (i + 1 < args.length) {
            return args[i + 1];
        }
        throw new IllegalArgumentException("Option " + arg + " requires a value");
    }

    private static void generateHashes(CommandLine cmd) throws IOException {
        String user = cmd.username != null ? cmd.username : "";
        int at = user.indexOf('@');
        String domain = cmd.cliDomain != null ? cmd.cliDomain : "";
        if (at >= 0) {
            if (domain.isEmpty()) {
                domain = user.substring(at + 1);
            }
            user = user.substring(0, at);
        }
        String password = cmd.password != null ? cmd.password : promptPassword("Password: ");

        byte[] nt = NtlmCrypto.ntHash(password);
        byte[] lm = NtlmCrypto.lmHash(password);
        System.out.println("Username        " + user);
        System.out.println("Domain          " + domain);
        System.out.println("PassLM          " + Hex.encode(lm));
        System.out.println("PassNT          " + Hex.encode(nt));
        if (!user.isEmpty()) {
            byte[] v2 = NtlmCrypto.ntlmv2Hash(nt, user, domain);
            System.out.println("PassNTLMv2      " + Hex.encode(v2));
        } else {
            System.out.println("# PassNTLMv2 requires -u <user> (and -d <domain>) to be computed");
        }
    }

    private static String promptPassword(String prompt) throws IOException {
        if (System.console() != null) {
            char[] pw = System.console().readPassword(prompt);
            return pw == null ? "" : new String(pw);
        }
        System.out.print(prompt);
        System.out.flush();
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = r.readLine();
        return line == null ? "" : line;
    }

    private static void writePidFile(Config cfg) {
        if (cfg.pidFile == null) {
            return;
        }
        try {
            String pid = String.valueOf(ProcessHandleCompat.currentPid());
            Files.write(Paths.get(cfg.pidFile), (pid + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            System.err.println("famntlm: cannot write pidfile: " + e.getMessage());
        }
    }

    private static void removePidFile(Config cfg) {
        if (cfg.pidFile != null) {
            try {
                Files.deleteIfExists(Paths.get(cfg.pidFile));
            } catch (IOException ignore) {
            }
        }
    }

    private static void printUsage(java.io.PrintStream o) {
        o.println("FamNTLM - CNTLM-compatible NTLM authenticating proxy (Java)");
        o.println();
        o.println("Usage: famntlm [options] [parent-proxy:port ...]");
        o.println("       famntlm stop | status");
        o.println("       famntlm test [-c file] [-u user] [-d domain] [-p pass] [url]");
        o.println("            reach an external URL through the proxy using the config's");
        o.println("            credentials/hashes; exits non-zero on failure");
        o.println("       famntlm -list-config [-c file] [url]");
        o.println("            locate the config, print all parameters (secret keys hidden),");
        o.println("            run the self-test through the proxy, then exit");
        o.println();
        o.println("Options (CNTLM-compatible):");
        o.println("  -A <ip/mask>   Allow ACL rule            -a <type>   Auth: NTLMv2|NTLM2SR|NT|NTLM|LM");
        o.println("  -B             NTLM-to-basic             -c <file>   Config file");
        o.println("  -D <ip/mask>   Deny ACL rule             -d <domain> Account domain");
        o.println("  -F <flags>     NTLM flag override        -f          Foreground");
        o.println("  -G <pattern>   ISA scanner User-Agent    -g          Gateway mode");
        o.println("  -H             Generate password hashes  -h          This help");
        o.println("  -I             Prompt for password       -L <tunnel> [saddr:]lport:rhost:rport");
        o.println("  -l <[saddr:]port>  Listen endpoint       -M <url>    Magic dialect detection");
        o.println("  -N <patterns>  NoProxy host patterns     -O <[saddr:]port> SOCKS5 listen");
        o.println("  -P <pidfile>   Write PID file            -p <pass>   Account password");
        o.println("  -R <user:pass> SOCKS5 account            -r <hdr>    Header substitution");
        o.println("  -S <kb>        ISA scanner size          -s          Serialize (no threads)");
        o.println("  -T <file>      Trace file                -U <uid>    Drop privileges to uid");
        o.println("  -u <user>      Account username          -v          Verbose (implies -f)");
        o.println("  -w <host>      Workstation name");
        o.println();
        o.println("Default config: " + String.join(", ", ConfigParser.defaultLocations()));
        o.println("Stop a running instance: famntlm stop   (control port " + ControlServer.port() + ")");
    }
}
