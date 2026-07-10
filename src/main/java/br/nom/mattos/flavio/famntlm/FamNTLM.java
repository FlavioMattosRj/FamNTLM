package br.nom.mattos.flavio.famntlm;

import br.nom.mattos.flavio.famntlm.config.CommandLine;
import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.config.ConfigParser;
import br.nom.mattos.flavio.famntlm.control.ControlServer;
import br.nom.mattos.flavio.famntlm.log.AsyncRequestLog;
import br.nom.mattos.flavio.famntlm.ntlm.Credentials;
import br.nom.mattos.flavio.famntlm.ntlm.NtlmCrypto;
import br.nom.mattos.flavio.famntlm.proxy.ProxyServer;
import br.nom.mattos.flavio.famntlm.util.Hex;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
