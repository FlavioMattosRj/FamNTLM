package br.nom.mattos.flavio.famntlm.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a cntlm.conf / cntlm.ini file. The grammar matches CNTLM: one
 * "Keyword value" per line, '#' or ';' start comments, keywords are
 * case-insensitive, and several keywords may repeat.
 */
public final class ConfigParser {

    private ConfigParser() {
    }

    /** Resolve the config file to use, honouring the -c override and CNTLM defaults. */
    public static File resolve(String explicitPath) {
        if (explicitPath != null) {
            return new File(explicitPath);
        }
        for (String candidate : defaultLocations()) {
            File f = new File(candidate);
            if (f.isFile()) {
                return f;
            }
        }
        return null;
    }

    public static List<String> defaultLocations() {
        List<String> paths = new ArrayList<>();
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (windows) {
            String programFiles = System.getenv("PROGRAMFILES");
            if (programFiles != null) {
                paths.add(programFiles + File.separator + "Cntlm" + File.separator + "cntlm.ini");
            }
            paths.add("cntlm.ini");
        } else {
            paths.add("/etc/cntlm.conf");
            paths.add("/usr/local/etc/cntlm.conf");
        }
        return paths;
    }

    public static void parseInto(File file, Config cfg) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                String trimmed = stripComment(line).trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int sep = firstWhitespace(trimmed);
                String key;
                String value;
                if (sep < 0) {
                    key = trimmed;
                    value = "";
                } else {
                    key = trimmed.substring(0, sep);
                    value = trimmed.substring(sep + 1).trim();
                }
                try {
                    applyDirective(cfg, key, value);
                } catch (RuntimeException e) {
                    throw new IOException(file + ":" + lineNo + ": " + e.getMessage(), e);
                }
            }
        }
    }

    static void applyDirective(Config cfg, String key, String value) {
        switch (key.toLowerCase()) {
            case "username":
                cfg.username = value;
                break;
            case "domain":
                cfg.domain = value;
                break;
            case "workstation":
                cfg.workstation = value;
                break;
            case "password":
                cfg.password = value;
                break;
            case "passlm":
                cfg.passLM = value;
                break;
            case "passnt":
                cfg.passNT = value;
                break;
            case "passntlmv2":
                cfg.passNTLMv2 = value;
                break;
            case "auth":
                cfg.auth = AuthType.parse(value);
                break;
            case "flags":
                cfg.flags = (int) Long.decode(value).longValue();
                break;
            case "gateway":
                cfg.gateway = parseBool(value);
                break;
            case "ntlmtobasic":
                cfg.ntlmToBasic = parseBool(value);
                break;
            case "proxy":
                cfg.proxies.add(parseProxy(value));
                break;
            case "noproxy":
                for (String p : value.split(",")) {
                    String t = p.trim();
                    if (!t.isEmpty()) {
                        cfg.noProxy.add(t);
                    }
                }
                break;
            case "listen":
                cfg.listen.add(parseListen(value));
                break;
            case "allow":
                cfg.acl.add(new Config.AclRule(true, value));
                break;
            case "deny":
                cfg.acl.add(new Config.AclRule(false, value));
                break;
            case "header":
                cfg.headers.add(value);
                break;
            case "tunnel":
                cfg.tunnels.add(parseTunnel(value));
                break;
            case "socks5proxy":
                cfg.socks5.add(parseListen(value));
                break;
            case "socks5user":
                cfg.socks5Users.add(value);
                break;
            case "isascannersize":
                cfg.isaScannerSize = Integer.parseInt(value.trim());
                break;
            case "isascanneragent":
                cfg.isaScannerAgent = value;
                break;
            default:
                throw new IllegalArgumentException("Unknown directive: " + key);
        }
    }

    static Config.Proxy parseProxy(String value) {
        int colon = value.lastIndexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("Proxy needs host:port: " + value);
        }
        String host = value.substring(0, colon).trim();
        int port = Integer.parseInt(value.substring(colon + 1).trim());
        return new Config.Proxy(host, port);
    }

    static Config.Listen parseListen(String value) {
        // [saddr:]port
        int colon = value.lastIndexOf(':');
        if (colon < 0) {
            return new Config.Listen(null, Integer.parseInt(value.trim()));
        }
        String addr = value.substring(0, colon).trim();
        int port = Integer.parseInt(value.substring(colon + 1).trim());
        return new Config.Listen(addr.isEmpty() ? null : addr, port);
    }

    static Config.Tunnel parseTunnel(String value) {
        // [saddr:]lport:rhost:rport
        String[] parts = value.split(":");
        if (parts.length == 3) {
            return new Config.Tunnel(null, Integer.parseInt(parts[0].trim()),
                    parts[1].trim(), Integer.parseInt(parts[2].trim()));
        } else if (parts.length == 4) {
            return new Config.Tunnel(parts[0].trim(), Integer.parseInt(parts[1].trim()),
                    parts[2].trim(), Integer.parseInt(parts[3].trim()));
        }
        throw new IllegalArgumentException("Tunnel needs [saddr:]lport:rhost:rport: " + value);
    }

    static boolean parseBool(String value) {
        String v = value.trim().toLowerCase();
        return v.equals("yes") || v.equals("true") || v.equals("1") || v.equals("on");
    }

    private static String stripComment(String line) {
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '#' || c == ';') {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static int firstWhitespace(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                return i;
            }
        }
        return -1;
    }
}
