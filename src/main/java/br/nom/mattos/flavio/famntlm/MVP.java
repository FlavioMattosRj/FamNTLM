package br.nom.mattos.flavio.famntlm;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Independent, single-file NTLM proxy connectivity probe.
 *
 * <p>This class deliberately does not depend on the FamNTLM implementation.
 * Its output never includes configuration values, identities, file paths,
 * proxy addresses, challenges, hashes, authorization tokens, or stack traces.
 */
public final class MVP {
    private static final byte[] NTLM_SIGNATURE = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int CONNECT_TIMEOUT_MS = 10000;
    private static final int READ_TIMEOUT_MS = 20000;

    private MVP() {
    }

    public static void main(String[] args) {
        int exit = run(args);
        if (exit != 0) {
            System.exit(exit);
        }
    }

    static int run(String[] args) {
        try {
            Arguments parsed = Arguments.parse(args);
            Config config = Config.load(parsed.configFile);
            Target target = Target.parse(parsed.targetUrl);
            Credentials credentials = Credentials.from(config);
            out("CONFIG_OK", "configuration accepted; authentication material is structurally valid");

            Failure last = null;
            for (int i = 0; i < config.proxies.size(); i++) {
                out("PROXY_ATTEMPT", "trying a configured parent");
                try {
                    probe(config.proxies.get(i), target, credentials, config.flags);
                    out("SUCCESS", "authenticated tunnel, TLS handshake, and HTTP response verified");
                    return 0;
                } catch (Failure e) {
                    last = e;
                    out(e.code, e.safeMessage);
                }
            }
            if (last == null) {
                out("E_CONFIG_PROXY", "configuration contains no usable parent proxy");
            } else {
                out("FAILED", "all configured parents were exhausted; last_code=" + last.code);
            }
            return 1;
        } catch (Failure e) {
            out(e.code, e.safeMessage);
            return 2;
        } catch (RuntimeException e) {
            out("E_INTERNAL", "unexpected local failure; no sensitive diagnostic was emitted");
            return 3;
        }
    }

    private static void probe(Proxy proxy, Target target, Credentials credentials, Integer flagOverride)
            throws Failure {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(proxy.host, proxy.port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            out("TCP_OK", "parent connection established");

            InputStream in = socket.getInputStream();
            OutputStream wire = socket.getOutputStream();
            byte[] type1 = type1(credentials, flagOverride);
            sendConnect(wire, target, type1);
            out("NEGOTIATE_SENT", "type=1 flags=" + hex32(le32(type1, 12)));

            Head challengeHead = Head.read(in);
            if (challengeHead.status != 407) {
                throw new Failure("E_NEGOTIATE_STATUS",
                        "parent did not return an NTLM challenge; http_status=" + challengeHead.status);
            }
            String token = challengeHead.ntlmChallenge();
            if (token == null) {
                throw new Failure("E_NEGOTIATE_SCHEME",
                        "parent returned 407 without a usable NTLM challenge");
            }
            challengeHead.drain(in);
            if (challengeHead.closesConnection()) {
                throw new Failure("E_NEGOTIATE_CLOSE",
                        "parent closed the connection after the challenge; NTLM requires connection affinity");
            }

            Challenge challenge = parseType2(token);
            out("CHALLENGE_OK", "type=2 flags=" + hex32(challenge.flags));
            byte[] type3 = type3(credentials, challenge);
            out("AUTH_SENT", "type=3 flags=" + hex32(le32(type3, 60)));
            sendConnect(wire, target, type3);

            Head authenticated = Head.read(in);
            if (authenticated.status == 407) {
                throw new Failure("E_AUTH_REJECTED",
                        "parent rejected the NTLM authenticate message; http_status=407");
            }
            if (authenticated.status != 200) {
                throw new Failure("E_TUNNEL_STATUS",
                        "parent did not establish the tunnel; http_status=" + authenticated.status);
            }
            out("AUTH_OK", "parent accepted authentication and established the tunnel");

            verifyTlsAndHttp(socket, target);
            socket = null; // TLS wrapper owns and closes it.
        } catch (UnknownHostException e) {
            throw new Failure("E_TCP_DNS", "parent name resolution failed");
        } catch (ConnectException e) {
            throw new Failure("E_TCP_CONNECT", "parent connection was refused or unreachable");
        } catch (SocketTimeoutException e) {
            throw new Failure("E_TIMEOUT", "network operation timed out");
        } catch (SSLHandshakeException e) {
            throw new Failure("E_TLS_HANDSHAKE",
                    "TLS handshake failed; certificate trust or interception policy may be involved");
        } catch (Failure e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new Failure("E_CRYPTO", "required local cryptographic operation failed");
        } catch (IOException e) {
            throw new Failure("E_IO", "network stream ended or became invalid during the probe");
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignore) {
                    // Sanitized probe: cleanup failure is intentionally not reported.
                }
            }
        }
    }

    private static void verifyTlsAndHttp(Socket tunnel, Target target)
            throws IOException, GeneralSecurityException, Failure {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket tls = (SSLSocket) factory.createSocket(tunnel, target.host, target.port, true);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(parameters);
        tls.setSoTimeout(READ_TIMEOUT_MS);
        tls.startHandshake();
        out("TLS_OK", "TLS handshake and endpoint verification completed");

        OutputStream out = tls.getOutputStream();
        String request = "GET " + target.path + " HTTP/1.1\r\n"
                + "Host: " + target.host + "\r\n"
                + "User-Agent: FamNTLM-MVP/1\r\n"
                + "Accept: */*\r\n"
                + "Connection: close\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        Head response = Head.read(tls.getInputStream());
        if (response.status < 200 || response.status >= 400) {
            throw new Failure("E_HTTP_STATUS",
                    "target returned an unexpected response; http_status=" + response.status);
        }
        MVP.out("HTTP_OK", "target returned an accepted response; http_status=" + response.status);
        tls.close();
    }

    private static void sendConnect(OutputStream out, Target target, byte[] message) throws IOException {
        String authority = target.host + ":" + target.port;
        String request = "CONNECT " + authority + " HTTP/1.1\r\n"
                + "Host: " + authority + "\r\n"
                + "Proxy-Connection: Keep-Alive\r\n"
                + "Connection: Keep-Alive\r\n"
                + "Proxy-Authorization: NTLM " + Base64.getEncoder().encodeToString(message) + "\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    private static byte[] type1(Credentials c, Integer override) {
        byte[] domain = asciiUpper(c.domain);
        byte[] workstation = asciiUpper(c.workstation);
        int flags = override != null ? override : defaultType1Flags(c.auth);
        if (override == null) {
            if (domain.length > 0) flags |= 0x00001000;
            if (workstation.length > 0) flags |= 0x00002000;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, NTLM_SIGNATURE);
        int32(out, 1);
        int32(out, flags);
        sec(out, domain.length, 32 + workstation.length);
        sec(out, workstation.length, 32);
        write(out, workstation);
        write(out, domain);
        return out.toByteArray();
    }

    private static Challenge parseType2(String base64) throws Failure {
        final byte[] message;
        try {
            message = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new Failure("E_CHALLENGE_BASE64", "NTLM challenge was not valid Base64");
        }
        if (message.length < 32 || !startsWith(message, NTLM_SIGNATURE) || le32(message, 8) != 2) {
            throw new Failure("E_CHALLENGE_FORMAT", "NTLM challenge had an invalid header");
        }
        int flags = le32(message, 20);
        byte[] serverChallenge = Arrays.copyOfRange(message, 24, 32);
        byte[] targetInfo = new byte[0];
        if (message.length >= 48) {
            int length = le16(message, 40);
            int offset = le32(message, 44);
            if (length > 0) {
                if (offset < 0 || offset > message.length || length > message.length - offset) {
                    throw new Failure("E_CHALLENGE_BOUNDS", "NTLM challenge contained invalid field bounds");
                }
                targetInfo = Arrays.copyOfRange(message, offset, offset + length);
            }
        }
        return new Challenge(flags, serverChallenge, targetInfo);
    }

    private static byte[] type3(Credentials c, Challenge challenge) throws GeneralSecurityException {
        byte[] lm;
        byte[] nt;
        if (c.auth == Auth.NTLMV2) {
            byte[] nonce = random(8);
            byte[] blob = v2Blob(challenge.targetInfo, nonce);
            nt = concat(hmac(c.passV2, concat(challenge.serverChallenge, blob)), blob);
            lm = concat(hmac(c.passV2, concat(challenge.serverChallenge, nonce)), nonce);
        } else if (c.auth == Auth.NTLM2SR) {
            byte[] nonce = random(8);
            lm = new byte[24];
            System.arraycopy(nonce, 0, lm, 0, 8);
            byte[] session = MessageDigest.getInstance("MD5")
                    .digest(concat(challenge.serverChallenge, nonce));
            nt = desl(c.passNT, Arrays.copyOf(session, 8));
        } else if (c.auth == Auth.NT) {
            lm = new byte[0];
            nt = desl(c.passNT, challenge.serverChallenge);
        } else if (c.auth == Auth.NTLM) {
            lm = desl(c.passLM, challenge.serverChallenge);
            nt = desl(c.passNT, challenge.serverChallenge);
        } else {
            lm = desl(c.passLM, challenge.serverChallenge);
            nt = new byte[0];
        }

        boolean unicode = c.auth != Auth.LM;
        byte[] domain = encode(upper(c.domain), unicode);
        byte[] user = encode(unicode ? c.user : upper(c.user), unicode);
        byte[] workstation = encode(upper(c.workstation), unicode);
        int domainOffset = 64;
        int userOffset = domainOffset + domain.length;
        int workstationOffset = userOffset + user.length;
        int lmOffset = workstationOffset + workstation.length;
        int ntOffset = lmOffset + lm.length;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, NTLM_SIGNATURE);
        int32(out, 3);
        sec(out, lm.length, lmOffset);
        sec(out, nt.length, ntOffset);
        sec(out, domain.length, domainOffset);
        sec(out, user.length, userOffset);
        sec(out, workstation.length, workstationOffset);
        sec(out, 0, ntOffset + nt.length);
        int32(out, challenge.flags);
        write(out, domain);
        write(out, user);
        write(out, workstation);
        write(out, lm);
        write(out, nt);
        return out.toByteArray();
    }

    private static byte[] v2Blob(byte[] targetInfo, byte[] nonce) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int32(out, 0x00000101);
        int32(out, 0);
        long filetime = (System.currentTimeMillis() + 11644473600000L) * 10000L;
        int64(out, filetime);
        write(out, nonce);
        int32(out, 0);
        write(out, targetInfo);
        int32(out, 0);
        return out.toByteArray();
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        return mac.doFinal(data);
    }

    private static byte[] desl(byte[] hash, byte[] challenge) throws GeneralSecurityException {
        byte[] key21 = new byte[21];
        System.arraycopy(hash, 0, key21, 0, 16);
        byte[] result = new byte[24];
        for (int i = 0; i < 3; i++) {
            byte[] key = desKey(key21, i * 7);
            Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
            des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            System.arraycopy(des.doFinal(challenge), 0, result, i * 8, 8);
        }
        return result;
    }

    private static byte[] desKey(byte[] source, int offset) {
        byte[] key = new byte[8];
        key[0] = (byte) (source[offset] & 0xfe);
        key[1] = (byte) ((source[offset] << 7) | ((source[offset + 1] & 0xff) >>> 1));
        key[2] = (byte) ((source[offset + 1] << 6) | ((source[offset + 2] & 0xff) >>> 2));
        key[3] = (byte) ((source[offset + 2] << 5) | ((source[offset + 3] & 0xff) >>> 3));
        key[4] = (byte) ((source[offset + 3] << 4) | ((source[offset + 4] & 0xff) >>> 4));
        key[5] = (byte) ((source[offset + 4] << 3) | ((source[offset + 5] & 0xff) >>> 5));
        key[6] = (byte) ((source[offset + 5] << 2) | ((source[offset + 6] & 0xff) >>> 6));
        key[7] = (byte) (source[offset + 6] << 1);
        for (int i = 0; i < key.length; i++) {
            int value = key[i] & 0xfe;
            key[i] = (byte) ((Integer.bitCount(value) & 1) == 0 ? value | 1 : value);
        }
        return key;
    }

    private static int defaultType1Flags(Auth auth) {
        switch (auth) {
            case NTLMV2: return 0xa208b205;
            case NTLM2SR: return 0xa208b207;
            case NT: return 0x0000b205;
            case NTLM: return 0x0000b207;
            case LM: return 0x0000b206;
            default: throw new IllegalStateException();
        }
    }

    static boolean cryptographicSelfTest() {
        try {
            Credentials c = new Credentials("User", "Domain", "COMPUTER", Auth.NTLM,
                    hex("FF3750BCC2B22412C2265B23734E0DAC"),
                    hex("CD06CA7C7E10C99B1D33B7485A2ED808"), null);
            Challenge challenge = new Challenge(0x00000201, hex("0123456789ABCDEF"), new byte[0]);
            byte[] message = type3(c, challenge);
            int lmLength = le16(message, 12), lmOffset = le32(message, 16);
            int ntLength = le16(message, 20), ntOffset = le32(message, 24);
            return "C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56".equals(
                    hex(Arrays.copyOfRange(message, lmOffset, lmOffset + lmLength)))
                    && "25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6".equals(
                    hex(Arrays.copyOfRange(message, ntOffset, ntOffset + ntLength)));
        } catch (Exception e) {
            return false;
        }
    }

    private enum Auth {
        NTLMV2, NTLM2SR, NT, NTLM, LM;

        static Auth parse(String value) throws Failure {
            String normalized = value == null ? "NTLMV2" : value.trim().toUpperCase(Locale.ROOT);
            try {
                return Auth.valueOf(normalized);
            } catch (IllegalArgumentException e) {
                throw new Failure("E_CONFIG_AUTH", "configuration selects an unsupported authentication mode");
            }
        }
    }

    private static final class Credentials {
        final String user;
        final String domain;
        final String workstation;
        final Auth auth;
        final byte[] passLM;
        final byte[] passNT;
        final byte[] passV2;

        Credentials(String user, String domain, String workstation, Auth auth,
                    byte[] passLM, byte[] passNT, byte[] passV2) {
            this.user = user;
            this.domain = domain;
            this.workstation = workstation;
            this.auth = auth;
            this.passLM = passLM;
            this.passNT = passNT;
            this.passV2 = passV2;
        }

        static Credentials from(Config c) throws Failure {
            Auth auth = Auth.parse(c.value("auth"));
            String user = required(c.value("username"), "E_CONFIG_USER",
                    "configuration is missing the account identifier");
            String domain = required(c.value("domain"), "E_CONFIG_DOMAIN",
                    "configuration is missing the account realm");
            String workstation = c.value("workstation");
            if (workstation == null || workstation.trim().isEmpty()) {
                workstation = defaultWorkstation();
            }
            byte[] lm = optionalHash(c.value("passlm"), "E_CONFIG_PASSLM");
            byte[] nt = optionalHash(c.value("passnt"), "E_CONFIG_PASSNT");
            byte[] v2 = optionalHash(c.value("passntlmv2"), "E_CONFIG_PASSV2");
            if (auth == Auth.NTLMV2 && v2 == null) {
                throw new Failure("E_CONFIG_PASSV2", "selected authentication mode requires PassNTLMv2");
            }
            if ((auth == Auth.NTLM2SR || auth == Auth.NT || auth == Auth.NTLM) && nt == null) {
                throw new Failure("E_CONFIG_PASSNT", "selected authentication mode requires PassNT");
            }
            if ((auth == Auth.NTLM || auth == Auth.LM) && lm == null) {
                throw new Failure("E_CONFIG_PASSLM", "selected authentication mode requires PassLM");
            }
            return new Credentials(user, domain, workstation, auth, lm, nt, v2);
        }
    }

    private static final class Config {
        final Map<String, String> values = new LinkedHashMap<>();
        final List<Proxy> proxies = new ArrayList<>();
        Integer flags;

        String value(String key) {
            return values.get(key);
        }

        static Config load(File file) throws Failure {
            if (file == null || !file.isFile()) {
                throw new Failure("E_CONFIG_FILE", "configuration file is unavailable");
            }
            Config config = new Config();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String clean = stripComment(line).trim();
                    if (clean.isEmpty()) continue;
                    int split = whitespace(clean);
                    if (split < 0) continue;
                    String key = clean.substring(0, split).toLowerCase(Locale.ROOT);
                    String value = clean.substring(split).trim();
                    if (key.equals("proxy")) {
                        config.proxies.add(Proxy.parse(value));
                    } else if (key.equals("flags")) {
                        try {
                            config.flags = (int) Long.decode(value).longValue();
                        } catch (RuntimeException e) {
                            throw new Failure("E_CONFIG_FLAGS", "configuration contains invalid NTLM flags");
                        }
                    } else if (key.equals("username") || key.equals("domain")
                            || key.equals("workstation") || key.equals("auth")
                            || key.equals("passlm") || key.equals("passnt")
                            || key.equals("passntlmv2")) {
                        config.values.put(key, value);
                    }
                }
            } catch (Failure e) {
                throw e;
            } catch (IOException e) {
                throw new Failure("E_CONFIG_READ", "configuration file could not be read");
            }
            if (config.proxies.isEmpty()) {
                throw new Failure("E_CONFIG_PROXY", "configuration contains no usable parent proxy");
            }
            return config;
        }
    }

    private static final class Proxy {
        final String host;
        final int port;

        Proxy(String host, int port) {
            this.host = host;
            this.port = port;
        }

        static Proxy parse(String value) throws Failure {
            int colon = value.lastIndexOf(':');
            if (colon <= 0 || colon == value.length() - 1) {
                throw new Failure("E_CONFIG_PROXY", "configuration contains an invalid parent proxy entry");
            }
            try {
                int port = Integer.parseInt(value.substring(colon + 1).trim());
                if (port < 1 || port > 65535) throw new NumberFormatException();
                return new Proxy(value.substring(0, colon).trim(), port);
            } catch (NumberFormatException e) {
                throw new Failure("E_CONFIG_PROXY", "configuration contains an invalid parent proxy port");
            }
        }
    }

    private static final class Target {
        final String host;
        final int port;
        final String path;

        Target(String host, int port, String path) {
            this.host = host;
            this.port = port;
            this.path = path;
        }

        static Target parse(String value) throws Failure {
            try {
                URI uri = URI.create(value);
                if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
                    throw new Failure("E_TARGET", "test target must be an absolute HTTPS URL");
                }
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                return new Target(uri.getHost(), uri.getPort() > 0 ? uri.getPort() : 443, path);
            } catch (Failure e) {
                throw e;
            } catch (RuntimeException e) {
                throw new Failure("E_TARGET", "test target is not a valid HTTPS URL");
            }
        }
    }

    private static final class Arguments {
        final File configFile;
        final String targetUrl;

        Arguments(File configFile, String targetUrl) {
            this.configFile = configFile;
            this.targetUrl = targetUrl;
        }

        static Arguments parse(String[] args) throws Failure {
            String config = null;
            String target = null;
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("-c") && i + 1 < args.length) {
                    config = args[++i];
                } else if (!args[i].startsWith("-")) {
                    target = args[i];
                } else {
                    throw new Failure("E_USAGE", "usage: mvp.jar -c <config> <https-url>");
                }
            }
            if (config == null || target == null) {
                throw new Failure("E_USAGE", "usage: mvp.jar -c <config> <https-url>");
            }
            return new Arguments(new File(config), target);
        }
    }

    private static final class Challenge {
        final int flags;
        final byte[] serverChallenge;
        final byte[] targetInfo;

        Challenge(int flags, byte[] serverChallenge, byte[] targetInfo) {
            this.flags = flags;
            this.serverChallenge = serverChallenge;
            this.targetInfo = targetInfo;
        }
    }

    private static final class Head {
        final int status;
        final Map<String, List<String>> headers;

        Head(int status, Map<String, List<String>> headers) {
            this.status = status;
            this.headers = headers;
        }

        static Head read(InputStream in) throws IOException, Failure {
            String first = line(in, 8192);
            String[] parts = first.split(" ", 3);
            if (parts.length < 2) throw new Failure("E_HTTP_FORMAT", "received a malformed HTTP response");
            final int status;
            try {
                status = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                throw new Failure("E_HTTP_FORMAT", "received a malformed HTTP status");
            }
            Map<String, List<String>> headers = new LinkedHashMap<>();
            int total = first.length();
            while (true) {
                String line = line(in, 8192);
                total += line.length();
                if (total > 65536) throw new Failure("E_HTTP_HEADERS", "HTTP response headers were too large");
                if (line.isEmpty()) break;
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(line.substring(colon + 1).trim());
            }
            return new Head(status, headers);
        }

        String first(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        String ntlmChallenge() {
            List<String> values = headers.get("proxy-authenticate");
            if (values == null) return null;
            for (String value : values) {
                String[] offers = value.split(",");
                for (String offer : offers) {
                    String trimmed = offer.trim();
                    if (trimmed.regionMatches(true, 0, "NTLM ", 0, 5)) {
                        String token = trimmed.substring(5).trim();
                        if (!token.isEmpty()) return token;
                    }
                }
            }
            return null;
        }

        boolean closesConnection() {
            String connection = first("connection");
            String proxyConnection = first("proxy-connection");
            return containsToken(connection, "close") || containsToken(proxyConnection, "close");
        }

        void drain(InputStream in) throws IOException, Failure {
            String transfer = first("transfer-encoding");
            if (containsToken(transfer, "chunked")) {
                while (true) {
                    String sizeLine = line(in, 128);
                    int semi = sizeLine.indexOf(';');
                    String number = (semi >= 0 ? sizeLine.substring(0, semi) : sizeLine).trim();
                    final int size;
                    try {
                        size = Integer.parseInt(number, 16);
                    } catch (NumberFormatException e) {
                        throw new Failure("E_HTTP_BODY", "challenge response had invalid chunk framing");
                    }
                    if (size == 0) {
                        while (!line(in, 8192).isEmpty()) { /* trailers */ }
                        return;
                    }
                    discard(in, size);
                    if (!line(in, 2).isEmpty()) {
                        throw new Failure("E_HTTP_BODY", "challenge response had invalid chunk termination");
                    }
                }
            }
            String length = first("content-length");
            if (length != null) {
                try {
                    long count = Long.parseLong(length.trim());
                    if (count < 0 || count > 16 * 1024 * 1024L) throw new NumberFormatException();
                    discard(in, count);
                } catch (NumberFormatException e) {
                    throw new Failure("E_HTTP_BODY", "challenge response had an invalid body length");
                }
            }
        }
    }

    private static final class Failure extends Exception {
        final String code;
        final String safeMessage;

        Failure(String code, String safeMessage) {
            super(code);
            this.code = code;
            this.safeMessage = safeMessage;
        }
    }

    private static String line(InputStream in, int maximum) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (out.size() <= maximum) {
            int value = in.read();
            if (value < 0) throw new EOFException();
            if (value == '\n') {
                byte[] bytes = out.toByteArray();
                int length = bytes.length;
                if (length > 0 && bytes[length - 1] == '\r') length--;
                return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
            }
            out.write(value);
        }
        throw new IOException("line too long");
    }

    private static void discard(InputStream in, long count) throws IOException {
        byte[] buffer = new byte[4096];
        while (count > 0) {
            int read = in.read(buffer, 0, (int) Math.min(buffer.length, count));
            if (read < 0) throw new EOFException();
            count -= read;
        }
    }

    private static byte[] optionalHash(String value, String code) throws Failure {
        if (value == null || value.trim().isEmpty()) return null;
        try {
            byte[] decoded = hex(value.trim());
            if (decoded.length != 16) throw new IllegalArgumentException();
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new Failure(code, "configured authentication hash is not exactly 32 hexadecimal characters");
        }
    }

    private static String required(String value, String code, String message) throws Failure {
        if (value == null || value.trim().isEmpty()) throw new Failure(code, message);
        return value.trim();
    }

    private static String defaultWorkstation() {
        String value = System.getenv("COMPUTERNAME");
        if (value == null || value.isEmpty()) value = System.getenv("HOSTNAME");
        return value == null || value.isEmpty() ? "WORKSTATION" : value.split("\\.", 2)[0];
    }

    private static String stripComment(String line) {
        int hash = line.indexOf('#');
        int semi = line.indexOf(';');
        int cut = hash < 0 ? semi : semi < 0 ? hash : Math.min(hash, semi);
        return cut < 0 ? line : line.substring(0, cut);
    }

    private static int whitespace(String value) {
        for (int i = 0; i < value.length(); i++) if (Character.isWhitespace(value.charAt(i))) return i;
        return -1;
    }

    private static boolean containsToken(String value, String token) {
        if (value == null) return false;
        for (String part : value.split(",")) if (part.trim().equalsIgnoreCase(token)) return true;
        return false;
    }

    private static byte[] random(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    private static byte[] encode(String value, boolean unicode) {
        return value.getBytes(unicode ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII);
    }

    private static byte[] asciiUpper(String value) {
        return upper(value).getBytes(StandardCharsets.US_ASCII);
    }

    private static String upper(String value) {
        return value == null ? "" : value.toUpperCase(Locale.ROOT);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        if (value.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (value[i] != prefix[i]) return false;
        return true;
    }

    private static void sec(ByteArrayOutputStream out, int length, int offset) {
        int16(out, length);
        int16(out, length);
        int32(out, offset);
    }

    private static void int16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >>> 8) & 0xff);
    }

    private static void int32(ByteArrayOutputStream out, int value) {
        int16(out, value);
        int16(out, value >>> 16);
    }

    private static void int64(ByteArrayOutputStream out, long value) {
        int32(out, (int) value);
        int32(out, (int) (value >>> 32));
    }

    private static int le16(byte[] value, int offset) {
        return (value[offset] & 0xff) | ((value[offset + 1] & 0xff) << 8);
    }

    private static int le32(byte[] value, int offset) {
        return le16(value, offset) | (le16(value, offset + 2) << 16);
    }

    private static void write(ByteArrayOutputStream out, byte[] value) {
        out.write(value, 0, value.length);
    }

    private static byte[] hex(String value) {
        if ((value.length() & 1) != 0) throw new IllegalArgumentException();
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException();
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte b : value) result.append(String.format(Locale.ROOT, "%02X", b & 0xff));
        return result.toString();
    }

    private static String hex32(int value) {
        return String.format(Locale.ROOT, "0x%08X", value);
    }

    private static void out(String code, String message) {
        System.out.println("MVP " + code + " - " + message);
    }
}
