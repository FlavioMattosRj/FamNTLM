package br.nom.mattos.flavio.famntlm.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A parsed HTTP message head (request line or status line + headers). Reads
 * raw bytes up to and including the terminating CRLFCRLF without consuming any
 * body, so the caller stays in control of the byte stream.
 */
public final class HttpHead {

    public final String firstLine;
    public final List<String> headerLines;
    public final byte[] raw;

    private HttpHead(String firstLine, List<String> headerLines, byte[] raw) {
        this.firstLine = firstLine;
        this.headerLines = headerLines;
        this.raw = raw;
    }

    public static HttpHead read(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        int state = 0; // counts progress through \r \n \r \n
        int b;
        while ((b = in.read()) != -1) {
            buf.write(b);
            if (b == '\r' && (state == 0 || state == 2)) {
                state++;
            } else if (b == '\n' && (state == 1 || state == 3)) {
                state++;
                if (state == 4) {
                    break;
                }
            } else {
                state = 0;
            }
        }
        if (buf.size() == 0) {
            throw new IOException("Connection closed before request");
        }
        byte[] raw = buf.toByteArray();
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        String[] lines = text.split("\r\n", -1);
        String first = lines.length > 0 ? lines[0] : "";
        List<String> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty()) {
                break;
            }
            headers.add(lines[i]);
        }
        return new HttpHead(first, headers, raw);
    }

    public int statusCode() {
        // "HTTP/1.1 407 Proxy Authentication Required"
        String[] parts = firstLine.split(" ", 3);
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignore) {
            }
        }
        return -1;
    }

    public String header(String name) {
        String prefix = name.toLowerCase() + ":";
        for (String line : headerLines) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon + 1).toLowerCase().equals(prefix)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    public List<String> headers(String name) {
        String prefix = name.toLowerCase() + ":";
        List<String> out = new ArrayList<>();
        for (String line : headerLines) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon + 1).toLowerCase().equals(prefix)) {
                out.add(line.substring(colon + 1).trim());
            }
        }
        return out;
    }

    public long contentLength() {
        String cl = header("Content-Length");
        if (cl != null) {
            try {
                return Long.parseLong(cl.trim());
            } catch (NumberFormatException ignore) {
            }
        }
        return 0;
    }
}
