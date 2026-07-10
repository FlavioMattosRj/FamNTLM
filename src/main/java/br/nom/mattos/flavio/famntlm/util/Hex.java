package br.nom.mattos.flavio.famntlm.util;

public final class Hex {

    private static final char[] DIGITS = "0123456789ABCDEF".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(DIGITS[(b >> 4) & 0xf]);
            sb.append(DIGITS[b & 0xf]);
        }
        return sb.toString();
    }

    public static byte[] decode(String hex) {
        String s = hex.trim();
        int len = s.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Odd-length hex string: " + hex);
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((digit(s.charAt(i)) << 4) | digit(s.charAt(i + 1)));
        }
        return out;
    }

    private static int digit(char c) {
        int d = Character.digit(c, 16);
        if (d < 0) {
            throw new IllegalArgumentException("Invalid hex char: " + c);
        }
        return d;
    }
}
