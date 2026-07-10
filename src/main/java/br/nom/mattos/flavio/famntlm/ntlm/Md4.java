package br.nom.mattos.flavio.famntlm.ntlm;

/**
 * Pure-Java RFC 1320 MD4 implementation. The JDK does not ship an MD4
 * provider on every platform, and CNTLM relies on MD4 for the NT hash, so we
 * implement it here to keep behaviour identical across JVMs.
 */
public final class Md4 {

    private final int[] state = new int[]{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    private final byte[] buffer = new byte[64];
    private long byteCount;

    public static byte[] digest(byte[] input) {
        Md4 md4 = new Md4();
        md4.update(input, 0, input.length);
        return md4.digest();
    }

    public void update(byte[] input, int offset, int length) {
        int bufIndex = (int) (byteCount & 0x3f);
        byteCount += length;
        int partLen = 64 - bufIndex;
        int i = 0;
        if (length >= partLen) {
            System.arraycopy(input, offset, buffer, bufIndex, partLen);
            transform(buffer, 0);
            for (i = partLen; i + 63 < length; i += 64) {
                transform(input, offset + i);
            }
            bufIndex = 0;
        }
        System.arraycopy(input, offset + i, buffer, bufIndex, length - i);
    }

    public byte[] digest() {
        long bitCount = byteCount << 3;
        int index = (int) (byteCount & 0x3f);
        int padLen = (index < 56) ? (56 - index) : (120 - index);
        byte[] padding = new byte[padLen + 8];
        padding[0] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            padding[padLen + i] = (byte) (bitCount >>> (8 * i));
        }
        update(padding, 0, padding.length);

        byte[] out = new byte[16];
        for (int i = 0; i < 4; i++) {
            out[i * 4] = (byte) state[i];
            out[i * 4 + 1] = (byte) (state[i] >>> 8);
            out[i * 4 + 2] = (byte) (state[i] >>> 16);
            out[i * 4 + 3] = (byte) (state[i] >>> 24);
        }
        return out;
    }

    private void transform(byte[] block, int offset) {
        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            x[i] = (block[offset + i * 4] & 0xff)
                    | ((block[offset + i * 4 + 1] & 0xff) << 8)
                    | ((block[offset + i * 4 + 2] & 0xff) << 16)
                    | ((block[offset + i * 4 + 3] & 0xff) << 24);
        }

        int a = state[0], b = state[1], c = state[2], d = state[3];

        a = ff(a, b, c, d, x[0], 3);
        d = ff(d, a, b, c, x[1], 7);
        c = ff(c, d, a, b, x[2], 11);
        b = ff(b, c, d, a, x[3], 19);
        a = ff(a, b, c, d, x[4], 3);
        d = ff(d, a, b, c, x[5], 7);
        c = ff(c, d, a, b, x[6], 11);
        b = ff(b, c, d, a, x[7], 19);
        a = ff(a, b, c, d, x[8], 3);
        d = ff(d, a, b, c, x[9], 7);
        c = ff(c, d, a, b, x[10], 11);
        b = ff(b, c, d, a, x[11], 19);
        a = ff(a, b, c, d, x[12], 3);
        d = ff(d, a, b, c, x[13], 7);
        c = ff(c, d, a, b, x[14], 11);
        b = ff(b, c, d, a, x[15], 19);

        a = gg(a, b, c, d, x[0], 3);
        d = gg(d, a, b, c, x[4], 5);
        c = gg(c, d, a, b, x[8], 9);
        b = gg(b, c, d, a, x[12], 13);
        a = gg(a, b, c, d, x[1], 3);
        d = gg(d, a, b, c, x[5], 5);
        c = gg(c, d, a, b, x[9], 9);
        b = gg(b, c, d, a, x[13], 13);
        a = gg(a, b, c, d, x[2], 3);
        d = gg(d, a, b, c, x[6], 5);
        c = gg(c, d, a, b, x[10], 9);
        b = gg(b, c, d, a, x[14], 13);
        a = gg(a, b, c, d, x[3], 3);
        d = gg(d, a, b, c, x[7], 5);
        c = gg(c, d, a, b, x[11], 9);
        b = gg(b, c, d, a, x[15], 13);

        a = hh(a, b, c, d, x[0], 3);
        d = hh(d, a, b, c, x[8], 9);
        c = hh(c, d, a, b, x[4], 11);
        b = hh(b, c, d, a, x[12], 15);
        a = hh(a, b, c, d, x[2], 3);
        d = hh(d, a, b, c, x[10], 9);
        c = hh(c, d, a, b, x[6], 11);
        b = hh(b, c, d, a, x[14], 15);
        a = hh(a, b, c, d, x[1], 3);
        d = hh(d, a, b, c, x[9], 9);
        c = hh(c, d, a, b, x[5], 11);
        b = hh(b, c, d, a, x[13], 15);
        a = hh(a, b, c, d, x[3], 3);
        d = hh(d, a, b, c, x[11], 9);
        c = hh(c, d, a, b, x[7], 11);
        b = hh(b, c, d, a, x[15], 15);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    private static int ff(int a, int b, int c, int d, int x, int s) {
        a += ((b & c) | (~b & d)) + x;
        return rotl(a, s);
    }

    private static int gg(int a, int b, int c, int d, int x, int s) {
        a += ((b & c) | (b & d) | (c & d)) + x + 0x5a827999;
        return rotl(a, s);
    }

    private static int hh(int a, int b, int c, int d, int x, int s) {
        a += (b ^ c ^ d) + x + 0x6ed9eba1;
        return rotl(a, s);
    }

    private static int rotl(int value, int shift) {
        return (value << shift) | (value >>> (32 - shift));
    }
}
