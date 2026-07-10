package br.nom.mattos.flavio.famntlm.ntlm;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Low-level NTLM cryptographic primitives: LM/NT/NTLMv2 password hashes and the
 * building blocks used to compute Type-3 responses. Hash formats and hex
 * encoding match CNTLM so its generated PassLM/PassNT/PassNTLMv2 values are
 * fully interchangeable.
 */
public final class NtlmCrypto {

    private static final byte[] LM_MAGIC = {'K', 'G', 'S', '!', '@', '#', '$', '%'};
    private static final SecureRandom RANDOM = new SecureRandom();

    private NtlmCrypto() {
    }

    /** LM hash (16 bytes) of the plaintext password. */
    public static byte[] lmHash(String password) {
        try {
            byte[] oem = password.toUpperCase().getBytes("US-ASCII");
            byte[] key = new byte[14];
            System.arraycopy(oem, 0, key, 0, Math.min(oem.length, 14));
            byte[] out = new byte[16];
            System.arraycopy(desEncrypt(sevenToEight(key, 0), LM_MAGIC), 0, out, 0, 8);
            System.arraycopy(desEncrypt(sevenToEight(key, 7), LM_MAGIC), 0, out, 8, 8);
            return out;
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            throw new IllegalStateException("LM hash failure", e);
        }
    }

    /** NT hash (16 bytes) = MD4 of the UTF-16LE password. */
    public static byte[] ntHash(String password) {
        return Md4.digest(utf16le(password));
    }

    /**
     * NTLMv2 hash (NTOWFv2, 16 bytes) = HMAC-MD5(NT hash, UPPER(user)+domain)
     * with user and domain encoded as UTF-16LE. This is what CNTLM stores as
     * PassNTLMv2.
     */
    public static byte[] ntlmv2Hash(byte[] ntHash, String user, String domain) {
        byte[] identity = utf16le(user.toUpperCase() + domain);
        return hmacMd5(ntHash, identity);
    }

    public static byte[] ntlmv2HashFromPassword(String password, String user, String domain) {
        return ntlmv2Hash(ntHash(password), user, domain);
    }

    public static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-MD5 failure", e);
        }
    }

    /** DESL: encrypt the 8-byte data three times with a 21-byte (padded) key. */
    public static byte[] desl(byte[] key16, byte[] data8) {
        try {
            byte[] key21 = new byte[21];
            System.arraycopy(key16, 0, key21, 0, 16);
            byte[] out = new byte[24];
            System.arraycopy(desEncrypt(sevenToEight(key21, 0), data8), 0, out, 0, 8);
            System.arraycopy(desEncrypt(sevenToEight(key21, 7), data8), 0, out, 8, 8);
            System.arraycopy(desEncrypt(sevenToEight(key21, 14), data8), 0, out, 16, 8);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DESL failure", e);
        }
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static byte[] utf16le(String s) {
        try {
            return s.getBytes("UTF-16LE");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] desEncrypt(byte[] key8, byte[] data8) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key8, "DES"));
        return cipher.doFinal(data8);
    }

    /** Expand 7 key bytes (starting at offset) into an 8-byte DES key with parity. */
    private static byte[] sevenToEight(byte[] src, int offset) {
        byte[] k = new byte[8];
        k[0] = (byte) (src[offset] & 0xfe);
        k[1] = (byte) ((src[offset] << 7) | ((src[offset + 1] & 0xff) >> 1));
        k[2] = (byte) ((src[offset + 1] << 6) | ((src[offset + 2] & 0xff) >> 2));
        k[3] = (byte) ((src[offset + 2] << 5) | ((src[offset + 3] & 0xff) >> 3));
        k[4] = (byte) ((src[offset + 3] << 4) | ((src[offset + 4] & 0xff) >> 4));
        k[5] = (byte) ((src[offset + 4] << 3) | ((src[offset + 5] & 0xff) >> 5));
        k[6] = (byte) ((src[offset + 5] << 2) | ((src[offset + 6] & 0xff) >> 6));
        k[7] = (byte) (src[offset + 6] << 1);
        for (int i = 0; i < 8; i++) {
            k[i] = withOddParity(k[i]);
        }
        return k;
    }

    private static byte withOddParity(byte b) {
        int v = b & 0xfe;
        int ones = Integer.bitCount(v);
        return (byte) ((ones & 1) == 0 ? (v | 1) : v);
    }
}
