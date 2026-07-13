package br.nom.mattos.flavio.famntlm.ntlm;

import br.nom.mattos.flavio.famntlm.config.AuthType;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Encodes NTLM Type-1 (Negotiate) and Type-3 (Authenticate) messages and parses
 * Type-2 (Challenge) messages, supporting both legacy (LM/NTLM/NT/NTLM2SR) and
 * NTLMv2 response computation.
 */
public final class NtlmMessages {

    private static final byte[] SIGNATURE = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

    private NtlmMessages() {
    }

    /** Parsed Type-2 challenge. */
    public static final class Challenge {
        public final int flags;
        public final byte[] serverChallenge; // 8 bytes
        public final byte[] targetInfo;      // may be empty

        Challenge(int flags, byte[] serverChallenge, byte[] targetInfo) {
            this.flags = flags;
            this.serverChallenge = serverChallenge;
            this.targetInfo = targetInfo;
        }
    }

    public static byte[] type1(AuthType auth, Integer flagOverride) {
        int flags = flagOverride != null ? flagOverride : defaultType1Flags(auth);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(SIGNATURE, 0, SIGNATURE.length);
        writeInt(out, 1);          // message type
        writeInt(out, flags);
        // Empty domain and workstation security buffers (offset points past header).
        writeShort(out, 0);
        writeShort(out, 0);
        writeInt(out, 32);
        writeShort(out, 0);
        writeShort(out, 0);
        writeInt(out, 32);
        return out.toByteArray();
    }

    public static Challenge parseType2(byte[] msg) {
        if (msg.length < 32 || !startsWith(msg, SIGNATURE) || readInt(msg, 8) != 2) {
            throw new IllegalArgumentException("Not a valid NTLM Type-2 message");
        }
        int flags = readInt(msg, 20);
        byte[] challenge = Arrays.copyOfRange(msg, 24, 32);
        byte[] targetInfo = new byte[0];
        if (msg.length >= 48) {
            int tiLen = readShort(msg, 40);
            int tiOffset = readInt(msg, 44);
            // Validate without overflow (tiOffset is a signed int and may be
            // negative or huge in a malformed challenge) before copyOfRange.
            if (tiLen > 0 && tiOffset >= 0 && tiOffset <= msg.length
                    && tiLen <= msg.length - tiOffset) {
                targetInfo = Arrays.copyOfRange(msg, tiOffset, tiOffset + tiLen);
            }
        }
        return new Challenge(flags, challenge, targetInfo);
    }

    public static byte[] type3(Credentials cred, Challenge challenge, Integer flagOverride) {
        byte[] lmResp;
        byte[] ntResp;
        switch (cred.auth) {
            case NTLMV2: {
                byte[] clientChallenge = NtlmCrypto.randomBytes(8);
                byte[] blob = ntlmv2Blob(challenge.targetInfo, clientChallenge);
                byte[] proofInput = concat(challenge.serverChallenge, blob);
                byte[] proof = NtlmCrypto.hmacMd5(cred.ntlmv2Hash, proofInput);
                ntResp = concat(proof, blob);
                byte[] lmProof = NtlmCrypto.hmacMd5(cred.ntlmv2Hash,
                        concat(challenge.serverChallenge, clientChallenge));
                lmResp = concat(lmProof, clientChallenge);
                break;
            }
            case NTLM2SR: {
                byte[] clientChallenge = NtlmCrypto.randomBytes(8);
                lmResp = new byte[24];
                System.arraycopy(clientChallenge, 0, lmResp, 0, 8);
                byte[] sessionHash = md5(concat(challenge.serverChallenge, clientChallenge));
                ntResp = NtlmCrypto.desl(cred.ntHash, Arrays.copyOfRange(sessionHash, 0, 8));
                break;
            }
            case NT: {
                ntResp = NtlmCrypto.desl(cred.ntHash, challenge.serverChallenge);
                lmResp = ntResp;
                break;
            }
            case NTLM: {
                lmResp = NtlmCrypto.desl(cred.lmHash, challenge.serverChallenge);
                ntResp = NtlmCrypto.desl(cred.ntHash, challenge.serverChallenge);
                break;
            }
            case LM: {
                lmResp = NtlmCrypto.desl(cred.lmHash, challenge.serverChallenge);
                ntResp = new byte[0];
                break;
            }
            default:
                throw new IllegalStateException("Unsupported auth: " + cred.auth);
        }

        boolean unicode = (challenge.flags & NtlmFlags.NEGOTIATE_UNICODE) != 0;
        byte[] domain = encode(cred.domain, unicode);
        byte[] user = encode(cred.username, unicode);
        byte[] workstation = encode(cred.workstation, unicode);

        int flags = flagOverride != null ? flagOverride : (challenge.flags);

        // Header is 64 bytes: six security buffers + flags.
        int offset = 64;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(SIGNATURE, 0, SIGNATURE.length);
        writeInt(out, 3);
        offset = writeSecurityBuffer(out, lmResp.length, offset);
        offset = writeSecurityBuffer(out, ntResp.length, offset);
        offset = writeSecurityBuffer(out, domain.length, offset);
        offset = writeSecurityBuffer(out, user.length, offset);
        offset = writeSecurityBuffer(out, workstation.length, offset);
        writeSecurityBuffer(out, 0, offset); // session key (empty)
        writeInt(out, flags);
        // Payload in the same order as the security buffers were declared.
        out.write(lmResp, 0, lmResp.length);
        out.write(ntResp, 0, ntResp.length);
        out.write(domain, 0, domain.length);
        out.write(user, 0, user.length);
        out.write(workstation, 0, workstation.length);
        return out.toByteArray();
    }

    private static byte[] ntlmv2Blob(byte[] targetInfo, byte[] clientChallenge) {
        ByteArrayOutputStream blob = new ByteArrayOutputStream();
        blob.write(0x01);
        blob.write(0x01);
        writeShort(blob, 0);
        writeInt(blob, 0);
        long filetime = (System.currentTimeMillis() + 11644473600000L) * 10000L;
        for (int i = 0; i < 8; i++) {
            blob.write((int) (filetime >>> (8 * i)) & 0xff);
        }
        blob.write(clientChallenge, 0, clientChallenge.length);
        writeInt(blob, 0);
        blob.write(targetInfo, 0, targetInfo.length);
        writeInt(blob, 0);
        return blob.toByteArray();
    }

    private static int defaultType1Flags(AuthType auth) {
        int flags = NtlmFlags.NEGOTIATE_UNICODE | NtlmFlags.NEGOTIATE_OEM
                | NtlmFlags.REQUEST_TARGET | NtlmFlags.NEGOTIATE_NTLM
                | NtlmFlags.NEGOTIATE_ALWAYS_SIGN;
        if (auth == AuthType.NTLMV2 || auth == AuthType.NTLM2SR) {
            flags |= NtlmFlags.NEGOTIATE_NTLM2;
        }
        return flags;
    }

    private static int writeSecurityBuffer(ByteArrayOutputStream out, int length, int offset) {
        writeShort(out, length);
        writeShort(out, length);
        writeInt(out, offset);
        return offset + length;
    }

    private static byte[] encode(String s, boolean unicode) {
        if (s == null) {
            s = "";
        }
        if (unicode) {
            return NtlmCrypto.utf16le(s);
        }
        try {
            return s.getBytes("US-ASCII");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] md5(byte[] data) {
        try {
            return MessageDigest.getInstance("MD5").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static void writeInt(ByteArrayOutputStream out, int v) {
        out.write(v & 0xff);
        out.write((v >>> 8) & 0xff);
        out.write((v >>> 16) & 0xff);
        out.write((v >>> 24) & 0xff);
    }

    private static void writeShort(ByteArrayOutputStream out, int v) {
        out.write(v & 0xff);
        out.write((v >>> 8) & 0xff);
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static int readShort(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }
}
