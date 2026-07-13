package br.nom.mattos.flavio.famntlm.ntlm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Robustness of Type-2 (Challenge) parsing against malformed input from a hostile
 * or broken parent proxy: bad offsets must be ignored, never throwing an unchecked
 * exception that would escape the request path and kill a worker.
 */
public class NtlmMessagesTest {

    private static byte[] baseType2() {
        byte[] msg = new byte[48];
        byte[] sig = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
        System.arraycopy(sig, 0, msg, 0, 8);
        msg[8] = 2; // message type = 2 (little-endian int)
        return msg;
    }

    @Test
    public void negativeTargetInfoOffsetIsIgnored() {
        byte[] msg = baseType2();
        msg[40] = 16; // tiLen = 16
        msg[44] = (byte) 0xFF; // tiOffset = 0xFFFFFFFF = -1
        msg[45] = (byte) 0xFF;
        msg[46] = (byte) 0xFF;
        msg[47] = (byte) 0xFF;
        NtlmMessages.Challenge c = NtlmMessages.parseType2(msg); // must not throw
        assertEquals(0, c.targetInfo.length);
        assertEquals(8, c.serverChallenge.length);
    }

    @Test
    public void hugeTargetInfoOffsetDoesNotOverflow() {
        byte[] msg = baseType2();
        msg[40] = 16; // tiLen = 16
        msg[44] = (byte) 0xFF; // tiOffset = 0x7FFFFFFF (near Integer.MAX_VALUE)
        msg[45] = (byte) 0xFF;
        msg[46] = (byte) 0xFF;
        msg[47] = (byte) 0x7F;
        NtlmMessages.Challenge c = NtlmMessages.parseType2(msg); // must not throw
        assertEquals(0, c.targetInfo.length);
    }

    @Test
    public void invalidSignatureThrowsIllegalArgument() {
        byte[] msg = new byte[48]; // zeroed: no NTLMSSP signature
        assertThrows(IllegalArgumentException.class, () -> NtlmMessages.parseType2(msg));
    }

    @Test
    public void type3FlagsStripUnsupportedButKeepNegotiated() {
        int UNICODE = 0x00000001, OEM = 0x00000002, NTLM = 0x00000200, ALWAYS_SIGN = 0x00008000;
        int NTLM2 = 0x00080000, TARGET_INFO = 0x00800000, N128 = 0x20000000;
        int SIGN = 0x00000010, SEAL = 0x00000020, VERSION = 0x02000000, KEY_EXCHANGE = 0x40000000;
        int challenge = UNICODE | NTLM | ALWAYS_SIGN | NTLM2 | TARGET_INFO | N128
                | SIGN | SEAL | VERSION | KEY_EXCHANGE;

        int f = NtlmMessages.authenticateFlags(challenge, null);

        // Negotiated flags we honour are kept.
        assertTrue((f & UNICODE) != 0);
        assertTrue((f & NTLM) != 0);
        assertTrue((f & ALWAYS_SIGN) != 0);
        assertTrue((f & NTLM2) != 0);
        assertTrue((f & TARGET_INFO) != 0);
        assertTrue((f & N128) != 0);
        // Flags we do not implement are stripped (would make strict proxies reject).
        assertEquals(0, f & SIGN);
        assertEquals(0, f & SEAL);
        assertEquals(0, f & VERSION);
        assertEquals(0, f & KEY_EXCHANGE);
        // Charset is consistent with unicode encoding.
        assertEquals(0, f & OEM);
    }

    @Test
    public void type3FlagsUseOemWhenChallengeHasNoUnicode() {
        int OEM = 0x00000002, NTLM = 0x00000200;
        int f = NtlmMessages.authenticateFlags(OEM | NTLM, null);
        assertTrue((f & OEM) != 0);
        assertEquals(0, f & 0x00000001); // UNICODE not set
    }

    @Test
    public void type3FlagsOverrideWins() {
        assertEquals(0x00088207, NtlmMessages.authenticateFlags(0xFFFFFFFF, 0x00088207));
    }
}
