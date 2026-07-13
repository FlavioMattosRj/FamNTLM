package br.nom.mattos.flavio.famntlm.ntlm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

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
}
