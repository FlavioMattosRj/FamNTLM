package br.nom.mattos.flavio.famntlm.ntlm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import br.nom.mattos.flavio.famntlm.config.AuthType;
import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.util.Hex;
import org.junit.Test;

/**
 * Robustness of Type-2 (Challenge) parsing against malformed input from a hostile
 * or broken parent proxy: bad offsets must be ignored, never throwing an unchecked
 * exception that would escape the request path and kill a worker.
 */
public class NtlmMessagesTest {

    @Test
    public void type1CarriesCntlmDomainAndWorkstation() {
        Config cfg = new Config();
        cfg.username = "User";
        cfg.domain = "Domain";
        cfg.workstation = "Computer";
        cfg.auth = AuthType.NTLM;
        cfg.passLM = "FF3750BCC2B22412C2265B23734E0DAC";
        cfg.passNT = "CD06CA7C7E10C99B1D33B7485A2ED808";

        byte[] type1 = NtlmMessages.type1(Credentials.from(cfg), null);
        int flags = readInt(type1, 12);
        int domainLen = readShort(type1, 16);
        int domainOffset = readInt(type1, 20);
        int workstationLen = readShort(type1, 24);
        int workstationOffset = readInt(type1, 28);

        assertTrue((flags & 0x00001000) != 0);
        assertTrue((flags & 0x00002000) != 0);
        assertEquals("DOMAIN", new String(type1, domainOffset, domainLen,
                java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals("COMPUTER", new String(type1, workstationOffset, workstationLen,
                java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    public void classicNtlmResponsesMatchKnownAnswerVector() {
        Config cfg = new Config();
        cfg.username = "User";
        cfg.domain = "Domain";
        cfg.workstation = "COMPUTER";
        cfg.auth = AuthType.NTLM;
        cfg.passLM = "FF3750BCC2B22412C2265B23734E0DAC";
        cfg.passNT = "CD06CA7C7E10C99B1D33B7485A2ED808";
        Credentials credentials = Credentials.from(cfg);
        byte[] challengeBytes = Hex.decode("0123456789ABCDEF");
        NtlmMessages.Challenge challenge =
                new NtlmMessages.Challenge(0x00000201, challengeBytes, new byte[0]);

        byte[] type3 = NtlmMessages.type3(credentials, challenge, null);
        int lmLen = readShort(type3, 12);
        int lmOffset = readInt(type3, 16);
        int ntLen = readShort(type3, 20);
        int ntOffset = readInt(type3, 24);

        assertEquals(24, lmLen);
        assertEquals(24, ntLen);
        assertEquals("C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56",
                Hex.encode(java.util.Arrays.copyOfRange(type3, lmOffset, lmOffset + lmLen)));
        assertEquals("25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6",
                Hex.encode(java.util.Arrays.copyOfRange(type3, ntOffset, ntOffset + ntLen)));
    }

    private static byte[] baseType2() {
        byte[] msg = new byte[48];
        byte[] sig = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
        System.arraycopy(sig, 0, msg, 0, 8);
        msg[8] = 2; // message type = 2 (little-endian int)
        return msg;
    }

    private static int readShort(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
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
    public void type3FlagsMatchCntlmAndEchoChallenge() {
        int challenge = 0xe2888237;
        assertEquals(challenge,
                NtlmMessages.authenticateFlags(AuthType.NTLMV2, challenge, null));
        assertEquals(challenge,
                NtlmMessages.authenticateFlags(AuthType.NTLM, challenge, null));
    }

    @Test
    public void type3ClassicNtlmPreservesNegotiatedNtlm2FlagLikeCntlm() {
        int challenge = 0x00080201;
        assertEquals(challenge,
                NtlmMessages.authenticateFlags(AuthType.NTLM, challenge, null));
    }

    @Test
    public void type3FlagsDoNotInventCharsetFlags() {
        int challenge = 0x00000200;
        assertEquals(challenge,
                NtlmMessages.authenticateFlags(AuthType.NTLM, challenge, null));
    }

    @Test
    public void type3FlagsOverrideDoesNotReplaceNegotiatedChallenge() {
        assertEquals(0xe2888237,
                NtlmMessages.authenticateFlags(AuthType.NTLMV2, 0xe2888237, 0x00088207));
    }
}
