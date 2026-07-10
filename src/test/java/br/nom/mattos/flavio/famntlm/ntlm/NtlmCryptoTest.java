package br.nom.mattos.flavio.famntlm.ntlm;

import static org.junit.Assert.assertEquals;

import br.nom.mattos.flavio.famntlm.util.Hex;
import org.junit.Test;

/**
 * Known-answer tests from MS-NLMP and the classic Eric Glass NTLM document.
 * These pin our hashes to the exact values CNTLM produces.
 */
public class NtlmCryptoTest {

    @Test
    public void ntHashOfPassword() {
        // MS-NLMP 4.2.4.1.1: NTOWFv1("Password") = a4f49c406510bdcab6824ee7c30fd852
        assertEquals("A4F49C406510BDCAB6824EE7C30FD852",
                Hex.encode(NtlmCrypto.ntHash("Password")));
        // And the classic lowercase "password" hash, for good measure.
        assertEquals("8846F7EAEE8FB117AD06BDD830B7586C",
                Hex.encode(NtlmCrypto.ntHash("password")));
    }

    @Test
    public void ntlmv2HashMsNlmpExample() {
        // MS-NLMP 4.2.4.1.1: user "User", domain "Domain", password "Password".
        byte[] nt = NtlmCrypto.ntHash("Password");
        assertEquals("0C868A403BFD7A93A3001EF22EF02E3F",
                Hex.encode(NtlmCrypto.ntlmv2Hash(nt, "User", "Domain")));
    }

    @Test
    public void lmHashOfSecret() {
        // Classic test vector: LM hash of "SecREt01".
        assertEquals("FF3750BCC2B22412C2265B23734E0DAC",
                Hex.encode(NtlmCrypto.lmHash("SecREt01")));
    }

    @Test
    public void ntHashOfSecret() {
        assertEquals("CD06CA7C7E10C99B1D33B7485A2ED808",
                Hex.encode(NtlmCrypto.ntHash("SecREt01")));
    }

    @Test
    public void md4EmptyString() {
        // RFC 1320 test suite: MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assertEquals("31D6CFE0D16AE931B73C59D7E0C089C0",
                Hex.encode(Md4.digest(new byte[0])));
    }

    @Test
    public void md4Abc() {
        // RFC 1320 test suite: MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        assertEquals("A448017AAF21D8525FC10AE87AA6729D",
                Hex.encode(Md4.digest("abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
    }
}
