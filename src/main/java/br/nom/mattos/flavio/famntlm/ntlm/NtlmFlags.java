package br.nom.mattos.flavio.famntlm.ntlm;

/** NTLMSSP negotiate flag bits (subset used by CNTLM-style proxy auth). */
public final class NtlmFlags {

    public static final int NEGOTIATE_UNICODE = 0x00000001;
    public static final int NEGOTIATE_OEM = 0x00000002;
    public static final int REQUEST_TARGET = 0x00000004;
    public static final int NEGOTIATE_NTLM = 0x00000200;
    public static final int NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000;
    public static final int NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000;
    public static final int NEGOTIATE_ALWAYS_SIGN = 0x00008000;
    public static final int NEGOTIATE_NTLM2 = 0x00080000; // extended session security
    public static final int NEGOTIATE_TARGET_INFO = 0x00800000;
    public static final int NEGOTIATE_128 = 0x20000000;
    public static final int NEGOTIATE_56 = 0x80000000;

    private NtlmFlags() {
    }
}
