package br.nom.mattos.flavio.famntlm.ntlm;

import br.nom.mattos.flavio.famntlm.config.AuthType;
import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.util.Hex;

/**
 * Resolved authentication material. Hashes are taken from the config's
 * Pass* directives when present; otherwise they are derived from the plaintext
 * Password, exactly as CNTLM does at startup.
 */
public final class Credentials {

    public final String username;
    public final String domain;
    public final String workstation;
    public final AuthType auth;
    public final byte[] lmHash;      // 16 bytes or null
    public final byte[] ntHash;      // 16 bytes or null
    public final byte[] ntlmv2Hash;  // 16 bytes or null (NTOWFv2)

    private Credentials(String username, String domain, String workstation, AuthType auth,
                        byte[] lmHash, byte[] ntHash, byte[] ntlmv2Hash) {
        this.username = username;
        this.domain = domain;
        this.workstation = workstation;
        this.auth = auth;
        this.lmHash = lmHash;
        this.ntHash = ntHash;
        this.ntlmv2Hash = ntlmv2Hash;
    }

    public static Credentials from(Config cfg) {
        String user = cfg.username == null ? "" : cfg.username;
        String domain = cfg.domain == null ? "" : cfg.domain;
        String ws = cfg.workstation == null ? defaultWorkstation() : cfg.workstation;

        byte[] lm = cfg.passLM != null ? Hex.decode(cfg.passLM) : null;
        byte[] nt = cfg.passNT != null ? Hex.decode(cfg.passNT) : null;
        byte[] v2 = cfg.passNTLMv2 != null ? Hex.decode(cfg.passNTLMv2) : null;

        if (cfg.password != null && !cfg.password.isEmpty()) {
            if (lm == null) lm = NtlmCrypto.lmHash(cfg.password);
            if (nt == null) nt = NtlmCrypto.ntHash(cfg.password);
            if (v2 == null) v2 = NtlmCrypto.ntlmv2Hash(nt == null ? NtlmCrypto.ntHash(cfg.password) : nt,
                    user, domain);
        }
        return new Credentials(user, domain, ws, cfg.auth, lm, nt, v2);
    }

    public static String defaultWorkstation() {
        String host = System.getenv("COMPUTERNAME");
        if (host == null) {
            host = System.getenv("HOSTNAME");
        }
        if (host == null) {
            try {
                host = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception e) {
                host = "WORKSTATION";
            }
        }
        int dot = host.indexOf('.');
        return dot > 0 ? host.substring(0, dot) : host;
    }

    /** Validate that the material required for the chosen Auth type is present. */
    public String validate() {
        switch (auth) {
            case NTLMV2:
                if (ntlmv2Hash == null) return "Auth NTLMv2 requires PassNTLMv2 or Password";
                break;
            case NTLM2SR:
            case NT:
                if (ntHash == null) return "Auth " + auth.label() + " requires PassNT or Password";
                break;
            case NTLM:
                if (ntHash == null || lmHash == null) return "Auth NTLM requires PassNT+PassLM or Password";
                break;
            case LM:
                if (lmHash == null) return "Auth LM requires PassLM or Password";
                break;
            default:
                break;
        }
        return null;
    }
}
