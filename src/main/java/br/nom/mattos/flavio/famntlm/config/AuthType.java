package br.nom.mattos.flavio.famntlm.config;

/** NTLM authentication dialects, strongest to weakest, matching CNTLM's -a values. */
public enum AuthType {
    NTLMV2("NTLMv2"),
    NTLM2SR("NTLM2SR"),
    NT("NT"),
    NTLM("NTLM"),
    LM("LM");

    private final String label;

    AuthType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public static AuthType parse(String value) {
        for (AuthType t : values()) {
            if (t.label.equalsIgnoreCase(value)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unknown Auth type: " + value);
    }
}
