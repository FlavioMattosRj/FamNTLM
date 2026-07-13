package br.nom.mattos.flavio.famntlm;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class MVPTest {

    @Test
    public void classicNtlmResponseMatchesKnownVector() {
        assertTrue(MVP.cryptographicSelfTest());
    }

    @Test
    public void errorsDoNotEchoSensitiveArguments() throws Exception {
        String marker = "DO_NOT_DISCLOSE_LOCAL_IDENTITY";
        PrintStream original = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(captured, true, "UTF-8"));
            MVP.run(new String[]{"-c", "C:\\" + marker + "\\cntlm.ini",
                    "https://example.com/" + marker});
        } finally {
            System.setOut(original);
        }
        String output = new String(captured.toByteArray(), StandardCharsets.UTF_8);
        assertFalse(output.contains(marker));
    }
}
