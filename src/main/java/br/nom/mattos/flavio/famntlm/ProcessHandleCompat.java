package br.nom.mattos.flavio.famntlm;

import java.lang.management.ManagementFactory;

/** Java 8-compatible process id lookup (no java.lang.ProcessHandle). */
final class ProcessHandleCompat {

    private ProcessHandleCompat() {
    }

    static long currentPid() {
        String name = ManagementFactory.getRuntimeMXBean().getName(); // "pid@host"
        int at = name.indexOf('@');
        try {
            return Long.parseLong(at > 0 ? name.substring(0, at) : name);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
