package br.nom.mattos.flavio.famntlm.proxy;

import br.nom.mattos.flavio.famntlm.config.AccessControl;
import br.nom.mattos.flavio.famntlm.config.Config;
import br.nom.mattos.flavio.famntlm.log.AsyncRequestLog;
import br.nom.mattos.flavio.famntlm.ntlm.Credentials;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Accepts client connections on every configured Listen endpoint and dispatches
 * each to a worker thread. The pool is bounded and uses a caller-runs fallback,
 * so under a heavy connection burst the accept loop naturally throttles instead
 * of exhausting memory. Shutdown is graceful: listeners stop accepting, then
 * in-flight work is given time to finish.
 */
public final class ProxyServer {

    private final Config config;
    private final Credentials credentials;
    private final AsyncRequestLog log;
    private final NtlmProxyClient proxyClient;
    private final AccessControl acl;

    private final List<ServerSocket> serverSockets = new ArrayList<>();
    private final List<Thread> acceptors = new ArrayList<>();
    private volatile boolean running = true;

    private final ThreadPoolExecutor pool;

    public ProxyServer(Config config, Credentials credentials, AsyncRequestLog log) {
        this.config = config;
        this.credentials = credentials;
        this.log = log;
        this.proxyClient = new NtlmProxyClient(config, credentials, 10000, 30000);
        this.acl = AccessControl.compile(config.acl,
                msg -> log.log("[acl] ignoring invalid rule: " + msg));
        int max = config.magicTest ? 1 : 256;
        this.pool = new ThreadPoolExecutor(16, max, 60, TimeUnit.SECONDS,
                new SynchronousQueue<>(), daemonFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public void start() throws IOException {
        List<Config.Listen> listeners = config.listen.isEmpty()
                ? defaultListeners() : config.listen;
        for (Config.Listen listen : listeners) {
            InetAddress bind = resolveBind(listen);
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(bind, listen.port));
            serverSockets.add(ss);
            Thread acceptor = new Thread(() -> acceptLoop(ss), "famntlm-accept-" + listen.port);
            acceptor.setDaemon(false);
            acceptors.add(acceptor);
            acceptor.start();
            log.log("[listen] " + bind.getHostAddress() + ":" + listen.port);
        }
    }

    private List<Config.Listen> defaultListeners() {
        List<Config.Listen> list = new ArrayList<>();
        list.add(new Config.Listen(null, 3128)); // CNTLM default port
        return list;
    }

    private InetAddress resolveBind(Config.Listen listen) throws IOException {
        if (listen.bindAddress != null) {
            return InetAddress.getByName(listen.bindAddress);
        }
        if (config.gateway) {
            return InetAddress.getByName("0.0.0.0");
        }
        return InetAddress.getByName("127.0.0.1");
    }

    private void acceptLoop(ServerSocket ss) {
        while (running) {
            try {
                Socket client = ss.accept();
                InetAddress peer = client.getInetAddress();
                if (peer == null || !acl.isAllowed(peer)) {
                    log.log("[denied] " + (peer != null ? peer.getHostAddress() : "unknown")
                            + "  (blocked by ACL)");
                    closeQuietly(client);
                    continue;
                }
                pool.execute(new ProxyConnection(client, config, proxyClient, log));
            } catch (IOException e) {
                if (running) {
                    log.log("[accept error] " + e.getMessage());
                }
            } catch (RuntimeException e) {
                // A single bad connection or ACL edge case must never kill the
                // acceptor and take the whole listener down with it.
                if (running) {
                    log.log("[accept error] unexpected: " + e);
                }
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignore) {
        }
    }

    public void shutdown() {
        running = false;
        for (ServerSocket ss : serverSockets) {
            try {
                ss.close();
            } catch (IOException ignore) {
            }
        }
        pool.shutdown();
        try {
            if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static ThreadFactory daemonFactory() {
        final AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, "famntlm-worker-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
