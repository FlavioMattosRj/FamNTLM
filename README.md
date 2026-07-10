# FamNTLM

A Java (8+) re-implementation of [CNTLM](https://cntlm.sourceforge.net/) — an
authenticating NTLM/NTLMv2 proxy that sits between local applications and a
parent corporate proxy that requires NTLM authentication.

FamNTLM aims to be **drop-in compatible** with CNTLM: the same `cntlm.conf`
directives, the same command-line options, and the same password-hash formats
(`PassLM` / `PassNT` / `PassNTLMv2`), so existing configurations work unchanged.

## Build

```
mvn clean package
```

Produces a self-contained executable JAR with all dependencies:
`target/famntlm.jar`.

## Usage

```
java -jar famntlm.jar [options] [parent-proxy:port ...]
java -jar famntlm.jar stop        # gracefully stop a running instance
java -jar famntlm.jar status      # query a running instance
```

Run `java -jar famntlm.jar -h` for the full option list.

### Generate password hashes (like `cntlm -H`)

```
java -jar famntlm.jar -H -u User -d Domain
```

Prints `PassLM`, `PassNT` and `PassNTLMv2` to paste into your config — the
plaintext password never needs to be stored.

### Configuration file

By default FamNTLM looks for (in order):

- Windows: `%PROGRAMFILES%\Cntlm\cntlm.ini`, then `./cntlm.ini`
- Unix: `/etc/cntlm.conf`, then `/usr/local/etc/cntlm.conf`

Override with `-c <file>`. Command-line options always take precedence over the
configuration file. A documented sample lives in [doc/cntlm.conf](doc/cntlm.conf).

## Compatibility status

| Area | Status |
|------|--------|
| `cntlm.conf` parsing (all directives) | ✅ recognized |
| All CNTLM command-line options | ✅ parsed |
| Password hashes LM / NT / NTLMv2 (`-H`) | ✅ verified against MS-NLMP vectors |
| NTLM auth: NTLMv2, NTLM2SR, NT, NTLM, LM | ✅ implemented |
| HTTPS / CONNECT tunneling through parent proxy | ✅ working |
| Plain HTTP forwarding (buffered body) | ✅ working |
| Concurrent requests (bounded thread pool) | ✅ |
| Async buffered request log | ✅ |
| `stop` / `status` control commands + graceful shutdown | ✅ |
| Multiple parent proxies with failover | ✅ |
| SOCKS5 proxy (`-O`) | ⏳ parsed, not yet served |
| Transparent tunnels (`Tunnel` / `-L`) | ⏳ parsed, not yet served |
| ISA scanner plugin (`-S` / `-G`) | ⏳ parsed, not yet active |
| ACL (`Allow` / `Deny`) enforcement | ⏳ parsed, not yet enforced |
| Magic dialect detection (`-M`) | ⏳ parsed, not yet run |

Legend: ✅ done · ⏳ configuration accepted, behaviour pending.

## Design notes

- **Concurrency**: a bounded `ThreadPoolExecutor` with a caller-runs fallback,
  so bursts throttle the accept loop instead of exhausting memory.
- **Logging**: a lock-free bounded ring drained by one daemon thread; entries
  are dropped (and counted) rather than blocking request threads under load.
- **Lifecycle**: a loopback control channel (default port 3129, override with
  `FAMNTLM_CONTROL_PORT`) handles `stop`/`status` cross-platform without POSIX
  signals; a JVM shutdown hook also triggers graceful shutdown.
- **Crypto**: pure-Java MD4 for the NT hash (not guaranteed by JCE providers);
  DES-based LM hash; HMAC-MD5 for NTLMv2. Hash and hex formats match CNTLM.
