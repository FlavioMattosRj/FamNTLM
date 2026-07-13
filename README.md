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

### Independent privacy-safe connectivity MVP

The build also creates `target/mvp.jar`, a self-contained probe implemented only
by `MVP.java` and its nested classes. It reads an existing CNTLM hash profile,
authenticates directly with the configured parent proxy, establishes an HTTPS
tunnel, verifies TLS, and requests the target URL.

```text
java -jar target\mvp.jar -c C:\path\to\cntlm.ini https://registry.yarnpkg.com/
```

Its output contains only stable phase/error codes, HTTP status codes, and NTLM
flags. It never echoes configuration values, identities, hashes, paths, proxy or
target addresses, authorization tokens, challenges, or exception messages. The
MVP accepts CNTLM `PassLM`, `PassNT`, and `PassNTLMv2` profiles; it intentionally
does not accept a plaintext `Password` fallback.

## Usage

```
java -jar famntlm.jar [options] [parent-proxy:port ...]
java -jar famntlm.jar stop        # gracefully stop a running instance
java -jar famntlm.jar status      # query a running instance
java -jar famntlm.jar test [url]  # connectivity self-test (see below)
```

Run `java -jar famntlm.jar -h` for the full option list. Add `-v` (verbose) to
print NTLM handshake diagnostics to stderr — the parent's challenge, the
negotiated flags, and the flags sent back — which is the quickest way to debug a
`407` from the parent proxy.

Beyond the CNTLM-compatible options, FamNTLM adds two long options:

- `--full-log` — never drop log lines: apply backpressure instead of the default
  drop-and-count when the log buffer is full (see [Logging](#design-notes)).
- `--allow-open-proxy` — explicitly permit a non-loopback listener with no
  restricting ACL (see [Access control & security](#access-control--security)).

### Connectivity self-test

Verify that an existing CNTLM configuration works end-to-end — it loads the
config (honouring `-c` for a non-default location), **reuses the existing
`PassLM`/`PassNT`/`PassNTLMv2` hashes**, and tries to reach an external URL
through the parent proxy. It exits non-zero on failure, so it fits in scripts.

```
java -jar famntlm.jar test -c C:\path\to\cntlm.ini https://example.com
```

Example output on success:

```
[test] config: C:\path\to\cntlm.ini
[test] identity: CORP\testuser  auth=NTLMv2  credentials=PassNTLMv2 PassNT PassLM
  trying example.com:443 via 10.0.0.41:8080 as CORP\testuser (auth=NTLMv2) ...
[test] PASS: reached example.com:443 via 10.0.0.41:8080 (CONNECT tunnel established)
```

On failure it prints `famntlm: test FAILED - <reason>` and returns exit code 1.

### Inspect a configuration: `--list-config`

Locates the configuration, describes where it was found, prints **every
parameter except the secret keys** (the `Pass*` hashes and any password are
masked), then runs the connectivity self-test through the proxy and reports the
result before exiting.

```
java -jar famntlm.jar --list-config -c C:\path\to\cntlm.ini https://example.com
```

```
=== FamNTLM configuration report ===
Source          : -c override
Location        : C:\path\to\cntlm.ini
Searched paths  : C:\Program Files\Cntlm\cntlm.ini, cntlm.ini

--- Parameters (secret keys hidden) ---
Username        : testuser
Domain          : CORP
Auth            : NTLMv2
Credentials     : PassNTLMv2 PassNT PassLM (values hidden)
Proxy           : 10.0.0.41:8080
Listen          : 3128

--- Connectivity self-test ---
Result          : PASS - reached example.com:443 via 10.0.0.41:8080 (CONNECT tunnel established)
URL tested      : https://example.com
```

Exit code is 0 when the self-test passes, 1 otherwise.

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

`NoProxy` hosts bypass the parent proxy and are reached **directly**. Patterns use
CNTLM-style wildcards (`*` and `?`), are anchored and case-insensitive, and match
the request hostname — e.g. `NoProxy localhost, 127.0.0.*, *.intranet.local`. This
applies to both CONNECT (HTTPS) and plain HTTP requests.

## Access control & security

`Allow` / `Deny` ACL rules are enforced on every accepted connection. Rules are
evaluated in configuration order and the **first match wins**; a spec may be `*`,
a bare host/IP, a CIDR (`192.168.0.0/16`), or an address with a dotted netmask
(`192.168.0.0/255.255.0.0`).

To avoid accidentally exposing your NTLM credentials as an open proxy, startup is
**fail-closed**:

- **Loopback-only listeners** (the default, `127.0.0.1`) allow by default when no
  rule matches — CNTLM-compatible, since only local apps can connect.
- **Non-loopback listeners** (`Gateway yes`, or `Listen 0.0.0.0` / a public
  address) default to **deny** when no rule matches, so a whitelist such as
  `Allow 192.168.0.0/16` blocks everyone else even without a trailing `Deny *`.
- A non-loopback listener with **no ACL at all** makes FamNTLM **refuse to start**
  unless you pass `--allow-open-proxy` (which then runs an open proxy and prints a
  loud warning — firewall the port to trusted networks).
- **Any invalid ACL rule** (e.g. a malformed mask) makes FamNTLM **refuse to
  start** rather than silently ignore a rule you intended as protection.

Other hardening applied on the request path:

- Requests carrying `Transfer-Encoding` or a duplicate/conflicting `Content-Length`
  are rejected with `400` (HTTP request-smuggling guard); bodies are forwarded by
  a single `Content-Length` only.
- HTTP message heads are capped (64 KiB) so a client or parent proxy cannot
  exhaust memory with unbounded headers.
- Logged request targets are sanitized: `user:pass@` userinfo and the query string
  are removed and control characters neutralised, so tokens and secrets in URLs
  are not written to the log.

Directives that are parsed but not yet enforced (see the table below) print a
startup warning instead of failing silently.

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
| Async buffered request log (bounded; `--full-log` for backpressure) | ✅ |
| `stop` / `status` control commands + graceful shutdown | ✅ |
| Multiple parent proxies with failover | ✅ |
| ACL (`Allow` / `Deny`) enforcement | ✅ enforced (first-match; public listeners fail closed) |
| Open-proxy guard (refuses to start; `--allow-open-proxy` to override) | ✅ |
| `NoProxy` direct-connect bypass | ✅ matched hosts reach the origin directly (CONNECT + plain HTTP) |
| SOCKS5 proxy (`-O`) | ⏳ parsed, warns, not yet served |
| Transparent tunnels (`Tunnel` / `-L`) | ⏳ parsed, warns, not yet served |
| ISA scanner plugin (`-S` / `-G`) | ⏳ parsed, warns, not yet active |
| `Header` injection / `NTLMToBasic` | ⏳ parsed, warns, not yet applied |
| Magic dialect detection (`-M`) | ⏳ parsed, not yet run |

Legend: ✅ done · ⏳ configuration accepted (and warned about at startup),
behaviour pending.

## Design notes

- **Concurrency**: a bounded `ThreadPoolExecutor` with a caller-runs fallback,
  so bursts throttle the accept loop instead of exhausting memory.
- **Logging**: a bounded queue drained by one daemon thread. By default entries
  are dropped (and counted) rather than blocking request threads under load;
  `--full-log` switches to backpressure so nothing is dropped, blocking a producer
  only when the buffer is full. Timestamps are captured cheaply and formatted off
  the request path. `status` reports `log-backlog`, `peak` and `dropped`.
- **Access control**: `Allow`/`Deny` enforced first-match on every connection;
  fail-closed startup for public listeners (see
  [Access control & security](#access-control--security)).
- **Lifecycle**: a loopback control channel (default port 3129, override with
  `FAMNTLM_CONTROL_PORT`) handles `stop`/`status` cross-platform without POSIX
  signals; a JVM shutdown hook also triggers graceful shutdown. Connections are
  handled off the accept thread with a read timeout, a bounded command length,
  and capped concurrency, so a local client cannot wedge the channel by stalling
  or flooding it.
- **Crypto**: pure-Java MD4 for the NT hash (not guaranteed by JCE providers);
  DES-based LM hash; HMAC-MD5 for NTLMv2. Hash and hex formats match CNTLM.
