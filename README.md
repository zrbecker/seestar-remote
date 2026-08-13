# seestar-remote

Remote access to a ZWO **Seestar** telescope over the internet, reaching a scope behind
NAT with no LAN access. It reimplements ThroughTek's **Kalay** P2P stack in Go and runs
the Seestar's own services over that tunnel.

| tool | what it gives you |
|------|-------------------|
| **proxy**    | local TCP ports mapped to the device's services over one tunnel |
| **download**  | a resumable, self-verifying archive downloader |
| **upload**    | writes local files (or a whole directory) into the device's image share |

## How it works

```
ZWO cloud auth (login + online-link)           seestar/cloud.go
  └─ IOTC P2P rendezvous + NAT hole-punch      kalay/session.go
       └─ DTLS 1.2 ECDHE_PSK_CHACHA20_POLY1305 kalay/dtls.go
            └─ RDT reliable transport          kalay/rdt.go, kalay/tunnel.go
                 └─ P2PTunnel channels         kalay/tunnelconn.go
                      └─ device :4700 JSON-RPC, :445 SMB
```

`online-link` authorizes a fresh connection window per session. The device accepts
**one** remote session at a time.

## Setup

| env | meaning | default |
|-----|---------|---------|
| `SEESTAR_EMAIL` / `SEESTAR_PASSWORD` | ZWO account | — |
| `SEESTAR_SN` | device short serial | chosen from your account |
| `SEESTAR_MODEL` | device model | from the device list |
| `SEESTAR_MASTER` | Kalay rendezvous master | `119.45.181.137:3478` |

ZWO's cloud API is private and unversioned; it can change without notice.

`KALAY_TUN_DEBUG=1` adds tunnel and RDT tracing on stderr.

## Build

```
go build -o bin/proxy     ./cmd/proxy
go build -o bin/download  ./cmd/download
go build -o bin/upload    ./cmd/upload
```

## proxy

Maps device ports to local ones, Docker style, `-p local:device`:

```
bin/proxy -p 4700:4700
printf '{"id":1,"method":"get_device_state"}\r\n' | nc 127.0.0.1 4700
```

Repeat `-p` for more. All mappings share one tunnel, since the device rejects a second
concurrent Kalay session:

```
bin/proxy -p 4700:4700 -p 32323:32323 -p 8080:80
curl http://127.0.0.1:32323/management/v1/configureddevices
```

| device port | service |
|---|---|
| `4700` | JSON-RPC control API (newline-delimited JSON) |
| `32323` | ASCOM Alpaca REST — the scope serves this itself, so NINA and ConformU can be pointed straight at it |
| `80` | HTTP image server |

Any tool speaking the Seestar LAN protocols works unchanged, because a mapped port looks
like the device on localhost. The tunnel is dialled once and held until the process exits,
so each client connection costs only a TCP accept. Running proxy occupies the device's
single remote session for its lifetime; Ctrl-C releases it. One client at a time per
mapped port — a second connection is refused rather than left waiting.

`LISTEN_HOST` sets the bind address (default `127.0.0.1`).

## download

```
OUTBASE=/path/to/archive bin/download
```

Walks the device SMB tree and fetches each file, skipping any already present at
matching size, then re-walks the device and diffs. It prints `VERIFIED COMPLETE` only
when every device file is present locally at the exact size. A manifest of the device
tree is written to `$OUTBASE/_device_manifest.tsv`.

Env: `OUTBASE`, `SHARE` (default `EMMC Images`), `ROOT` (default `MyWorks`),
`SMB_PARALLEL` (default 4), `SMB_USER` (default `Guest`), `LIST_ONLY` (write the
manifest and stop).

Scope is narrowed with `TARGETS` (comma-separated top-level directories under `ROOT`)
and `EXCLUDE_EXT` (comma-separated extensions to skip); empty means no restriction.

```
TARGETS="M 24,Mizar" EXCLUDE_EXT=".mp4,.avi" OUTBASE=/path/to/archive bin/download
```

Directories outside `TARGETS` are never opened, so unwanted subtrees cost no `ReadDir`
round-trips. Matching is on whole path segments, so `M 24` does not pull in `M 24_sub`.
The same filter applies to the download walk, the manifest and the verify re-walk, so
`VERIFIED COMPLETE` describes the filtered scope.

Each file is fetched by `SMB_PARALLEL` concurrent range reads streamed into a `.part`
file, renamed only once every byte is on disk, so memory stays flat regardless of file
size. Reads have size-scaled timeouts; a file that fails four times is left for the
verify pass to report as missing. Teardown attempts a graceful SMB shutdown and
force-closes the tunnel if it blocks, since a wedged transfer would otherwise hold the
device's only session.

## upload

```
bin/upload <local_path> <device_rel_path>
```

Writes a file into the device's SMB image share, creating any missing parent directories and
reading the size back to confirm. A directory argument uploads every file beneath it in one
session, preserving structure — one session avoids the per-session cooldown the device imposes
after each disconnect.

Env: `SHARE` (default `EMMC Images`), `ROOT` (default `MyWorks`), `SMB_USER` (default `Guest`),
`UPLOAD_CHUNK` (SMB write size, default 8192), `UPLOAD_WORKERS` (concurrent writers, default 16).

```
bin/upload ./finals M31/finals          # a directory
bin/upload ./M31.fit finals/M31.fit     # a single file
```

Each file is streamed as small SMB writes dispatched to a pool of concurrent `WriteAt` workers.
Two constraints shape this: a single SMB write larger than the tunnel's send window deadlocks (the
device won't acknowledge a partial write, so the window fills and never slides), so writes stay
well under it; and go-smb2's write is synchronous, one round trip per write, so concurrency is what
keeps the window full. Throughput is ultimately bounded by the device's receive buffer times the
round-trip time — on a typical remote path a few hundred KB/s.

## Sharp edges

This is a reverse-engineered stack built around SMB bulk transfer — `download` and `upload` —
plus request/response for JSON-RPC and Alpaca. Those paths are solid. Other uses, especially
through raw `proxy`, run into limits that were never the focus:

- **No liveness detection.** The tunnel sends keepalives at several layers but never reads
  the replies, and nothing times out on silence. A tunnel that wedges mid-session does not
  error — it goes quiet. A `proxy` client then hangs with no feedback, and a CIFS mount
  over `proxy` can leave uninterruptible (D-state) processes. `download` works around this
  with its own per-file stall timeouts and a force-close teardown watchdog; `proxy` has
  none, so recovery is killing the process.

- **Outbound throughput is device-bound, and large writes need chunking.** The client-to-device
  direction has a go-back-N retransmit buffer with AIMD congestion control, so bulk uploads survive
  loss — but the device's receive buffer is small, so sustained outbound throughput is capped at a
  few hundred KB/s regardless of the path. A single application write larger than the congestion
  window also deadlocks, since the device won't consume a partial write; `upload` chunks to stay
  under it, but a client pushing large writes through raw `proxy` must do the same.

- **One session, one client per port.** The device accepts a single remote Kalay session,
  so a running `proxy` or `download` occupies the scope — the phone app and the other tool
  cannot connect meanwhile. Each mapped port serves one client at a time; a second is
  refused.

- **`proxy` is a byte pipe.** It does not parse the tunnelled protocols. On a dial failure
  it injects an error the client may not understand, and it cannot retry or recover a
  mid-stream failure — that is the client's problem.

- **Narrow, moving target.** Verified against a Seestar S30 Pro on one firmware. ZWO's
  cloud API is private and unversioned, and ports and behaviour move across models and
  firmware, so any of this can break without notice.

- **`download` verifies by size, not content.** `VERIFIED COMPLETE` means every device file
  is present locally at the exact byte length; it does not hash. A full-length but corrupt
  file passes. The most likely source of that — a short read leaving a sparse hole — is
  guarded against, so the risk is low, but the check is not integrity.

## Layout

- `kalay/` — the reversed transport: control, session, dtls, rdt, tunnel.
- `seestar/` — ZWO cloud auth and the tunnel dial.
- `internal/tnauth/` — the `51cc` relay authorization and coordination channel.
- `cmd/` — the tools: `proxy`, `download`, `upload`.
