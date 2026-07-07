# SlateFS Client Support

SlateFS currently serves NFSv3, 9P2000.L, and block volumes over NBD. 9P
listeners can be plaintext TCP for kernel v9fs, or rustls-wrapped TCP for
TLS-capable clients and sidecar tunnels. NBD listeners can be plaintext TCP or
NBD `STARTTLS`, with optional client-certificate authentication. The daemon
does not yet provide a virtio device; QEMU `virtio-9p` is QEMU's own
host-filesystem server, not a transport to an arbitrary TCP 9P server.

## Supported Paths

| Client | Command shape | Coverage |
|---|---|---|
| Linux/macOS/BSD NFSv3 | `mount -t nfs -o vers=3,nolock,tcp,port=<p>,mountport=<p> <host>:/ <mnt>` | Kernel smoke, pjdfstest, fsx/fsstress, failover drill |
| Linux v9fs over TCP | `mount -t 9p -o trans=tcp,version=9p2000.L,msize=1048576,uname=<token>,aname=/tenant/volume,access=user <host> <mnt>` | Kernel smoke, pjdfstest, cross-protocol coherence |
| TLS-wrapped 9P TCP | Configure `p9_tls_cert` + `p9_tls_key`; connect with a TLS-capable 9P client or TLS tunnel that forwards plaintext 9P locally | In-process rustls end-to-end test |
| QEMU guest over TCP | Same 9P TCP mount from inside the guest, using the host/sidecar address reachable from the VM | `scripts/qemu-p9-tcp-smoke.sh` |
| Linux kernel NBD | `nbd-client <host> <port> /dev/nbdX -N /tenant/volume -persist off [-C 2]` | ext4 kernel attach/crash/TRIM smoke |
| QEMU/qemu-img NBD | `qemu-img info nbd://<host>:<port>//tenant/volume` | Userspace info/convert/bench smoke |

Linux kernel v9fs does not negotiate TLS itself. For encrypted transport with
kernel mounts, run the plaintext v9fs hop inside an already-isolated network
path or through a TLS tunnel/sidecar.

## QEMU Notes

For QEMU VMs, use a normal TCP 9P mount from the guest to the `slatefsd`
listener. With QEMU user networking, the guest usually reaches the host-side
listener at `10.0.2.2`.

`virtio-9p` remains a separate future transport question. Supporting it would
require a QEMU/virtio bridge or embedding SlateFS behind QEMU's virtfs backend;
it is not the same thing as the current TCP 9P daemon.

## NBD Notes

Linux kernel clients use `nbd-client` plus the `nbd.ko` module. Use
`nbd-client` 3.16 or newer for `NBD_OPT_GO` plus multi-connection support; the
kernel smoke probes `-C` and falls back to a single connection when a local
client build does not expose it. Attach with a bounded timeout:

```sh
modprobe nbd max_part=8 nbds_max=16
nbd-client 127.0.0.1 12059 /dev/nbd0 -N /t1/b1 -persist off -timeout 60 -C 2
```

QEMU userspace tools do not need `nbd.ko`. For SlateFS export names of the
form `/tenant/volume`, QEMU's URI form needs a doubled slash after the port:

```sh
qemu-img info nbd://127.0.0.1:12059//t1/b1
qemu-img convert -f raw -O raw -n disk.raw nbd://127.0.0.1:12059//t1/b1
```

NBD TLS is implemented with forced `NBD_OPT_STARTTLS` when `nbd_tls_cert` and
`nbd_tls_key` are configured. Setting `nbd_tls_client_ca` additionally requires
a verified client certificate and keys the writable session lease by the client
certificate identity instead of source IP. Plain NBD exports reject STARTTLS.

macOS has no built-in kernel NBD client. Use QEMU/libnbd userspace tools for
image maintenance from macOS, or attach the kernel device from a Linux VM.

## Validation

The QEMU smoke can be run through the Docker harness:

```sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-p9-tcp-smoke.sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-nbd-smoke.sh
```

The script boots a small Linux guest, mounts the SlateFS 9P TCP export, performs
file create/read/readdir/remove operations, and requires the guest to print a
success marker before the host process exits successfully.

The NBD QEMU smoke uses `qemu-img info`, writes a raw image to a SlateFS block
export with `qemu-img convert`, reads it back, compares bytes, and runs a short
`qemu-img bench`.
