# SlateFS Client Support

SlateFS currently serves NFSv3 and 9P2000.L over TCP. 9P listeners can be
plaintext TCP for kernel v9fs, or rustls-wrapped TCP for TLS-capable clients
and sidecar tunnels. The daemon does not yet provide a virtio device; QEMU
`virtio-9p` is QEMU's own host-filesystem server, not a transport to an
arbitrary TCP 9P server.

## Supported Paths

| Client | Command shape | Coverage |
|---|---|---|
| Linux/macOS/BSD NFSv3 | `mount -t nfs -o vers=3,nolock,tcp,port=<p>,mountport=<p> <host>:/ <mnt>` | Kernel smoke, pjdfstest, fsx/fsstress, failover drill |
| Linux v9fs over TCP | `mount -t 9p -o trans=tcp,version=9p2000.L,msize=1048576,uname=<token>,aname=/tenant/volume,access=user <host> <mnt>` | Kernel smoke, pjdfstest, cross-protocol coherence |
| TLS-wrapped 9P TCP | Configure `p9_tls_cert` + `p9_tls_key`; connect with a TLS-capable 9P client or TLS tunnel that forwards plaintext 9P locally | In-process rustls end-to-end test |
| QEMU guest over TCP | Same 9P TCP mount from inside the guest, using the host/sidecar address reachable from the VM | `scripts/qemu-p9-tcp-smoke.sh` |

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

## Validation

The QEMU smoke can be run through the Docker harness:

```sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-p9-tcp-smoke.sh
```

The script boots a small Linux guest, mounts the SlateFS 9P TCP export, performs
file create/read/readdir/remove operations, and requires the guest to print a
success marker before the host process exits successfully.
