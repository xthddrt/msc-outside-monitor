# Linux agent

On Linux there is no driver. `msmon-agent` runs its own sensors (`agent/linux/`) and
feeds their records through the same queue format, sequence numbering, hash-chained
JSONL writer, classifier and session bundle as the Windows agent, so `verify_log.py`,
`session_pack.py`, `sensor_report.py` and `tools/analysis/` read Linux bundles unchanged.

## Build and check

```sh
./build.sh
```

Needs g++ (C++17) and python3. It builds `build/linux/msmon-agent` and
`build/linux/integration_regression`, then runs `tools/check_sensor_map.py`, the
regression (against the ETW stub), `identity_log.py --self-test`, `tests/*_test.py`, and
the `verify_log.py` gate that `tests/integration_regression.cmd` runs on Windows.

The kernel (eBPF) sensors also need clang, bpftool, the libbpf headers and the running
kernel's BTF (`/sys/kernel/btf/vmlinux`):

```sh
sudo apt install clang-18 libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

Without them `build.sh` says so and builds the agent without them; it then uses the
fanotify, proc connector and polling sensors below. `CLANG=`, `BPFTOOL=` and
`LIBBPF_INCLUDE=` point the build at tools outside `PATH`.

Root-only check (run it in a VM): `sudo tests/linux_ebpf_test.sh`. With Wine 11.0 in
`/opt/wine-stable` (or `WINE_ROOT=`), `sudo tests/linux_wine_test.sh` records `reg query`, `reg add`
and `tasklist` in a temporary prefix it creates as `$SUDO_USER` and checks the wineserver-decoded
records, the PE frames and the decoder's coverage notes.

## Run

```sh
sudo build/linux/msmon-agent --client ~/.wine-nexon/drive_c/Nexon/Library/maplestorycw --log-dir /var/tmp/msmon-sessions
sudo build/linux/msmon-agent --pid 1234 --log-dir /var/tmp/msmon-sessions --once
```

Under Wine `/proc/<pid>/exe` is the Wine loader, never `MapleStory.exe`. A process is in
scope when its image is under a root, when it has an executable file mapping under a
root (checked in the kernel at `mmap`, and in `/proc/<pid>/maps`), when it is the
wineserver of the client's prefix (its `WINEPREFIX`, default `$HOME/.wine`), or when it
descends from a process in scope. Other programs in the prefix (the Nexon launcher, Wine's
services) are not in scope unless they map an executable under a root. A descendant that
execs a native program (anything whose basename does not start with `wine` and is not under
the root, e.g. `xdg-open` and the browser it starts) leaves scope at that exec: the exec is
recorded, then a `process_exit` with value1 1 and `untracked;native_exec`, and neither it nor
its children are followed. The prefix is the nearest folder above `--client` that holds
`system.reg`, or `--prefix DIR`. `/proc` is rescanned every second for processes that
started outside the tracked tree (a wineserver started earlier, a client service).
The prefix is a snapshot root: the `*.reg` files wineserver saves (it writes a temporary
file and renames it into place) are copied into the session, up to 16 MiB each.

`--no-ebpf` keeps the kernel sensors off.

`MapleStory.exe` is not required: any `--client`/`--scope-root` directory with an
executable file directly inside it is accepted (the first by name is hashed as the
client; `MapleStory.exe` is preferred when present), or `--pid`. Paths are used as given (absolute, case-sensitive). Stop with
Ctrl+C, SIGTERM or `--stop-file`.

Root is needed for the kernel sensors (CAP_BPF, CAP_PERFMON, CAP_MAC_ADMIN for the LSM
hooks), for fanotify and for the process-events connector (CAP_SYS_ADMIN, CAP_NET_ADMIN,
CAP_DAC_READ_SEARCH). Without it the agent still runs and writes a valid,
chain-verified log, but records `fanotify_unavailable` / `proc_connector_unavailable` and
marks those registrations failed in `coverage.json`; only `/proc` polling (images and
sockets of your own processes) is active.

## Sensors

With root and a BPF-capable kernel the kernel sensors are used, and the user-space sensors
of the classes they cover are not started (coverage notes `*_superseded`). The maps poll
is the exception: it always stays active and owns `image_load`, because Wine maps PE
modules without `PROT_EXEC` and makes their code sections executable with `mprotect`.

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.ebpf_process` (48/54) | `tp_btf/task_newtask` (tracking copied before the child runs), `sched_process_fork/exec/exit`, `lsm/mmap_file` and `lsm/file_mprotect` (an untracked process mapping an executable under the root, or mprotecting a mapped file executable, joins the scope) | `process_start` (fork = inherited; exec = value1 1 with the image and argv), `process_exit`, `thread_start`, `thread_exit` |
| `linux.ebpf_file` (49/55) | `tp_btf/sys_enter` + `sys_exit` for 105 syscalls of tracked processes | `file_create` (open*, mkdir, mknod), `file_read`/`file_write` (value0 bytes transferred, value1 offset; also recvmmsg/sendmmsg, and the input fd of sendfile, copy_file_range and splice), `file_close`, `file_set_information` (unlink 13, rename 10 as `rename;from`/`rename;to`, link 11, truncate 20), `file_set_security` (chmod/chown/utimes), `file_query_information` (stat, access, readlink, statfs), `file_directory_control` (getdents, value1 bytes), `file_set_ea`/`file_query_ea` |
| `linux.ebpf_net` (50/56) | the same syscalls on sockets | `network_connect` (connect; sendto and sendmsg with an address), `network_accept` (accept; recvfrom and recvmsg with a source; `bind;` with the local address; `listen;` with value1 the backlog), `network_flow_close` (close of a socket; value0 socket inode) |
| `linux.ebpf_ipc` (51/57) | AF_UNIX connect/accept, kill/tkill/tgkill | `network_connect`/`network_accept` with `unix:` endpoints, `process_handle` (`signal=N`, target_process_id) |
| `linux.ebpf_device` (52/58) | ioctl | `file_device_control` (value0 request, value1 argument) |
| `linux.ebpf_wineserver` (60/61) | `tp_btf/sys_enter` write/writev and `sys_exit` read on a Wine thread's wineserver request/reply pipes (`mm_ws_*`) | see [Wineserver requests](#wineserver-requests) |
| `linux.ebpf_memory` (53/59) | mmap, mprotect, ptrace, process_vm_readv/writev; `lsm/ptrace_access_check`, `lsm/bpf`, `lsm/perf_event_open` | `file_section` (file or executable mappings; value0 flags, value1 protection); an executable file mmap or a successful `mprotect(PROT_EXEC)` triggers an immediate `linux.maps_poll` scan, so `image_load` arrives at once; `process_handle` (ptrace request or VM read/write, target_process_id; `prctl;option=N`, PR_SET_PTRACER naming its target; `init_module`/`finit_module`; `pidfd_open`, `pidfd_getfd`, `pidfd_send_signal`, `process_madvise`, `kcmp`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`); the tracked tree is refused ptrace of the agent, `bpf()` and `perf_event_open` (`self_protection_denied=` records) |

Every syscall record carries the syscall name, all six arguments, the result and the
duration in `detail`, the thread in `thread_id`, the negative errno in `status`, and up to
8 user return addresses as the stack (resolved against `image_load` ranges into `modules`).
Paths are rebuilt in the kernel from the task's dentries and its fd table, cwd or dirfd
(pipes, sockets and anonymous inodes are named `pipe:[ino]`, `socket:[ino]`,
`anon_inode:[ino]`); a path the kernel could not resolve falls back to the agent's fd table.
When the ring is full a record is dropped and counted as a sequence gap.

Repeats are collapsed: the same call by one process on the same target (path, endpoint,
ioctl request or target process) with the same errno is written at most once per second.
The first call of each second keeps its full record; the calls after it are counted, and
the count (`repeats_before=N;repeat_bytes=B`) is added to the next record of that key or
written as a `repeats_tail` record (value0 bytes, value1 count) when the process exits or
leaves scope. Mutations (unlink, rename, link, mkdir, truncate, chmod/chown, set-xattr),
mappings, execs, bind/listen, prctl and module loads are never collapsed. Counts still held
when the agent stops (under a second of calls per key) are not written.

Every operation kfilter's BPF layer can refuse has a record here: file open/read/write/
readdir, delete/rename/link/symlink/mkdir/mknod/truncate/chmod/chown/xattr/explicit times,
executable mappings, ioctls, exec, fork, ptrace-checked process access (ptrace,
process_vm_*, `/proc/<pid>/mem` opens, pidfd_getfd, process_madvise, kcmp), signals,
prctl PR_SET_MM/PR_SET_PTRACER, module loads, bpf/perf_event_open, connect, sendto/sendmsg
peers, bind, listen, accept and recvfrom/recvmsg sources. A refused call appears with its
negative errno in `status`; the decision itself is the KFilter record read from kfilterd.

Syscalls of 32-bit (ia32) processes (the Nexon launcher, grap-updater) are skipped: their
numbers and argument registers are not the x86_64 ones the syscall table describes. Their
process, thread and image records still come from the scheduler tracepoints and the maps poll.

## Kernel sensor upgrades

Each part below has its own BPF and agent files. `tcp`, `packets`, `wineserver` and the socket
tags they share (`socks`) are optional program groups: if the verifier refuses one, the object
is loaded without it and `ebpf_active` says so (`optional=socks:on,tcp:load_failed:22,...`).

### PE frames

Wine runs a PE program's syscalls on its own per-thread stack, so the 8 user frames of a syscall record
stop in Wine's unix code (`ntdll.so`). At `sys_exit`, `read_pe` (`bpf/pe.bpf.h`) takes the thread's TEB
from its GS base (TEB `Self` must equal it, else the thread has no TEB and is skipped) and, when the
thread's sp is on Wine's kernel stack below its `syscall_frame` (Wine's `is_inside_syscall`), copies the
frame's rip, rsp and rbp and up to 512 bytes of the PE stack at rsp (up to the TEB's `StackBase`). Such a
record is a full 2080-byte event; others stay 1536 bytes. The agent (`pe.cpp`, `bpf_pe.inc`) turns it into
up to 16 PE frames placed before the unix frames: rip (inside the `NtXxx` stub of `ntdll.dll`), then the
return addresses unwound with the x64 `.pdata`/`.xdata` of the mapped PE images (each file parsed once from
disk), then, where unwinding stops, the words of the rest of the copied stack that point into PE code
sections. `detail` gets `pe_frames=N` and, for scan finds, `pe_scanned=M`. `modules` (resolved in stack
order, deduplicated, at most 8) therefore reads Windows side first, then unix side, e.g. `ntdll.dll`,
`kernelbase.dll`, the game's module, `ntdll.so`, `libc.so.6`; `tools/analysis/common.py` `caller_module`
skips Wine's own, the prefix's `windows` and the system's modules. This applies to every record built from
a syscall (and the wineserver-request records); process, thread, TCP and packet records have no PE side.

A PE image's `image_load` is one record per load: value0 is its header mapping (file offset 0), value1 its
`SizeOfImage`, so code Wine reads into anonymous memory (sections not page-aligned in the file) resolves
too. Coverage: a `pe_frames` note, and `pe_frames=16;pe_stack_bytes=512` in the `ebpf_active` detail.

- Coverage limit: only 512 bytes of PE stack are copied, so a frame larger than what is left (ping.exe's
  `main` takes 760 bytes) ends the unwinding and the scan of the rest may name stale addresses. A frame
  register other than rbp, an indirect unwind entry or a missing image also end it (packed code without
  `.pdata` is scan-only). WoW64 threads show their 64-bit side (`wow64*.dll`), not the 32-bit caller.
  Frames resolve against the images of the last maps scan, and a repeat-collapsed record keeps the
  first call's frames.

### Socket bytes and DNS

Every byte a tracked process sends or receives on an `AF_INET`, `AF_INET6` or `AF_NETLINK`
socket with `read`, `write`, `readv`, `writev`, `preadv2`, `pwritev2`, `sendto`, `recvfrom`, `sendmsg`,
`recvmsg`, `sendmmsg` or `recvmmsg` (all iovecs, every message) is logged. `mm_sys_exit` copies the bytes
the call moved (bounded by its result) into a separate 64 MiB ring (`payload_ring`) in 4 KiB
pieces with `bpf_loop`, before the call's record; the agent writes them as a `network_data`
payload on the call's own I/O record (`file_read`/`file_write`, or `network_connect`/
`network_accept` when the call names a peer), Base64 in 8 KiB chunks linked by `operation_id`
(docs/LOG_SCHEMA.md §4). Sent bytes carry `payload_input`. The detail adds
`endpoints=local -> remote` of the socket (`netlink=<protocol>` for netlink), and
`sendmmsg`/`recvmmsg` write one series per message with `msg=<index>` (value0 its bytes).
Calls that carry bytes are never collapsed into repeat counts. Wine's own socket I/O
(`sendmsg`/`recvmsg` from `ntdll.so`) is the game's path. `ebpf_active` names the settings
(`payload=on;payload_chunk=4096;payload_call_max=1048576`).

At most 1 MiB is captured per call; the rest is counted (`payload_partial`,
`payload_missing=<bytes>;payload_stop=limit`). A full payload ring or an unreadable buffer
stops that call's capture (`payload_stop=ring_full` or `fault`; `steps` after 4096 walk
steps; `truncated` when a `MSG_TRUNC` call reported more than its buffers held;
`chunks_lost` when the agent lost bytes the kernel captured, past its 64 MiB of held chunks). A
partial series keeps whole 8 KiB chunks only, and a call with none is one record flagged
`payload_unavailable`, its reason (`payload_ring_full`, `payload_fault`, `payload_truncated`,
`payload_chunks_lost`) first in the detail; `sendmmsg`/`recvmmsg` messages after the stop get one
such record with `msg_missing=<first>-<last>`. Such operations count as incomplete, as on Windows.

DNS messages to or from port 53 (UDP, and TCP with its 2-byte length framing across calls) are
parsed from those bytes in the agent (`agent/linux/dns.cpp`, self-tested by `build.sh`) into
`etw_dns` records: `text` the queried name, `detail`
`query_type=N;dns_id=N[;rcode=N;answers=TYPE value|...];transport=udp|tcp;server=address:53`,
value0 3006 for a query and 3008 for a response, `operation_id` the payload it came from.

`--no-payloads` turns all of this off in the kernel (`mm_config.flags`; the ring shrinks to
one page) and in the agent: no bytes and no `etw_dns`.

Limits:

- Most game traffic is TLS or the game's own encryption: it is logged as ciphertext, never
  plaintext.
- Only `AF_INET`, `AF_INET6` and `AF_NETLINK` sockets: not `AF_UNIX` or pipe contents (X11,
  D-Bus, wineserver), not `sendfile`/`splice`/`copy_file_range` into a socket, not io_uring,
  and not the syscalls of 32-bit (ia32) processes.
- `MSG_PEEK` reads are not captured (wineserver peeks one byte on every readable socket; the
  bytes are captured when they are read), nor `MSG_TRUNC` reads on TCP (the kernel discards
  those bytes without copying them).
- Bytes in pages not resident when the call returns (`payload_fault`) and calls that found
  the payload ring full (`payload_ring_full`) are missing; send buffers are read at the
  call's return, so another thread rewriting one during the call is seen rewritten.
- The client's pings (`IcmpSendEcho`, `IcmpSendEcho2Ex`) are not its own sockets: Wine's iphlpapi sends
  `IOCTL_NSIPROXY_WINE_ICMP_ECHO` to `\Device\Nsi`, and nsiproxy.sys opens the ICMP socket inside
  `winedevice.exe`, a Wine service outside the tracked tree. Neither the echo bytes nor its packets
  (pcapng) are captured, and the wineserver decoder records only AFD ioctls, not this one.
- DNS is parsed only from the client's own port-53 traffic: names resolved by another process
  (systemd-resolved's upstream queries, DNS-over-TLS or -HTTPS) are not seen.

**The log now holds secrets**: login tokens, passwords and chat sent without encryption,
server addresses, interface and MAC data from netlink replies, and window titles (wineserver
`get_window_text`). Bundles are marked `sensitivity=secrets` when the eBPF net sensor or the
wineserver decoder ran with payloads (otherwise `payload`); `redact_session.py` removes all of these
and marks its copy `metadata`; see docs/STORAGE.md. Record with `--no-payloads` for a log to share.

### Socket join

Under Wine, wineserver creates, connects, binds, accepts and closes the sockets and the game only
reads and writes them (the same inode; wineserver's `connect` record carries it in `value0`, the
game's I/O names `socket:[ino]`). The agent joins them in user space (`agent/linux/socket_join.h`,
fed by `agent/linux/bpf_join.inc` from the syscall records; no BPF code): a socket one tracked
process made is attributed to every other tracked process that reads or writes it.

- At that process's first I/O on the socket: a `network_flow_established` for it, with the maker's
  endpoint in `text`, the inode in `value0`, protocol and port packed in `value1`,
  `status` 0 (the maker's errno, e.g. -115 EINPROGRESS, is `creator_status`), flag and attribution
  `service_correlated`, no stack, and `detail` starting with how the maker got it (`connect;`,
  `accept;`, `bind;` or `listen;`), then `family`, `type`, `creator_pid`, `creator_start`,
  `creator_status`, `creator_time`, `first_use` (the call) and `first_use_ret`.
- Its `network_flow_close` (same `value0`, so `tools/analysis/network_timeline.py` pairs them):
  `close;service_correlated;reason=...;bytes_sent=N;bytes_received=N` and the creator fields. The
  bytes are what that process moved on the socket, without MSG_PEEK reads and sendmmsg/recvmmsg
  (which return message counts). It is written when the maker closes the socket or exits
  (`socket_closed`) or leaves scope (`untracked`), the process exits (`process_exit`) or leaves
  scope (`untracked`), the inode returns from `socket`/`accept` (`inode_reused`) or tracking stops
  (`session_end`).
- Several processes on one socket each get their own pair. The process's own closes stay plain
  `close;` records and end nothing: Wine clients close per-call fds.

One game connect thus gives the wineserver `network_connect` (`syscall=connect`), the game's request
view (`ws=ioctl`, wineserver upgrade) and the game's flow pair, with no type repeated. Coverage
note: `socket_join`.

Limits (`shortcut:` comments in `socket_join.h`): only sockets made while the agent runs are known;
a socket its maker never bound or connected (a UDP socket the game only `sendto`s on) is not joined,
nor is one whose connect failed other than with EINPROGRESS; a lost connect (ring full) leaves a
socket unjoined, a lost close of the maker delays the flow close to an exit or the agent stop, and
lost I/O records are missing from the byte totals, as are bytes
`sendfile`/`splice`/`copy_file_range` move into a socket (only their input fd is resolved; bytes
they take out of one count as received); a helper that hands its socket to another process and
closes its own fd ends the join early. 32-bit (ia32) processes make no syscall records, so their I/O
is not joined.

### TCP lifecycle

TCP connections are followed as Windows follows them with `Microsoft-Windows-TCPIP`
(`tp_btf/inet_sock_set_state`, `tcp_receive_reset`, `tcp_send_reset`, `tcp_retransmit_skb` and
`lsm/sock_graft`, group `tcp`). A socket is followed once it carries a socket tag (`socks`: a
tracked process created, connected, sent or received on it; a listener's connections carry its tag
from the handshake on; `accept()` tags the accepted socket), and its state changes, the resets it
receives and sends and its retransmissions are logged as `etw_tcp` for the tag's first tracked user,
never for whatever task the CPU was running (most of them happen in softirq context). Under Wine that
user is wineserver (it calls `connect()` and `accept()` for every process of the prefix);
`user_pid=<pid>` names the game once it sent or received on the socket, and `sock_ino` joins the
game's `socket:[ino]` records. `text` is `local -> remote`, `value0` the Windows event id (0 for
`state_change` and `retransmit`, which have none), `value1` the socket cookie (one per connection;
the packet capture's pcapng comments carry the same cookie), `status` the negative socket error.
`detail` is `event=<name>`, `from=`/`to=` (state changes) or `state=`, `sock_ino`, then `user_pid`,
`err`, `shutdown` (1 receive, 2 send side shut), `orphan=1` (no descriptor left), `reason` (resets
sent, the kernel's `sk_rst_reason` name), `rexmit` (retransmissions so far), `srtt_us`,
`bytes_acked`, `bytes_received`.

Names: `SYN_SENT -> ESTABLISHED` connect_completed; `SYN_SENT -> CLOSE` connect_failed
(connect_timeout on ETIMEDOUT, abort_issued without an error); an accept accept_completed;
`ESTABLISHED -> FIN_WAIT1` and `CLOSE_WAIT -> LAST_ACK` close_issued (`shutdown=2` is
`shutdown(SHUT_WR)`, 3 a close); `ESTABLISHED -> CLOSE_WAIT`, `FIN_WAIT1 -> CLOSING` and
`FIN_WAIT2 -> CLOSE` of a socket still open fin_received; `LAST_ACK`, `CLOSING` or a closed
`FIN_WAIT2 -> CLOSE` disconnect_completed; `-> CLOSE` after a timeout retransmit_timeout
(keepalive_timeout when nothing was being retransmitted, by `icsk_retransmits`: the kernel purges
`packets_out` before that `CLOSE`; disconnect_timeout from `FIN_WAIT1`, `CLOSING` or `LAST_ACK`);
`-> CLOSE` without an error from a data state
abort_issued (a reset_sent with its reason follows); a received RST reset_received
(`state=SYN_SENT`: the connect was refused); every other transition state_change. Retransmissions
(`connect_retransmit` in `SYN_SENT`) are collapsed per connection like syscall repeats, and the counts
still held are written before the connection's `CLOSE` record, as the generic `repeats_tail` record
(value0 0, value1 the count, not the cookie: join it by `text`, the endpoints). Records carry
`observer_record`, as on Windows. `fin_received` before the owner's
`close_issued` means the remote closed it; `reset_received` that the remote reset it.

Limits (`tcp_lifecycle` coverage record): connections no tracked process touched since tracking
began, the TIME_WAIT/FIN_WAIT2 minisocket that replaces a closed socket (the remote FIN after
`close()`, FIN-WAIT-2 timeouts) and resets sent for segments no socket owns (a SYN to a closed port)
are not seen. `--no-etw` does not turn it off; `--no-ebpf` does.

### Packet capture

The client's packets are written as pcapng beside the events: `events.pcapng` in a bundle
(`<output stem>.pcapng` otherwise), rotated at the events' part size (`--max-file-mb`) into
`events.pcapng.1`, `.2`, ... on its own byte count: `events.pcapng.N` does not cover the same time as
`events.jsonl.N`; each part's `first_utc` and `last_utc` are in its `packet_capture_part` record.
Every IP packet (TCP, UDP, ICMP of the client's own ping sockets; IPv4 and IPv6; both directions, handshakes,
retransmissions, RST and FIN included) of a socket a tracked process used is kept, up to 64 KiB per packet
(`orig_len` keeps the full length; the cut is counted as `truncated`).

- **Kernel side** (`bpf/pkt.bpf.h`, optional group `packets`): `mm_skb_egress` and `mm_skb_ingress`
  are `cgroup_skb` programs attached to the cgroup v2 root `/sys/fs/cgroup` with a BPF link
  (`BPF_F_ALLOW_MULTI`, so they run beside systemd's and kfilter's programs). They always return 1:
  traffic is never dropped or changed. A packet is copied (`bpf_skb_load_bytes`, from the IP header)
  to the 32 MiB `pkts` ring only if its socket carries an `mm_socks` tag, which the socket LSM hooks
  (`socks`) set when a tracked process creates, connects, sends or receives on it. Ring overflows are
  counted in `pkt_drops` and reported as `ring_drops`.
- **Format**: one interface, `LINKTYPE_RAW` (101), `if_tsresol` 10^-7 s (the log's FILETIME unit),
  snaplen 65536. One Enhanced Packet Block per packet with the capture time, the direction in
  `epb_flags` (1 inbound, 2 outbound) and an `opt_comment`
  `pid=<owner>;process=<comm>;socket=socket:[<inode>];cookie=<cookie>[;wineserver=<pid>][;held=1][;gso_segs=<n>][;pending_skipped=<n>]`.
  The cookie is the socket cookie: the same number is `value1` of the tcp upgrade's `etw_tcp`
  records, the join key between the two.
- **Attribution**: under Wine, wineserver creates and connects the sockets of its clients, the Nexon
  launcher's too. A socket is the game's once a tracked process other than wineserver sends or
  receives on it (the tag's `owner`). Until then the kernel captures at most 256 KiB of it
  (the rest is counted, `pending_skipped`) and the agent holds those packets (16 MiB in all; past
  it the socket held longest is dropped, counted in `held_overflow`, so a new socket's handshake is
  always kept): they are written, marked `held=1`, when the owner appears, and dropped, counted as
  `unattributed_*`, when its maker (wineserver; without one, the owner) closes it or the session
  ends; another process's close of its own per-call fd ends nothing. A close takes effect only after
  the `pkts` ring was read to its end, so a socket's last packets (a FIN that attributes it) are
  never outrun by its close event. A packet that raced the owner's first send/recv on another CPU
  (still `owner` 0) is written with the owner already known for its cookie.
- **Chain**: each closed part becomes a `packet_capture_part` coverage record (path, part, packet
  count, wire and captured bytes, file size, SHA-256, first and last time, ring drops) in the hash
  chained log; `packet_capture` totals it at the end. `packet_capture_active` at start names the
  settings; `packet_capture_unavailable` says why there is no capture (no eBPF, the group refused,
  an attach failure: then neither direction stays attached); `packet_capture_disabled` is written
  under `--no-packets` or `--no-payloads`. The parts are listed in `checksums.json` like every
  bundle file (docs/STORAGE.md).
- **Hashing**: a closed part is hashed on its own thread, so a rotation never stalls the BPF thread
  that also drains the events ring.
- **Detach**: at the end the final drain has the BPF thread destroy both links, read the `pkts`
  ring to its end and the drop count, and only then writes the `packet_capture` totals (after 5 s
  without that they carry `final_read=timed_out`). The links are also destroyed when the agent exits;
  the kernel detaches them when the agent is killed (their fds close). `tests/ebpf_checks/packets.sh`
  checks both with `bpftool cgroup show`.

Limits: a GSO/GRO super-packet is captured as one packet as the socket saw it (`gso_segs`
in the comment, `gso_packets` in the totals), not as the frames on the wire, and may exceed the MTU
and the 64 KiB cut. Packets the kernel sends for a socket that no longer has a full socket (TIME_WAIT
ACKs, RSTs for unknown ports) are not captured, nor are ICMP errors about the game's traffic (port
unreachable, fragmentation needed: the kernel handles them without the socket's receive filter) or
ICMP the kernel generates itself; only ICMP of ping sockets is, and only of the client's own: Wine's
`IcmpSendEcho` pings leave from `winedevice.exe` (nsiproxy.sys), outside the tracked tree, and are not
captured (see Socket bytes and DNS). The SYN, SYN-ACK and final ACK of a
connection the game accepts carry the listener's cookie and inode (the kernel runs the programs on
the listener): they are attributed only when the listener has an owner, and their cookie is not the
accepted socket's `etw_tcp` `value1`. The maker's close of any of its fds of a socket counts as the
socket's end for held packets. Packets of the probe's loopback exchanges appear twice (egress of one socket, ingress
of the other). pcapng parts contain the game's traffic in clear (keep them like `sensitivity=secrets`
bundles).

### Wineserver requests

Under Wine the client asks wineserver for registry access, handle opens, file creates, named
pipes and sections, enumerations and socket connects; wineserver then makes the Linux syscall, so
the syscall records name wineserver. `mm_ws_enter` copies each wanted request a tracked Wine thread
writes to its request pipe (the fds in its TEB: GS base on x86_64, the `set_thread_area` TLS entry
on ia32; the request fd must be a pipe): the 64-byte fixed part and up to 8 KiB of its data.
`mm_ws_exit` copies the reply it reads back (64 bytes, plus up to 8 KiB of data for registry
values, enumerated names, volume information and window text). `agent/linux/wineserver.cpp`
decodes protocol 930 (wine-11.0) into records of the requesting process and thread, with its user
stack and (pecaller) PE frames; `status` is the reply's NTSTATUS:

| Request | Record |
|---|---|
| `open_key`, `create_key`, `delete_key`, `enum_key`, `get_key_value`, `set_key_value`, `enum_key_value`, `delete_key_value`, `rename_key` | `registry_*`: text the full key path (handles are tracked from replies and forgotten at `close_handle` or when the handle value is given out again; an unknown one is `hkey:0x..`), detail the value name; set/query/enumerated values are `registry_value` payloads as on Windows |
| `open_process`, `open_thread`, `dup_handle` (to or from another process), `debug_process`, `get_next_process` | `process_handle` / `thread_handle`: `desired_access`, target the unix pid when the Windows pid belongs to a tracked client, detail `open_process;win_pid=N;handle=..`. Process handles are learned from `open_process` and `new_process` replies (both captured for the handle table only, with `close_handle`, which forgets a handle); one from `get_next_process` or a `dup_handle` copy names no Windows pid |
| `read_process_memory`, `write_process_memory` | `process_handle`, value0 1 / 2, value1 the length, detail with handle, `win_pid` and address |
| `create_file`, `open_file_object`, `create_named_pipe` | `file_create`: text the unix path (`create_file`) or the NT name, detail `create_file;nt=...`, value0 disposition << 24 \| options, value1 the handle |
| `create_mapping` (named only), `open_mapping` | `file_section`, value0 the `SEC_*` flags; detail `file_access` (what ntdll derived from the page protection, which wineserver never sees) |
| `get_volume_info` | `file_query_volume_information`, value0 the class, a `volume_information` payload |
| `list_processes`, `get_system_handles`, `get_window_list`, `get_window_tree`, `get_window_text`, `get_tcp_connections`, `get_udp_endpoints` | `file_query_information`, text `system:<request>`, value1 the count (`get_window_text`: the text length; `get_window_tree`: 0, detail `;parent=0x..`); `get_window_text` adds `;text=` (with payloads) or `;text_bytes=N` |
| `ioctl` AFD connect / bind / listen / accept | `network_connect` / `network_accept`: text the endpoint, value0 0, detail `connect;family=2;ws=ioctl;afd=connect;socket=..`; status the ioctl's (a pending connect is `0x103` with `;pending`: Wine completes it by APC, and netattr's `network_flow_established` gives the outcome) |

Hot requests (select, messages, ...) are not captured; repeats are collapsed as for syscalls
(pseudo syscall 1000 + request, name `wineserver:<request>`). A request whose reply never came is
written with `;no_reply` (except when the agent stops: those are not written). The decoder runs for a process only when the `ntdll.so` it maps holds the
`wine-11.0` build string (Wine refuses a server of another protocol; a client already gone when its
first request is drained gets the last `ntdll.so` seen, `;assumed=1`); the first request of each
process writes a `wineserver_decoder` coverage record (`active=1;build=wine-11.0;protocol=930;ntdll=...`),
and the session notes `wineserver_requests` or `wineserver_requests_unavailable`. With
`--no-payloads` the records keep their metadata only. Limits: a value whose captured bytes are
short of the whole (over about 8 KiB minus its name for `set_key_value`/`enum_key_value`) is
`payload_unavailable` with `payload_truncated;value=<name>` (also when a data page was not yet
faulted in at the request); a query whose buffer is smaller than the value (a size probe:
wineserver answers success) has no payload and `;buffer=N` in the detail; one over 8 KiB read back by
`get_key_value` is its first 8-KiB chunk of a partial series; keys opened before tracking or
duplicated are named by handle; no PE frames for ia32 clients.

Without the kernel sensors (`--no-ebpf`, no root, or an agent built without clang):

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.fanotify` (40/44) | fanotify mount marks: `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`; filesystem marks with `FAN_REPORT_DFID_NAME`: `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVE` | `file_read`, `file_write`, `file_close`, `file_create`, `file_set_information` (value0 13 = unlink, 10 = rename; detail `unlink`, `rename;from`, `rename;to`) |
| `linux.proc_connector` (41/45) | netlink process-events connector | `process_start` (fork from a tracked process = inherited; exec of an image under a root = explicit; a tracked exec is logged again with value1 = 1), `process_exit` |
| `linux.maps_poll` (42/46) | `/proc/<pid>/maps` on track, on an executable file mmap/mprotect, and every 2 s (also with the kernel sensors) | `image_load` per executable file mapping (value0 base, value1 span) |
| `linux.net_poll` (43/47) | `/proc/net/{tcp,tcp6,udp,udp6}` every 1 s, owners via `/proc/<pid>/fd` | `network_connect`, `network_accept`, `network_flow_close` (value0 socket inode) |

Process identity is PID plus start time (from `/proc/<pid>/stat`, in FILETIME units).
Paths come from the event fd (`/proc/self/fd`) or the directory handle plus name; an
unresolved path sets `missing_path` (the entry name stays in the detail).

## Coverage limits

Written as coverage records at session start and listed here.

With the kernel sensors:

- File contents are not captured; work done inside the kernel, page faults on existing
  mappings and io_uring worker I/O have no syscall record. The upgrades above list their own
  limits.
- Without the wineserver decoder, Wine's registry is file-level (the prefix's `*.reg` files),
  not per key.
- Paths of 256 bytes or more are truncated (`truncated_path`).
- Loading and verifying the BPF programs takes a few seconds; the agent prints
  `Registered` once they are live.

Without them:

- fanotify events carry no byte counts, offsets, open flags or status; those fields are 0.
  The kernel merges queued events on one object; a queue overflow is counted as a drop
  (sequence gap).
- Sockets are polled once a second: shorter-lived sockets are missed, the first poll reports
  already-open sockets, and timestamps are poll times.
- Executable mappings are polled every 2 s; a library mapped and unmapped in between is missed.
  An executable file mmap or `mprotect` triggers an extra scan, so a newly loaded module is
  recorded at once even though the periodic poll still owns `image_load` under eBPF.
- `registry_unavailable`, `etw_unavailable`, `blackcat_not_applicable`: no key-level registry, ETW
  (WMI/DNS/RPC/TCPIP/CodeIntegrity) or BlackCat sensors exist. The Windows driver's
  registration slots (20-38) are reported failed with ENOSYS.
- `payload_unavailable`: there are no registry values or volume-information queries to
  capture. Hardware identity appears as file events on `/sys/class/dmi/id/*`,
  `/proc/cpuinfo`, `/sys/block/*/serial` (classified `hardware_identity`).
- No thread, handle, stack attribution, memory or payload sensors.
- Without root, only processes running at start (or `--pid`) are tracked; their children
  are not.

## KFilter

The agent reads kfilterd over `/run/kfilter.sock` (see `kernel-filter/linux/kfilter_socket.h`):
`GET_STATUS` (0x800) and `READ_EVENTS` (0x802), ABI 5 structures with 32-bit fields and
4-byte `wchar_t`. If the socket is absent the session records `kfilter_unavailable`.

## Windows-only parts

Not ported: `driver/`, `compat/`, `tools/windows-test/`, the PowerShell tests in `tests/`
and `tests/fixtures/`, `build.cmd`, `tests/integration_regression.cmd`.
`tools/analyze_client.py` parses PE images only; ELF files are counted and reported as an
`elf_inventory` gap. The scenario files in `tests/scenarios/` name Windows sensors.
