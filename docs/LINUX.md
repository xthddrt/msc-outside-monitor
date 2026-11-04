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

Root-only check (run it in a VM): `sudo tests/linux_ebpf_test.sh`.

## Run

```sh
sudo build/linux/msmon-agent --client ~/.wine-nexon/drive_c/Nexon/Library/maplestorycw --log-dir /var/tmp/msmon-sessions
sudo build/linux/msmon-agent --pid 1234 --log-dir /var/tmp/msmon-sessions --once
```

Under Wine `/proc/<pid>/exe` is the Wine loader, never `MapleStory.exe`. A process is in
scope when its image is under a root, when it has an executable file mapping under a
root (checked in the kernel at `mmap`, and in `/proc/<pid>/maps`), when its `WINEPREFIX`
(default `$HOME/.wine`) is the client's prefix, or when it descends from a process in
scope. The prefix is the nearest folder above `--client` that holds `system.reg`, or
`--prefix DIR`. `/proc` is rescanned every second for processes that started outside the
tracked tree (a wineserver started earlier, a service started by another Wine program).
The prefix is a snapshot root: the `*.reg` files wineserver saves (it writes a temporary
file and renames it into place) are copied into the session, up to 16 MiB each.

`--no-ebpf` keeps the kernel sensors off.

`MapleStory.exe` is not required: any `--client`/`--scope-root` directory with an
executable file directly inside it is accepted (the first by name is hashed as the
client), or `--pid`. Paths are used as given (absolute, case-sensitive). Stop with
Ctrl+C, SIGTERM or `--stop-file`.

Root is needed for the kernel sensors (CAP_BPF, CAP_PERFMON, CAP_MAC_ADMIN for the LSM
hooks), for fanotify and for the process-events connector (CAP_SYS_ADMIN, CAP_NET_ADMIN,
CAP_DAC_READ_SEARCH). Without it the agent still runs and writes a valid,
chain-verified log, but records `fanotify_unavailable` / `proc_connector_unavailable` and
marks those registrations failed in `coverage.json`; only `/proc` polling (images and
sockets of your own processes) is active.

## Sensors

With root and a BPF-capable kernel the kernel sensors are used, and the user-space sensors
of the classes they cover are not started (coverage notes `*_superseded`):

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.ebpf_process` (48/54) | `tp_btf/task_newtask` (tracking copied before the child runs), `sched_process_fork/exec/exit`, `lsm/mmap_file` (an untracked process mapping an executable under the root joins the scope) | `process_start` (fork = inherited; exec = value1 1 with the image and argv), `process_exit`, `thread_start`, `thread_exit` |
| `linux.ebpf_file` (49/55) | `tp_btf/sys_enter` + `sys_exit` for 85 syscalls of tracked processes | `file_create` (open*, mkdir, mknod), `file_read`/`file_write` (value0 bytes transferred, value1 offset), `file_close`, `file_set_information` (unlink 13, rename 10 as `rename;from`/`rename;to`, link 11, truncate 20), `file_set_security` (chmod/chown/utimes), `file_query_information` (stat, access, readlink, statfs), `file_directory_control` (getdents, value1 bytes), `file_set_ea`/`file_query_ea` |
| `linux.ebpf_net` (50/56) | the same syscalls on sockets | `network_connect` (connect, sendto with an address), `network_accept` (accept, recvfrom with a source), `network_flow_close` (close of a socket; value0 socket inode) |
| `linux.ebpf_ipc` (51/57) | AF_UNIX connect/accept, kill/tkill/tgkill | `network_connect`/`network_accept` with `unix:` endpoints, `process_handle` (`signal=N`, target_process_id) |
| `linux.ebpf_device` (52/58) | ioctl | `file_device_control` (value0 request, value1 argument) |
| `linux.ebpf_memory` (53/59) | mmap, mprotect, ptrace, process_vm_readv/writev; `lsm/ptrace_access_check`, `lsm/bpf`, `lsm/perf_event_open` | `file_section` (file or executable mappings; value0 flags, value1 protection), `image_load` (each executable file mapping, so stacks resolve), `process_handle` (ptrace request or VM read/write, target_process_id); the tracked tree is refused ptrace of the agent, `bpf()` and `perf_event_open` (`self_protection_denied=` records) |

Every syscall record carries the syscall name, all six arguments, the result and the
duration in `detail`, the thread in `thread_id`, the negative errno in `status`, and up to
8 user return addresses as the stack (resolved against `image_load` ranges into `modules`).
Paths are rebuilt in the kernel from the task's dentries and its fd table, cwd or dirfd
(pipes, sockets and anonymous inodes are named `pipe:[ino]`, `socket:[ino]`,
`anon_inode:[ino]`); a path the kernel could not resolve falls back to the agent's fd table.
When the ring is full a record is dropped and counted as a sequence gap.

Without the kernel sensors (`--no-ebpf`, no root, or an agent built without clang):

| Sensor (slot) | Source | Records |
|---|---|---|
| `linux.fanotify` (40/44) | fanotify mount marks: `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`; filesystem marks with `FAN_REPORT_DFID_NAME`: `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVE` | `file_read`, `file_write`, `file_close`, `file_create`, `file_set_information` (value0 13 = unlink, 10 = rename; detail `unlink`, `rename;from`, `rename;to`) |
| `linux.proc_connector` (41/45) | netlink process-events connector | `process_start` (fork from a tracked process = inherited; exec of an image under a root = explicit; a tracked exec is logged again with value1 = 1), `process_exit` |
| `linux.maps_poll` (42/46) | `/proc/<pid>/maps` on track and every 2 s | `image_load` per executable file mapping (value0 base, value1 span) |
| `linux.net_poll` (43/47) | `/proc/net/{tcp,tcp6,udp,udp6}` every 1 s, owners via `/proc/<pid>/fd` | `network_connect`, `network_accept`, `network_flow_close` (value0 socket inode) |

Process identity is PID plus start time (from `/proc/<pid>/stat`, in FILETIME units).
Paths come from the event fd (`/proc/self/fd`) or the directory handle plus name; an
unresolved path sets `missing_path` (the entry name stays in the detail).

## Coverage limits

Written as coverage records at session start and listed here.

With the kernel sensors:

- File and network contents are not captured; work done inside the kernel, page faults on
  existing mappings and io_uring worker I/O have no syscall record.
- Wine's registry lives in wineserver: registry activity is file-level (the prefix's
  `*.reg` files), not per key.
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
