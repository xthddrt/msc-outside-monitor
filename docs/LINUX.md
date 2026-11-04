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

## Run

```sh
sudo build/linux/msmon-agent --client /opt/client --log-dir /var/tmp/msmon-sessions
sudo build/linux/msmon-agent --pid 1234 --log-dir /var/tmp/msmon-sessions --once
```

`MapleStory.exe` is not required: any `--client`/`--scope-root` directory with an
executable file directly inside it is accepted (the first by name is hashed as the
client), or `--pid`. Paths are used as given (absolute, case-sensitive). Stop with
Ctrl+C, SIGTERM or `--stop-file`.

Root (CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH) is needed for fanotify and the
process-events connector. Without it the agent still runs and writes a valid,
chain-verified log, but records `fanotify_unavailable` / `proc_connector_unavailable` and
marks those registrations failed in `coverage.json`; only `/proc` polling (images and
sockets of your own processes) is active.

## Sensors

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

Written as coverage records at session start and listed here:

- fanotify events carry no byte counts, offsets, open flags or status; those fields are 0.
  The kernel merges queued events on one object; a queue overflow is counted as a drop
  (sequence gap).
- Sockets are polled once a second: shorter-lived sockets are missed, the first poll reports
  already-open sockets, and timestamps are poll times.
- Executable mappings are polled every 2 s; a library mapped and unmapped in between is missed.
- `registry_unavailable`, `etw_unavailable`, `blackcat_not_applicable`: no registry, ETW
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
