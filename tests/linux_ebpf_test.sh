#!/bin/sh
# Runtime check of the eBPF sensors (needs root; run in a VM: `sudo tests/linux_ebpf_test.sh`
# after ./build.sh). The agent watches a temporary scope; a probe started there does one of
# each action and must be recorded with byte counts, a failing status, kernel paths and
# resolved stacks. Then the same probe under --no-ebpf must still be recorded by the
# fanotify/proc-connector sensors, and the existing proc connector test must pass with it.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -x build/linux/linux_ebpf_probe ] || { echo "build first (./build.sh)"; exit 2; }
work=$(mktemp -d)
trap 'if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi' EXIT
fail=0
# Each kernel-sensor upgrade keeps its part of this test in tests/ebpf_checks/<upgrade>.sh (functions
# <upgrade>_session, run in every session after the probe while the agent still runs, and <upgrade>_end,
# run after all sessions; they may set fail=1) and check_<upgrade>.py (check(), run by check()).
upgrades="pecaller payload netattr tcp packets wineserver"
for upgrade in $upgrades; do . "tests/ebpf_checks/$upgrade.sh"; done

run_session() {   # $1 = name, rest = agent flags
    name=$1
    shift
    scope="$work/$name/scope"
    mkdir -p "$scope/files"
    cp build/linux/linux_ebpf_probe "$scope/probe"
    build/linux/msmon-agent --scope-root "$scope" --output "$work/$name/events.jsonl" --stop-file "$work/$name/stop" \
        --wait-ms 100 --no-etw "$@" >"$work/$name/agent.log" 2>&1 &
    agent=$!
    # Loading and verifying the BPF programs takes a few seconds; the agent prints
    # "Registered" once its sensors are live.
    for _ in $(seq 1 60); do grep -q Registered "$work/$name/agent.log" && break; sleep 0.5; done
    "$scope/probe" "$scope/files" || { echo "FAIL $name: probe exited $?"; fail=1; }
    for upgrade in $upgrades; do "${upgrade}_session"; done
    sleep 2
    touch "$work/$name/stop"
    wait "$agent" || { echo "FAIL $name: agent exited $?"; cat "$work/$name/agent.log"; fail=1; }
    python3 tools/verify_log.py "$work/$name/events.jsonl" >"$work/$name/verify.json" ||
        { echo "FAIL $name: verify_log rejected the log"; fail=1; }
}

check() {   # $1 = name, $2 = mode (ebpf | nopayloads | fallback)
    # On failure show the end of the agent's stderr (libbpf and the verifier log land there).
    python3 - "$work/$1/events.jsonl" "$2" "$work/$1/scope/probe" <<'PY' || { fail=1; echo "--- $1 agent.log (tail)"; tail -n 80 "$work/$1/agent.log"; }
import json, sys
path, mode, probe = sys.argv[1:4]
events = [json.loads(line) for line in open(path) if line.strip()]
coverage = {e["text"] for e in events if e.get("type") == "coverage"}
pids = {e["process_id"] for e in events if e["type"] == "process_start" and probe in (e.get("text", "") + e.get("process_path", ""))}
# The probe's forked child is tracked as inherited.
pids |= {e["process_id"] for e in events if e["type"] == "process_start" and e.get("parent_process_id") in pids}
mine = [e for e in events if e.get("process_id") in pids]
def has(kind, test=lambda e: True):
    return any(e["type"] == kind and test(e) for e in mine)
problems = []
if not pids:
    problems.append("the probe was not tracked")
expect = {
    "file_create": lambda e: e["text"].endswith("/probe-a.txt"),
    "file_write": lambda e: e["value0"] > 0 or mode == "fallback",
    "file_read": lambda e: e["value0"] > 0 or mode == "fallback",
    "file_set_information": lambda e: "unlink" in e["detail"],
}
if mode in ("ebpf", "nopayloads"):
    expect.update({
        "file_close": lambda e: e["text"].endswith("/probe-a.txt"),
        "file_set_security": lambda e: e["text"].endswith("/probe-b.txt"),
        "file_section": lambda e: e["text"].endswith("/probe-b.txt") and e["value1"] & 4,
        "image_load": lambda e: e["text"].endswith("/probe-b.txt"),
        "network_connect": lambda e: e["text"].startswith("127.0.0.1:"),
        "network_accept": lambda e: e["text"].startswith("127.0.0.1:"),
        "network_flow_close": lambda e: True,
        "thread_start": lambda e: True,
        "thread_exit": lambda e: True,
        "process_exit": lambda e: True,
        "process_handle": lambda e: "process_vm_readv" in e["detail"],
    })
    if "ebpf_active" not in coverage:
        problems.append("no ebpf_active coverage record")
    if not any(e["type"] == "file_set_information" and "rename;to" in e["detail"] and e["text"].endswith("/probe-b.txt") for e in mine):
        problems.append("no rename;to record for probe-b.txt")
    if not any(e["type"] == "file_create" and e["status"] != 0 and e["text"].endswith("probe-missing.txt") for e in mine):
        problems.append("the failed open has no nonzero status")
    if not any(e.get("stack_frames", 0) > 0 and e["modules"] for e in mine):
        problems.append("no stack resolved to a module")
    if not any(e["type"] == "process_start" and e["value1"] == 0 and e.get("flags", 0) & 2 for e in mine):
        problems.append("the forked child was not tracked as inherited")
    # 100 preads of probe-burst.txt: a few full records, the rest counted, nothing lost.
    import re
    def count(e, key):
        found = re.search(key + r"=(\d+)", e["detail"])
        return int(found.group(1)) if found else 0
    burst = [e for e in mine if e["type"] == "file_read" and e["text"].endswith("/probe-burst.txt") and "pread64" in e["detail"]]
    total = sum(1 + count(e, "repeats_before") for e in burst if "repeats_tail" not in e["detail"])
    total += sum(count(e, "repeats_before") for e in burst if "repeats_tail" in e["detail"])
    if total != 100 or len(burst) > 20:
        problems.append("burst: %d pread records accounting for %d calls (want 100 calls in <= 20 records)" % (len(burst), total))
    opens = [e for e in mine if e["type"] == "file_create" and e["text"].endswith("/probe-burst.txt") and e["value0"] == 0]
    if not any(e["status"] == 0 for e in opens) or not any(e["status"] != 0 for e in opens):
        problems.append("the failing repeat of a successful open was not recorded")
    for word in ("bind;", "listen;"):
        if not any(e["type"] == "network_accept" and e["detail"].startswith(word) for e in mine):
            problems.append("no " + word + " record")
    if not any(e["type"] == "network_connect" and "sendmsg;" in e["detail"] and e["text"].startswith("127.0.0.1:") for e in mine):
        problems.append("no sendmsg record with its UDP peer")
    if not any(e["type"] == "network_accept" and "recvmsg;" in e["detail"] and e["text"].startswith("127.0.0.1:") for e in mine):
        problems.append("no recvmsg record with its UDP source")
    if not any(e["type"] == "process_handle" and e["detail"].startswith("prctl;") for e in mine):
        problems.append("no prctl record")
    if not any(e["type"] == "process_handle" and e["detail"].startswith("pidfd_open;") for e in mine):
        problems.append("no pidfd_open record")
    news = {
        "uname": lambda e: e["type"] == "file_query_information" and e["text"] == "system:uname" and e["category"] == "hardware_identity",
        "sysinfo": lambda e: e["type"] == "file_query_information" and e["text"] == "system:sysinfo",
        "socket": lambda e: e["type"] == "file_create" and e["detail"].startswith("socket;family=2;type=1;") and e["text"].startswith("socket:["),
        "shutdown": lambda e: e["type"] == "network_flow_close" and e["detail"].startswith("shutdown;how=1;"),
        "inotify_add_watch": lambda e: e["type"] == "file_directory_control" and e["detail"].startswith("inotify_add_watch;") and e["text"].endswith("/files"),
        "memfd_create": lambda e: e["type"] == "file_create" and "syscall=memfd_create" in e["detail"] and "probe-memfd" in e["text"],
        "fsync": lambda e: e["type"] == "file_flush" and e["text"].endswith("/probe-sync.txt"),
        "shmget": lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:key="),
        "shmat": lambda e: e["type"] == "file_section" and e["text"].startswith("sysv_shm:id="),
    }
    for name, test in news.items():
        if not any(test(e) for e in mine):
            problems.append("no " + name + " record")
    native = {e["process_id"] for e in mine if e["type"] == "process_exit" and "untracked;native_exec" in e["detail"]}
    if not native:
        problems.append("the child that exec'd /bin/true was not untracked")
    elif any(e["process_id"] in native and e["type"].startswith("file_") for e in mine):
        problems.append("records from /bin/true after it left scope")
else:
    if "bpf_unavailable" not in coverage:
        problems.append("no bpf_unavailable coverage record under --no-ebpf")
    if "ebpf_active" in coverage:
        problems.append("ebpf_active although --no-ebpf was given")
for kind, test in expect.items():
    if not has(kind, test):
        problems.append("no " + kind)
import importlib
sys.path.insert(0, "tests/ebpf_checks")
for upgrade in ("pecaller", "payload", "netattr", "tcp", "packets", "wineserver"):
    importlib.import_module("check_" + upgrade).check(mode, path, events, mine, pids, coverage, problems)
for problem in problems:
    print("FAIL %s: %s" % (mode, problem))
print("%s: %d records, %d from the probe" % (mode, len(events), len(mine)))
sys.exit(1 if problems else 0)
PY
}

run_session ebpf
check ebpf ebpf
run_session nopayloads --no-payloads
check nopayloads nopayloads
run_session fallback --no-ebpf
check fallback fallback
MSMON_AGENT_ARGS=--no-ebpf sh tests/linux_proc_connector_test.sh || { echo "FAIL proc connector test under --no-ebpf"; fail=1; }

for upgrade in $upgrades; do "${upgrade}_end"; done

[ "$fail" = 0 ] && echo "linux ebpf test: PASS" || echo "linux ebpf test: FAIL"
exit "$fail"
