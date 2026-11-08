#!/bin/sh
# End-to-end check with real Wine (root only; run in a VM: `sudo tests/linux_wine_test.sh` after ./build.sh).
# A fresh temporary WINEPREFIX owned by the invoking user ($SUDO_USER) is initialised, copies of Wine's
# reg.exe and tasklist.exe go into a scope directory, and the agent records `reg query`, `reg add` and
# `tasklist` run there. Every Wine command runs as $SUDO_USER, never as root. The log must verify and hold
# the wineserver-decoded registry and process-enumeration records of those processes, PE frames in their
# modules, and the decoder's coverage notes. The prefix and its wineserver are removed at the end.
# WINE_ROOT (default /opt/wine-stable) points at another Wine 11.0 install.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 2; }
user=${SUDO_USER:-}
[ -n "$user" ] && [ "$user" != root ] || { echo "run through sudo from a normal user: Wine never runs as root here"; exit 2; }
wine_root=${WINE_ROOT:-/opt/wine-stable}
[ -x "$wine_root/bin/wine" ] || { echo "no Wine at $wine_root (set WINE_ROOT)"; exit 2; }
[ -x build/linux/msmon-agent ] || { echo "build first (./build.sh)"; exit 2; }

work=$(runuser -u "$user" -- mktemp -d /tmp/msmon-wine.XXXXXX) || exit 2
prefix=$work/prefix
scope=$work/scope
out=$work/out
agent=
# A clean environment: no DISPLAY (no window), no Mono/Gecko prompts, nothing in the user's real HOME.
runw() {
    runuser -u "$user" -- env -i HOME="$work/home" USER="$user" PATH="$wine_root/bin:/usr/bin:/bin" \
        WINEPREFIX="$prefix" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree=;mshtml=;winemenubuilder.exe=d" "$@"
}
cleanup() {
    [ -n "$agent" ] && kill "$agent" 2>/dev/null
    runw timeout 30 wineserver -k >/dev/null 2>&1
    if [ -n "${MSMON_KEEP_WORK:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail=0

runw mkdir -p "$work/home" "$scope"
mkdir -p "$out"
if ! runw timeout 600 wineboot -i >"$work/wineboot.log" 2>&1 || ! runw timeout 120 wineserver -w ||
    [ ! -f "$prefix/system.reg" ]; then
    echo "FAIL: wineboot -i did not create $prefix"; tail -n 20 "$work/wineboot.log"; exit 1
fi
# Wine swaps a file carrying the "Wine builtin DLL" signature (DOS stub, offset 0x40) for its own copy in
# lib/wine, so the process would map nothing under the scope. Overwriting the signature makes Wine load
# the scope copy as a native PE; the code is unchanged.
for exe in reg.exe tasklist.exe; do
    runw cp "$wine_root/lib/wine/x86_64-windows/$exe" "$scope/$exe" &&
        printf 'msmon test copy\0' | runw dd of="$scope/$exe" bs=1 seek=64 conv=notrunc status=none &&
        runw chmod +x "$scope/$exe" ||
        { echo "FAIL: cannot copy $exe into the scope"; exit 1; }
done

build/linux/msmon-agent --scope-root "$scope" --prefix "$prefix" --output "$out/events.jsonl" --stop-file "$out/stop" \
    --wait-ms 100 --no-etw >"$out/agent.log" 2>&1 &
agent=$!
for _ in $(seq 1 60); do grep -q Registered "$out/agent.log" && break; sleep 0.5; done
grep -q Registered "$out/agent.log" || { echo "FAIL: the agent did not register"; tail -n 40 "$out/agent.log"; exit 1; }

runw timeout 120 wine "$scope/reg.exe" query 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' /v ProductName \
    >"$out/query.txt" 2>&1 || { echo "FAIL: reg query exited $?"; cat "$out/query.txt"; fail=1; }
runw timeout 120 wine "$scope/reg.exe" add 'HKCU\Software\MsmonTest' /v probe /d hello /f >"$out/add.txt" 2>&1 ||
    { echo "FAIL: reg add exited $?"; cat "$out/add.txt"; fail=1; }
runw timeout 120 wine "$scope/tasklist.exe" >"$out/tasklist.txt" 2>&1 ||
    { echo "FAIL: tasklist exited $?"; cat "$out/tasklist.txt"; fail=1; }
runw timeout 60 wineserver -w
sleep 2
touch "$out/stop"
wait "$agent" || { echo "FAIL: agent exited $?"; tail -n 40 "$out/agent.log"; fail=1; }
agent=
python3 tools/verify_log.py "$out/events.jsonl" >"$out/verify.json" || { echo "FAIL: verify_log rejected the log"; fail=1; }

python3 - "$out/events.jsonl" "$out/query.txt" <<'PY' || { fail=1; echo "--- agent.log (tail)"; tail -n 40 "$out/agent.log"; }
import base64, json, re, sys
path, query = sys.argv[1:3]
events = [json.loads(line) for line in open(path) if line.strip()]
printed = open(query, errors="replace").read()
problems = []


def pids(name):
    """The Wine processes that mapped the scope copy of name (under Wine the image is the loader)."""
    return {e["process_id"] for e in events if e["type"] == "image_load" and e.get("text", "").endswith("/scope/" + name)}


def value(e):
    """The registry value as text: the agent's decoded_value, else the payload; None without one."""
    if isinstance(e.get("decoded_value"), str):
        return e["decoded_value"].rstrip("\0")
    if "payload" in e:
        return base64.b64decode(e["payload"]["data"]).decode("utf-16-le", "replace").rstrip("\0")
    return None


def key(e, tail):
    return e.get("text", "").lower().endswith(tail.lower())


def name(e):
    return e.get("detail", "").split(";")[0]


reg, tasklist = pids("reg.exe"), pids("tasklist.exe")
if not reg:
    problems.append("no image_load of scope/reg.exe: reg.exe was not tracked")
if not tasklist:
    problems.append("no image_load of scope/tasklist.exe: tasklist.exe was not tracked")
mine = [e for e in events if e.get("process_id") in reg | tasklist]
of_reg = [e for e in mine if e["process_id"] in reg]
current = r"\Software\Microsoft\Windows NT\CurrentVersion"
expect = {
    "registry_open of HKLM" + current: lambda e: e["type"] == "registry_open" and key(e, current) and e["status"] == 0,
    "registry_query of ProductName with the value reg.exe printed": lambda e: e["type"] == "registry_query" and
        key(e, current) and name(e) == "ProductName" and bool(value(e)) and value(e) in printed,
    r"registry_create or registry_open of HKCU\Software\MsmonTest": lambda e: e["type"] in ("registry_create", "registry_open")
        and key(e, r"\Software\MsmonTest") and e["status"] == 0,
    "registry_set_value of probe = hello (REG_SZ)": lambda e: e["type"] == "registry_set_value" and
        key(e, r"\Software\MsmonTest") and name(e) == "probe" and value(e) == "hello" and e["value1"] == 1,
}
for what, test in expect.items():
    if not any(test(e) for e in of_reg):
        problems.append("reg.exe: no " + what)
if not any(e["type"] == "file_query_information" and e.get("text") == "system:list_processes" and e["process_id"] in tasklist
           for e in mine):
    problems.append("tasklist.exe: no file_query_information system:list_processes (process enumeration)")


def pe_frames(e):
    found = re.search(r";pe_frames=(\d+)", e.get("detail", ""))
    return int(found.group(1)) if found else 0


if not any(pe_frames(e) and any(m.lower().endswith((".exe", ".dll")) for m in e.get("modules") or []) for e in mine):
    problems.append("no record of reg.exe/tasklist.exe with pe_frames and a PE module (.exe/.dll) in modules")
notes = {e["text"]: e.get("detail", "") for e in events if e["type"] == "coverage"}
if ";wineserver=on" not in notes.get("ebpf_active", ""):
    problems.append("ebpf_active does not say wineserver=on: %s" % notes.get("ebpf_active"))
if "protocol=930" not in notes.get("wineserver_requests", ""):
    problems.append("no wineserver_requests coverage note (unavailable: %s)" % notes.get("wineserver_requests_unavailable"))
if not any(e["type"] == "coverage" and e["text"] == "wineserver_decoder" and "active=1" in e.get("detail", "")
           and e["process_id"] in reg for e in events):
    problems.append("no wineserver_decoder coverage record with active=1 for reg.exe")
for problem in problems:
    print("FAIL wine: " + problem)
if problems:
    kinds = {}
    for e in mine:
        kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    print("records of reg.exe/tasklist.exe by type: %s" % kinds)
    for e in of_reg:
        if e["type"].startswith("registry_"):
            print("  %s %s [%s] status=%s value=%r" % (e["type"], e.get("text"), e.get("detail", "")[:60], e.get("status"), value(e)))
print("wine: %d records, %d from reg.exe/tasklist.exe" % (len(events), len(mine)))
sys.exit(1 if problems else 0)
PY

[ "$fail" = 0 ] && echo "linux wine test: PASS" || echo "linux wine test: FAIL"
exit "$fail"
