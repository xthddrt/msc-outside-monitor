#!/usr/bin/env bash
# Linux build (see docs/LINUX.md): the agent with its in-process sensors into build/linux/,
# then the offline checks that integration_regression.cmd runs on Windows.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
out=build/linux
mkdir -p "$out" build/tests
cxx="${CXX:-g++}"
flags=(-std=c++17 -O2 -Wall -Wextra -pthread)
shared=(agent/telemetry.cpp agent/classify.cpp agent/integrations.cpp agent/rpc_names.cpp agent/etw.cpp
        agent/linux/etw_stub.cpp agent/linux/platform.cpp)
sensors=(agent/linux/session.cpp agent/linux/fanotify.cpp agent/linux/proc_connector.cpp
         agent/linux/images.cpp agent/linux/net.cpp agent/linux/bpf.cpp
         agent/linux/pe.cpp agent/linux/dns.cpp agent/linux/packets.cpp agent/linux/wineserver.cpp)

# eBPF preflight: clang (CLANG=), bpftool (BPFTOOL=), libbpf headers (LIBBPF_INCLUDE=) and the
# running kernel's BTF. Without them the agent is built without its kernel sensors and falls back
# to fanotify, the proc connector and /proc polling.
clang="${CLANG:-$(command -v clang-18 || command -v clang || true)}"
bpftool="${BPFTOOL:-$(command -v bpftool || { [ -x /usr/sbin/bpftool ] && echo /usr/sbin/bpftool; } || true)}"
libbpf_include="${LIBBPF_INCLUDE:-/usr/include}"
bpf_flags=()
if [ -n "$clang" ] && [ -n "$bpftool" ] && [ -f "$libbpf_include/bpf/libbpf.h" ] && [ -r /sys/kernel/btf/vmlinux ]; then
    mkdir -p "$out/bpf"
    "$bpftool" btf dump file /sys/kernel/btf/vmlinux format c > "$out/bpf/vmlinux.h"
    "$clang" -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wno-missing-declarations -I "$out/bpf" -I "$libbpf_include" \
        -c agent/linux/bpf/monitor.bpf.c -o "$out/bpf/monitor.debug.o"
    "$bpftool" gen object "$out/bpf/monitor.bpf.o" "$out/bpf/monitor.debug.o"
    python3 - "$out/bpf/monitor.bpf.o" "$out/bpf/monitor_bpf_object.h" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
rows = ",\n".join(",".join(str(b) for b in data[i:i + 32]) for i in range(0, len(data), 32))
open(sys.argv[2], "w").write("static const unsigned char kMonitorBpfObject[] = {\n" + rows + "\n};\n")
PY
    if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so ] || [ -n "${LIBBPF_LIB:-}" ]; then libbpf_link="${LIBBPF_LIB:--lbpf}"; else libbpf_link=-l:libbpf.so.1; fi
    bpf_flags=(-DMSMON_BPF -I "$out/bpf" -I "$libbpf_include" "$libbpf_link")
    echo "eBPF sensors: built ($out/bpf/monitor.bpf.o)"
else
    echo "eBPF sensors: NOT built (need clang, bpftool, libbpf headers and /sys/kernel/btf/vmlinux):" >&2
    echo "  sudo apt install clang-18 libbpf-dev linux-tools-common linux-tools-\$(uname -r)" >&2
fi

"$cxx" "${flags[@]}" -o "$out/msmon-agent" agent/agent.cpp "${shared[@]}" "${sensors[@]}" "${bpf_flags[@]}"
# The action probe tests/linux_ebpf_test.sh runs as root.
"${CC:-gcc}" -O2 -Wall -pthread -o "$out/linux_ebpf_probe" tests/fixtures/linux_ebpf_probe.c
"$cxx" "${flags[@]}" -o "$out/integration_regression" tests/integration_regression.cpp "${shared[@]}"
python3 tools/check_sensor_map.py

"$out/integration_regression"
# Kernel-sensor upgrade checks: each upgrade adds its lines between its own two markers only.
# >>> pecaller
"$cxx" "${flags[@]}" -o "$out/linux_pe_test" tests/linux_pe_test.cpp agent/linux/pe.cpp && "$out/linux_pe_test"
# <<< pecaller
# >>> payload
"$cxx" "${flags[@]}" -DMSMON_DNS_SELF_TEST -o build/tests/dns_self_test agent/linux/dns.cpp
build/tests/dns_self_test
# <<< payload
# >>> netattr
# Two commands, not "a && b": under set -e a failed compile inside && would not stop the build.
"$cxx" "${flags[@]}" -o build/tests/socket_join_test tests/socket_join_test.cpp
build/tests/socket_join_test
# <<< netattr
# >>> tcp
# <<< tcp
# >>> packets
"$cxx" "${flags[@]}" -o "$out/linux_packets_test" tests/linux_packets_test.cpp agent/linux/packets.cpp "${shared[@]}"
# <<< packets
# >>> wineserver
"$cxx" "${flags[@]}" -o "$out/wineserver_test" tests/wineserver_test.cpp agent/linux/wineserver.cpp "${shared[@]}"
"$out/wineserver_test"
# The fake Wine clients tests/ebpf_checks/wineserver.sh runs as root (freestanding: no 32-bit libc needed).
fake=(-O2 -Wall -static -nostdlib -ffreestanding -fno-stack-protector -fno-pie -no-pie)
"${CC:-gcc}" "${fake[@]}" -o "$out/ws_fake_client" tests/fixtures/ws_fake_client.c
"${CC:-gcc}" -m32 "${fake[@]}" -o "$out/ws_fake_client32" tests/fixtures/ws_fake_client.c 2>/dev/null ||
    { rm -f "$out/ws_fake_client32"; echo "ws_fake_client32: not built (gcc -m32 failed); the root test skips the ia32 client"; }
# <<< wineserver
python3 tools/analysis/identity_log.py --self-test
for test in tests/*_test.py; do python3 "$test"; done

# verify_log gate: the regression log has 3 events and no gap; a truncated copy must fail it.
gate() {
    python3 tools/verify_log.py "$1" > build/tests/verify_log.json &&
    python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(r["events"] != 3 or r["missing_events"] != 0)' \
        build/tests/verify_log.json
}
gate build/tests/integration-events.jsonl
head -n -1 build/tests/integration-events.jsonl > build/tests/integration-events-bad.jsonl
if gate build/tests/integration-events-bad.jsonl; then
    echo "[fail] verify_log gate accepted a truncated log" >&2
    exit 1
fi
sh tests/linux_proc_connector_test.sh
echo "linux build and checks passed: $out/msmon-agent"
