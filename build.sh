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
         agent/linux/images.cpp agent/linux/net.cpp)

"$cxx" "${flags[@]}" -o "$out/msmon-agent" agent/agent.cpp "${shared[@]}" "${sensors[@]}"
"$cxx" "${flags[@]}" -o "$out/integration_regression" tests/integration_regression.cpp "${shared[@]}"
python3 tools/check_sensor_map.py

"$out/integration_regression"
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
