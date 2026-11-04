#!/bin/sh
# Regression for the process-events connector: the agent must track a process that
# starts after the session, so a session no longer depends on the client already
# running when the agent starts.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp /bin/sleep "$work/client"

./build/linux/msmon-agent --scope-root "$work" --output "$work/events.jsonl" \
    --stop-file "$work/stop" --wait-ms 200 >/dev/null 2>&1 &
agent=$!
sleep 2
"$work/client" 3 &
client=$!
sleep 2
touch "$work/stop"
wait "$agent"

if ! grep -q '"type":"process_start"' "$work/events.jsonl"; then
    echo "proc connector test: no process_start for a process started after the session" >&2
    exit 1
fi
if grep -q 'proc_connector_unavailable' "$work/events.jsonl"; then
    echo "proc connector test: the agent reported the connector unavailable" >&2
    exit 1
fi
if ! grep -q "\"process_id\":$client" "$work/events.jsonl"; then
    echo "proc connector test: no record for the started client pid $client" >&2
    exit 1
fi
kill "$client" 2>/dev/null || true
echo "proc connector test: PASS"
