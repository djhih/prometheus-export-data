#!/usr/bin/env bash
# collect-via-jump.sh - run from a jump host that can reach both the monitoring
# host and the target, when the monitoring host cannot reach the target itself.
#
# It fetches the collect-host-logs.sh that incident_dump.py generated (the
# incident window is already baked into it), runs it on the target, and pushes
# the result back next to the rest of the evidence.
#
#   1. edit the four values below
#   2. bash collect-via-jump.sh
#
# Nothing is left behind: the target's /tmp copy and the jump host's scratch
# directory are both removed, because these logs carry user names and full
# command lines.
set -euo pipefail
umask 077

MON=user@monitoring-host        # where incident_dump.py ran
TARGET=target-host              # the affected machine
INC='incidents/incident-HOST-DATE-TIME'   # path on MON, relative to its home (no leading ~/)
NEED_SUDO=yes                   # does reading the system journal need sudo there?

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

echo "==> 1/4 fetch collect-host-logs.sh from $MON"
scp -q "$MON:$INC/collect-host-logs.sh" "$WORK/"

echo "==> 2/4 collect on $TARGET"
if [ "$NEED_SUDO" = yes ]; then
    # a password prompt and a piped script fight over stdin, so stage the file
    scp -q "$WORK/collect-host-logs.sh" "$TARGET:/tmp/"
    ssh -t "$TARGET" 'sudo bash /tmp/collect-host-logs.sh > /tmp/host-logs.txt; chmod 600 /tmp/host-logs.txt'
    scp -q "$TARGET:/tmp/host-logs.txt" "$WORK/"
    ssh "$TARGET" 'rm -f /tmp/collect-host-logs.sh /tmp/host-logs.txt'
else
    ssh "$TARGET" 'bash -s' < "$WORK/collect-host-logs.sh" > "$WORK/host-logs.txt"
fi

echo "==> 3/4 sanity check"
sed -n '1,8p' "$WORK/host-logs.txt"      # the header prints the hostname: is it the right box?
echo "lines: $(wc -l < "$WORK/host-logs.txt")"
grep -n 'entries in window:' "$WORK/host-logs.txt" || true
grep -n 'Hint:\|No journal files' "$WORK/host-logs.txt" \
    && echo "!! journal was truncated or unreadable - the log-based checks cannot conclude" \
    || echo "journal looks readable"

echo "==> 4/4 push back to $MON"
scp -q "$WORK/host-logs.txt" "$MON:$INC/host-logs.txt"
echo "done -> $MON:~/$INC/host-logs.txt"
echo "now re-run incident_dump.py with --host-logs on $MON (see RUNBOOK.zh-tw.md)"
