#!/usr/bin/env bash
# ECP Aegis — prove the lab CANNOT reach the real LAN / internet.
# Run from the Mac host. PASS = lab peer reachable; host LAN + internet + DNS all blocked.
#
# Usage:  LAN_GW=192.168.1.1 ./verify-isolation.sh
set -uo pipefail

NET="${NET:-targets_ptlab}"          # compose-prefixed network name (check: docker network ls)
LAN_GW="${LAN_GW:-192.168.1.1}"      # <-- set to your ACTUAL physical LAN gateway
LAB_PEER="${LAB_PEER:-172.30.0.10}"  # juiceshop

echo "== ECP Aegis isolation check =="
echo "network=$NET  lab_peer=$LAB_PEER  lan_gw=$LAN_GW"
echo

docker run --rm --network "$NET" alpine sh -c "
  apk add -q iputils bind-tools >/dev/null 2>&1
  echo '[+] lab peer  (expect OK):    '; ping -c1 -W2 $LAB_PEER  >/dev/null 2>&1 && echo '    OK'      || echo '    FAIL (lab broken)'
  echo '[+] host LAN  (expect block): '; ping -c1 -W2 $LAN_GW    >/dev/null 2>&1 && echo '    LEAK !!' || echo '    blocked'
  echo '[+] internet  (expect block): '; ping -c1 -W2 8.8.8.8    >/dev/null 2>&1 && echo '    LEAK !!' || echo '    blocked'
  echo '[+] DNS egress(expect block): '; nslookup google.com 8.8.8.8 >/dev/null 2>&1 && echo '    LEAK !!' || echo '    blocked'
  echo '[+] default route (expect none):'; ip route | grep -q '^default' && echo '    LEAK !! (default route exists)' || echo '    none'
"
echo
echo "PASS criteria: lab peer OK, everything else blocked/none. Any LEAK = misconfig — do NOT proceed."
