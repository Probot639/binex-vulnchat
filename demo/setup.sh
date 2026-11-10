#!/bin/bash
# spins up authd + chatd, cleans leftover evidence files.
# run this, wait for READY, then start OBS.
cd "$(dirname "$0")/.."

pkill -f "authd.*4001" 2>/dev/null
sleep 0.5
services/auth/build/authd -k services/auth/keys/idp_ed25519.sk -d services/auth/ -p 4001 &
sleep 1
echo "authd up on :4001"

vagrant winrm win -c '
$p = Get-Process chatd -ErrorAction SilentlyContinue
if ($p) { Stop-Process $p -Force; Start-Sleep 1 }
Remove-Item C:\chatd\pwned.txt -ErrorAction SilentlyContinue
Remove-Item C:\chatd\uaf_pwned.txt -ErrorAction SilentlyContinue
([wmiclass]"Win32_Process").Create("C:\chatd\chatd.exe -k C:\chatd\idp_ed25519.pk -p 4002", "C:\chatd", $null) | Out-Null
Start-Sleep 2
$p = Get-Process chatd
Write-Host "chatd up PID=$($p.Id)"
' 2>/dev/null

python3 -c "
import socket, sys
sys.path.insert(0, 'tests/lib')
import protocol as p
jwt = p.get_jwt('127.0.0.1', 4001)
s = socket.create_connection(('192.168.121.32', 4002), timeout=3)
s.close()
print('auth + chat connectivity verified')
"

echo ""
echo "READY -- start OBS, then run demo/overflow.sh"
