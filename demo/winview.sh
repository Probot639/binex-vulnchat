#!/bin/bash
# opens RDP to the windows VM with a powershell monitor that watches
# C:\chatd for new files. point OBS at this window.
#
# in a second terminal, run demo/overflow.sh while this is up.
# you'll see pwned.txt appear in real time.
cd "$(dirname "$0")/.."

VM_IP="192.168.121.32"

# pop open a monitoring powershell + explorer on the VM
vagrant winrm win -c '
Start-Process explorer.exe "C:\chatd"

$script = @"
`$host.UI.RawUI.WindowTitle = "chatd monitor"
while (`$true) {
    Clear-Host
    Write-Host "=== C:\chatd ===" -ForegroundColor Cyan
    Write-Host ""
    Get-ChildItem C:\chatd | Format-Table Name, Length, LastWriteTime -AutoSize
    Write-Host ""
    if (Test-Path C:\chatd\pwned.txt) {
        Write-Host "*** pwned.txt ***" -ForegroundColor Red
        Get-Content C:\chatd\pwned.txt
        Write-Host ""
    }
    if (Test-Path C:\chatd\uaf_pwned.txt) {
        Write-Host "*** uaf_pwned.txt ***" -ForegroundColor Red
        Get-Content C:\chatd\uaf_pwned.txt
        Write-Host ""
    }
    `$p = Get-Process chatd -ErrorAction SilentlyContinue
    if (`$p) { Write-Host "chatd: running (PID `$(`$p.Id))" -ForegroundColor Green }
    else { Write-Host "chatd: dead" -ForegroundColor Red }
    Start-Sleep 2
}
"@
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
Start-Process powershell.exe -ArgumentList "-NoExit -EncodedCommand $enc"
' 2>/dev/null

echo "monitor + explorer launched on VM"
echo "opening RDP..."

# /dynamic-resolution lets you resize the window in OBS
xfreerdp3 /v:$VM_IP /u:vagrant /p:vagrant /cert:ignore /size:1920x1080 \
  /t:vulnchat-win /dynamic-resolution

# blocks here until you close the RDP window
