# provision_win.ps1 - install build tools inside the Windows vagrant guest.
# runs during `vagrant provision win`.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# install chocolatey if missing
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# build toolchain: MSVC or MinGW, plus deps
choco install -y visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
choco install -y git python3 cmake

# python test deps
python -m pip install --upgrade pip
python -m pip install pytest pytest-timeout

# vcpkg for libsodium and sqlite if needed
if (-not (Test-Path "C:\vcpkg")) {
    git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
    C:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
}
C:\vcpkg\vcpkg.exe install sqlite3:x64-windows libsodium:x64-windows

Write-Host ""
Write-Host "=== Windows provision done ==="
Write-Host "  vcpkg: C:\vcpkg"
Write-Host "  test: cd C:\vagrant\tests; python -m pytest -v"
