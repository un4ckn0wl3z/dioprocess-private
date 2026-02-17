#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test DioProcess EFI in QEMU with OVMF firmware.

.DESCRIPTION
    Creates a virtual ESP with DioProcessEfi.efi and boots it in QEMU.
    Downloads OVMF automatically if not found.

.PARAMETER OvmfPath
    Path to OVMF firmware file. Auto-downloads if not specified.

.PARAMETER EfiBinary
    Path to DioProcessEfi.efi. Defaults to build output.

.PARAMETER Resolution
    Screen resolution (default: 1024x768)

.PARAMETER Memory
    VM memory in MB (default: 512)

.EXAMPLE
    .\Run-Qemu.ps1
    
.EXAMPLE
    .\Run-Qemu.ps1 -Resolution 1920x1080 -Memory 1024
#>

param(
    [string]$OvmfPath,
    [string]$EfiBinary,
    [string]$Resolution = "1024x768",
    [int]$Memory = 512
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EfiDir = Split-Path -Parent $ScriptDir

Write-Host "`n=== DioProcess EFI QEMU Tester ===" -ForegroundColor Cyan
Write-Host ""

# === Find QEMU ===
$QemuPath = Get-Command "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source

if (-not $QemuPath) {
    # Check common install locations
    $CommonPaths = @(
        "C:\Program Files\qemu\qemu-system-x86_64.exe",
        "C:\qemu\qemu-system-x86_64.exe",
        "$env:LOCALAPPDATA\Programs\qemu\qemu-system-x86_64.exe"
    )
    foreach ($p in $CommonPaths) {
        if (Test-Path $p) {
            $QemuPath = $p
            break
        }
    }
}

if (-not $QemuPath) {
    Write-Host "[-] QEMU not found!" -ForegroundColor Red
    Write-Host "    Install with: winget install QEMU.QEMU" -ForegroundColor Yellow
    Write-Host "    Or download:  https://www.qemu.org/download/#windows" -ForegroundColor Yellow
    exit 1
}
Write-Host "[+] QEMU: $QemuPath" -ForegroundColor Green

# === Find/Download OVMF ===
$OvmfDir = Join-Path $ScriptDir "ovmf"

if (-not $OvmfPath) {
    # Check common locations
    $CommonOvmf = @(
        (Join-Path $OvmfDir "OVMF.fd"),
        "C:\Program Files\qemu\share\edk2-x86_64-code.fd",
        "C:\Program Files\qemu\share\OVMF.fd"
    )
    foreach ($p in $CommonOvmf) {
        if (Test-Path $p) {
            $OvmfPath = $p
            break
        }
    }
}

if (-not $OvmfPath -or -not (Test-Path $OvmfPath)) {
    Write-Host "[*] OVMF not found, downloading..." -ForegroundColor Yellow
    
    if (-not (Test-Path $OvmfDir)) {
        New-Item -ItemType Directory -Path $OvmfDir | Out-Null
    }
    
    $OvmfUrl = "https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd"
    $OvmfPath = Join-Path $OvmfDir "OVMF.fd"
    
    try {
        Write-Host "    Downloading from: $OvmfUrl"
        Invoke-WebRequest -Uri $OvmfUrl -OutFile $OvmfPath -UseBasicParsing
        Write-Host "[+] Downloaded OVMF firmware" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to download OVMF: $_" -ForegroundColor Red
        Write-Host "    Download manually from: https://retrage.github.io/edk2-nightly/" -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "[+] OVMF: $OvmfPath" -ForegroundColor Green

# === Find EFI binary ===
if (-not $EfiBinary) {
    # Check build outputs in multiple locations
    $BuildPaths = @(
        # EDK2 workspace (when script is in C:\edk2 or C:\edk2\tools)
        (Join-Path $ScriptDir "Build\DioProcessEfi\RELEASE_VS2022\X64\DioProcessEfi.efi"),
        (Join-Path $ScriptDir "..\Build\DioProcessEfi\RELEASE_VS2022\X64\DioProcessEfi.efi"),
        "C:\edk2\Build\DioProcessEfi\RELEASE_VS2022\X64\DioProcessEfi.efi",
        # Original DioProcess repo structure
        (Join-Path $EfiDir "Build\DioProcessEfi\RELEASE_VS2022\X64\DioProcessEfi.efi"),
        (Join-Path $EfiDir "Build\DioProcessEfi\RELEASE_GCC5\X64\DioProcessEfi.efi"),
        (Join-Path $EfiDir "Build\DioProcessEfi\DEBUG_VS2022\X64\DioProcessEfi.efi")
    )
    foreach ($p in $BuildPaths) {
        if (Test-Path $p) {
            $EfiBinary = (Resolve-Path $p).Path
            break
        }
    }
}

if (-not $EfiBinary -or -not (Test-Path $EfiBinary)) {
    Write-Host "[-] DioProcessEfi.efi not found!" -ForegroundColor Red
    Write-Host "    Build first with:" -ForegroundColor Yellow
    Write-Host "      cd efi" -ForegroundColor Yellow
    Write-Host "      build -a X64 -t VS2022 -p DioProcessEfi/DioProcessEfi.dsc -b RELEASE" -ForegroundColor Yellow
    exit 1
}
Write-Host "[+] EFI binary: $EfiBinary" -ForegroundColor Green

# === Create virtual ESP ===
$EspDir = Join-Path $env:TEMP "dioprocess_esp_$(Get-Random)"
$EspBootDir = Join-Path $EspDir "EFI\BOOT"

Write-Host ""
Write-Host "[*] Creating virtual ESP..." -ForegroundColor Cyan

New-Item -ItemType Directory -Path $EspBootDir -Force | Out-Null
Copy-Item $EfiBinary (Join-Path $EspBootDir "bootx64.efi")
Write-Host "[+] Copied to EFI\BOOT\bootx64.efi" -ForegroundColor Green

# === Parse resolution ===
$ResMatch = [regex]::Match($Resolution, "(\d+)x(\d+)")
if ($ResMatch.Success) {
    $Width = $ResMatch.Groups[1].Value
    $Height = $ResMatch.Groups[2].Value
} else {
    $Width = 1024
    $Height = 768
}

# === Run QEMU ===
Write-Host ""
Write-Host "[*] Starting QEMU..." -ForegroundColor Cyan
Write-Host "    Resolution: ${Width}x${Height}"
Write-Host "    Memory: ${Memory}MB"
Write-Host ""
Write-Host "    Controls:" -ForegroundColor Yellow
Write-Host "      Ctrl+Alt+G    = Release mouse"
Write-Host "      Ctrl+Alt+F    = Fullscreen"
Write-Host "      Ctrl+Alt+Q    = Quit"
Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray

$QemuArgs = @(
    "-machine", "q35",
    "-m", "${Memory}M",
    "-cpu", "qemu64",
    "-drive", "if=pflash,format=raw,readonly=on,file=$OvmfPath",
    "-drive", "if=virtio,format=raw,file=fat:rw:$EspDir",
    "-device", "VGA,vgamem_mb=64",
    "-serial", "stdio",
    "-boot", "menu=on"
)

try {
    # Use call operator for proper argument handling with spaces
    & $QemuPath @QemuArgs
    Write-Host ""
    Write-Host "[*] QEMU exited with code: $LASTEXITCODE" -ForegroundColor Cyan
}
finally {
    # Cleanup
    if (Test-Path $EspDir) {
        Remove-Item -Recurse -Force $EspDir -ErrorAction SilentlyContinue
    }
}
