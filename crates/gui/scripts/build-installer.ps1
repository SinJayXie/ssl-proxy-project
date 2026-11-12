# 构建 Windows 安装包（原地覆盖升级旧版 Tauri 客户端）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
#   powershell -File scripts\build-installer.ps1 -Version 2.1.7 -Makensis "C:\path\to\makensis.exe"
#
# 产物：target\installer\SSLProxyClient_<version>_x64-setup.exe

param(
    [string]$Version,
    [string]$Makensis
)

$ErrorActionPreference = 'Stop'
$crate = Split-Path -Parent $PSScriptRoot
# Workspace root: <root>/crates/gui/scripts -> <root>
$workspace = Split-Path -Parent (Split-Path -Parent $crate)
$targetDir = Join-Path $workspace 'target'

Push-Location $crate
try {
    if (-not $Version) {
        $toml = Get-Content (Join-Path $crate 'Cargo.toml') -Raw
        if ($toml -match '(?m)^version\s*=\s*"([^"]+)"') {
            $Version = $Matches[1]
        }
    }
    if (-not $Version) { throw '无法从 Cargo.toml 读取版本号，请用 -Version 指定' }

    if (-not $Makensis) {
        $candidates = @(
            (Join-Path $env:LOCALAPPDATA 'tauri\NSIS\Bin\makensis.exe'),
            (Join-Path $env:LOCALAPPDATA 'tauri\NSIS\makensis.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe'),
            (Join-Path $env:ProgramFiles 'NSIS\makensis.exe')
        )
        $Makensis = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    }
    if (-not $Makensis) {
        throw '未找到 makensis.exe。可安装 NSIS，或用 -Makensis 指定路径（Tauri 的缓存在 %LOCALAPPDATA%\tauri\NSIS\Bin）。'
    }

    Write-Host '==> cargo build --release'
    & cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build 失败（退出码 $LASTEXITCODE）" }

    $outDir = Join-Path $targetDir 'installer'
    $payloadDir = Join-Path $outDir 'payload'
    New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null

    # 复制一份到 payload 再压缩，避免改动 cargo 的产物；
    # upx 失败时回退到未压缩副本，保证安装包总能出。
    $releaseExe = Join-Path $targetDir 'release\ssl-proxy-gui.exe'
    $payloadExe = Join-Path $payloadDir 'ssl-proxy-gui.exe'
    Copy-Item -Force $releaseExe $payloadExe

    $upx = Get-Command upx -ErrorAction SilentlyContinue
    if ($upx) {
        Write-Host "==> upx --best（$($upx.Source)）"
        & $upx.Source --best $payloadExe
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "upx 压缩失败（退出码 $LASTEXITCODE），改用未压缩的 exe"
            Copy-Item -Force $releaseExe $payloadExe
        }
    }
    else {
        Write-Host '==> 未找到 upx，跳过压缩'
    }
    $exeSize = [math]::Round((Get-Item $payloadExe).Length / 1MB, 2)
    Write-Host "    打包用 exe：$exeSize MiB"

    Write-Host "==> makensis (版本 $Version)"
    & $Makensis /V2 "/DPRODUCT_VERSION=$Version" "/DUSE_PAYLOAD" (Join-Path $crate 'installer\installer.nsi')
    if ($LASTEXITCODE -ne 0) { throw "makensis 失败（退出码 $LASTEXITCODE）" }

    $setup = Join-Path $outDir "SSLProxyClient_${Version}_x64-setup.exe"
    $size = [math]::Round((Get-Item $setup).Length / 1MB, 2)
    Write-Host "==> 完成：$setup（$size MiB）"
}
finally {
    Pop-Location
}
