# 一键构建并打包客户端与服务端
#
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Makensis "C:\path\to\makensis.exe"
#
# 产物：
#   dist\client\SSLProxyClient_<gui版本>_x64-setup.exe
#   dist\server\ssl-proxy-svr-win-<svr版本>.zip

param(
    [string]$Makensis,
    [switch]$SkipClient,
    [switch]$SkipServer,
    [switch]$NoUpx,
    # version.json 中 downloadUrl 的目录前缀
    [string]$DownloadBase = 'https://hk.dishuyl.cn/ssl-proxy/win'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Target = Join-Path $Root 'target'
$Dist = Join-Path $Root 'dist'
$ClientOut = Join-Path $Dist 'client'
$ServerOut = Join-Path $Dist 'server'
$GuiCrate = Join-Path $Root 'crates\gui'
$SvrCrate = Join-Path $Root 'crates\svr'

function Get-CrateVersion([string]$Manifest) {
    if (-not (Test-Path $Manifest)) { throw "找不到清单: $Manifest" }
    $toml = Get-Content $Manifest -Raw
    if ($toml -match '(?m)^version\s*=\s*"([^"]+)"') { return $Matches[1] }
    throw "无法从 $Manifest 解析版本号"
}

function Get-ReleaseBin([string]$Name) {
    $exe = Join-Path $Target "release\$Name.exe"
    if (Test-Path $exe) { return $exe }
    $plain = Join-Path $Target "release\$Name"
    if (Test-Path $plain) { return $plain }
    throw "找不到构建产物: $exe"
}

Write-Host '==> cargo build --release --workspace'
& cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build 失败（退出码 $LASTEXITCODE）" }

$GuiExe = Get-ReleaseBin 'ssl-proxy-gui'
$SvrExe = Get-ReleaseBin 'ssl-proxy-svr'
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

if (-not $SkipClient) {
    $guiVersion = Get-CrateVersion (Join-Path $GuiCrate 'Cargo.toml')
    New-Item -ItemType Directory -Force -Path $ClientOut | Out-Null

    $payloadDir = Join-Path $Target 'installer\payload'
    New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null
    $payloadExe = Join-Path $payloadDir 'ssl-proxy-gui.exe'
    Copy-Item -Force $GuiExe $payloadExe

    if (-not $NoUpx) {
        $upx = Get-Command upx -ErrorAction SilentlyContinue
        if ($upx) {
            Write-Host '==> upx --best（客户端）'
            & $upx.Source --best $payloadExe
            if ($LASTEXITCODE -ne 0) {
                Write-Warning 'upx 压缩失败，改用未压缩的 exe'
                Copy-Item -Force $GuiExe $payloadExe
            }
        } else {
            Write-Host '==> 未找到 upx，跳过客户端压缩'
        }
    }

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

    $sourceGeo = Join-Path $GuiCrate 'assets\GeoDB.dat'
    $iconFile = [System.IO.Path]::GetFullPath((Join-Path $Root '..\ssl-proxy-client-tauri\src-tauri\icons\icon.ico'))
    if (-not (Test-Path $iconFile)) {
        throw "找不到安装包图标: $iconFile（可用 SSL_PROXY_ICON 环境变量指定）"
    }

    $setup = Join-Path $ClientOut "SSLProxyClient_${guiVersion}_x64-setup.exe"
    Write-Host "==> makensis（客户端 $guiVersion）"
    & $Makensis /V2 "/DPRODUCT_VERSION=$guiVersion" "/DUSE_PAYLOAD" `
        "/DPAYLOAD_EXE=$payloadExe" "/DSOURCE_GEO=$sourceGeo" `
        "/DICON_FILE=$iconFile" "/DOUT_FILE=$setup" `
        (Join-Path $GuiCrate 'installer\installer.nsi')
    if ($LASTEXITCODE -ne 0) { throw "makensis 失败（退出码 $LASTEXITCODE）" }
    Write-Host "    客户端安装包: $setup"

    # 发布清单：版本号取自 Cargo.toml，sha256/signature 来自本次产物，
    # changelog 沿用项目根目录 version.json 中已有的列表。
    $setupHash = (Get-FileHash -Algorithm SHA256 $setup).Hash.ToLower()
    Write-Host "    安装包 SHA256: $setupHash"

    $signKey = if ($env:SSL_PROXY_UPDATE_KEY) { $env:SSL_PROXY_UPDATE_KEY } else { Join-Path $Root '.secrets\update-signing-key.der' }
    if (-not (Test-Path $signKey)) {
        throw "未找到签名私钥 $signKey；新版客户端会拒绝执行未签名更新（可用 SSL_PROXY_UPDATE_KEY 指定私钥）"
    }

    Write-Host '==> Ed25519 签名（update-signer）'
    $sig = "$(& cargo run -q -p update-signer -- sign $signKey $setup)".Trim()
    if ($LASTEXITCODE -ne 0) { throw "安装包签名失败（退出码 $LASTEXITCODE）" }
    Write-Host "    安装包签名: $sig"

    $manifestPath = Join-Path $Root 'version.json'
    $changelog = @()
    if (Test-Path $manifestPath) {
        $existing = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($existing.PSObject.Properties.Name -contains 'changelog') {
            $changelog = @($existing.changelog)
        }
    }
    $manifest = [ordered]@{
        version     = $guiVersion
        changelog   = $changelog
        downloadUrl = "$DownloadBase/SSLProxyClient_${guiVersion}_x64-setup.exe"
        sha256      = $setupHash
        signature   = $sig
    }
    # 必须写成无 BOM 的 UTF-8，否则客户端 serde_json 解析会失败
    $json = $manifest | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($manifestPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "    发布清单: $manifestPath"
}

if (-not $SkipServer) {
    $svrVersion = Get-CrateVersion (Join-Path $SvrCrate 'Cargo.toml')
    $name = "ssl-proxy-svr-win-$svrVersion"
    $stage = Join-Path $ServerOut $name
    New-Item -ItemType Directory -Force -Path $ServerOut | Out-Null
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force -Path (Join-Path $stage 'certs'), (Join-Path $stage 'logs') | Out-Null

    $stagedExe = Join-Path $stage 'ssl-proxy-svr.exe'
    Copy-Item $SvrExe $stagedExe
    Copy-Item (Join-Path $SvrCrate 'config.example.yaml') (Join-Path $stage 'config.yaml')

    if (-not $NoUpx) {
        $upx = Get-Command upx -ErrorAction SilentlyContinue
        if ($upx) {
            Write-Host '==> upx --best（服务端）'
            & $upx.Source --best $stagedExe
            if ($LASTEXITCODE -ne 0) { Write-Warning 'upx 压缩失败，保留原始二进制' }
        } else {
            Write-Host '==> 未找到 upx，跳过服务端压缩'
        }
    }

    $zip = Join-Path $ServerOut "$name.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
    Write-Host "    服务端发布包: $zip"
}

Write-Host ''
Write-Host '完成。'
