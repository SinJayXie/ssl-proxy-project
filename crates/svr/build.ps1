# 构建并打包 release 产物
#
#   cargo build --release
#     → releases\ssl-proxy-svr-{darwin|linux|win}-{version}\
#          ├── ssl-proxy-svr.exe   可执行文件（若已安装 upx，则 upx --best 压缩）
#          ├── config.yaml         配置模板（源自 config.example.yaml）
#          ├── certs\              证书目录（空，放入正式证书）
#          └── logs\               日志目录（空）
#     → releases\ssl-proxy-svr-{darwin|linux|win}-{version}.zip
#
# 用法: powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
# Workspace root: <root>/crates/svr -> <root>
$Workspace = Split-Path -Parent (Split-Path -Parent $Root)
Set-Location $Root

# ---- 版本号 ----
$Version = (Select-String -Path (Join-Path $Root 'Cargo.toml') `
        -Pattern '^version\s*=\s*"([^"]+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $Version) {
    throw '无法从 Cargo.toml 解析版本号'
}

# ---- 平台标识 ----
if ($IsWindows -or $env:OS -eq 'Windows_NT') { $Platform = 'win' }
elseif ($IsMacOS) { $Platform = 'darwin' }
else { $Platform = 'linux' }

$Name = "ssl-proxy-svr-$Platform-$Version"
$Releases = Join-Path $Root 'releases'
$Stage = Join-Path $Releases $Name
$Bin = Join-Path $Workspace 'target\release\ssl-proxy-svr.exe'
$Zip = Join-Path $Releases "$Name.zip"

# ---- 构建 ----
Write-Host "==> 平台: $Platform, 版本: $Version"
Write-Host '==> cargo build --release'
cargo build --release
if ($LASTEXITCODE -ne 0) {
    throw "cargo build 失败 (exit $LASTEXITCODE)"
}
if (-not (Test-Path $Bin)) {
    throw "找不到构建产物: $Bin"
}

# ---- 组装目录 ----
Write-Host "==> 组装 $Stage"
if (Test-Path $Stage) {
    Remove-Item -Recurse -Force $Stage
}
New-Item -ItemType Directory -Force -Path (Join-Path $Stage 'certs'), (Join-Path $Stage 'logs') | Out-Null

Copy-Item $Bin (Join-Path $Stage 'ssl-proxy-svr.exe')
Copy-Item (Join-Path $Root 'config.example.yaml') (Join-Path $Stage 'config.yaml')

# ---- UPX 压缩（可选） ----
$StagedBin = Join-Path $Stage 'ssl-proxy-svr.exe'
$Upx = Get-Command upx -ErrorAction SilentlyContinue
if ($Upx) {
    Write-Host '==> upx --best ssl-proxy-svr.exe'
    & $Upx.Source --best $StagedBin
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'upx 压缩失败，保留原始二进制'
    }
}
else {
    Write-Host '==> 未找到 upx 命令，跳过压缩'
}

# ---- 打包 ----
Write-Host "==> 打包 $Zip"
if (Test-Path $Zip) {
    Remove-Item -Force $Zip
}
Compress-Archive -Path $Stage -DestinationPath $Zip -CompressionLevel Optimal

Write-Host ''
Write-Host "完成: $Zip"
Write-Host '解压后:'
Write-Host '  1. 编辑 config.yaml（端口 / 密码）'
Write-Host '  2. 正式证书放入 certs\；想用自签证书则注释掉 tls.cert 与 tls.key'
Write-Host '  3. 运行 .\ssl-proxy-svr.exe -c config.yaml'
