param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)
$Nro = Join-Path $Root "target/aarch64-skyline-switch/release/libsmush_info.nro"
$Dist = Join-Path $Root "dist"
$Zip = Join-Path $Root "smush_info-sd.zip"
$PluginDir = Join-Path $Dist "atmosphere/contents/01006A800016E000/romfs/skyline/plugins"

if (-not (Test-Path $Nro)) {
    Write-Error "missing $Nro; cargo skyline build --release first"
    exit 1
}

if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
if (Test-Path $Zip) { Remove-Item -Force $Zip }
New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Dist "ultimate/smush_info") | Out-Null
Copy-Item $Nro (Join-Path $PluginDir "libsmush_info.nro")
Copy-Item (Join-Path $Root "package/overrides.toml") (Join-Path $Dist "ultimate/smush_info/overrides.toml")
Compress-Archive -Path (Join-Path $Dist "*") -DestinationPath $Zip
Write-Host "wrote $Zip"
