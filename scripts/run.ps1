$ErrorActionPreference = "Stop"
if (!(Test-Path ".\config.json")) {
  Copy-Item ".\config.example.json" ".\config.json"
  Write-Host "Created config.json from example. Please edit it."
}
java -jar port-tunnel-oss-win.jar config.json
