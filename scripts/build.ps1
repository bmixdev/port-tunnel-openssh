$ErrorActionPreference = "Stop"

if (Test-Path out) { Remove-Item out -Recurse -Force }
javac -d out src/main/java/PortTunnelOpenSSH.java

@"
Manifest-Version: 1.0
Main-Class: PortTunnelOpenSSH

"@ | Out-File -Encoding ascii manifest.mf

# Кладём ВСЁ из ./out → исключаем проблемы с '$'
jar cfm port-tunnel-oss-win.jar manifest.mf -C out .

Write-Host "Built: port-tunnel-oss-win.jar"