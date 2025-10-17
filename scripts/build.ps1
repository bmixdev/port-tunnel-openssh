$ErrorActionPreference = "Stop"
Write-Host "Compiling..."
javac src/main/java/PortTunnelOpenSSH.java
Write-Host "Packaging JAR..."
jar --create --file port-tunnel-oss-win.jar --main-class=PortTunnelOpenSSH -C src/main/java PortTunnelOpenSSH.class
Write-Host "Done: port-tunnel-oss-win.jar"
