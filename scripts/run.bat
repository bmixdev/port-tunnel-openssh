@echo off
if not exist config.json (
  copy config.example.json config.json
  echo Created config.json from example. Please edit it.
)
java -jar port-tunnel-oss-win.jar config.json
