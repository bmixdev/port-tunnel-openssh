# PortTunnel OpenSSH (Windows)

Универсальная консольная утилита на **чистой Java SE** (без сторонних библиотек) для проброса портов через **OpenSSH (ssh.exe)** по JSON‑конфигу.
Поддерживает генерацию SSH‑ключа (`ssh-keygen.exe`), добавление в `ssh-agent` (`ssh-add.exe`), опциональный **ProxyJump** (бастион) и вывод
фактических проброшенных портов в JSON. Отлично подходит для сценариев доступа к внутренним сервисам (например, Apache Ignite,
который слушает `127.0.0.1:65482` на удалённом сервере AstraLinux).

## Возможности
- Несколько локальных форвардов (`-L`) в одном процессе.
- Конфигурация из JSON (собственный лёгкий парсер — без зависимостей).
- Генерация ключа (`ed25519`/`rsa`), добавление в `ssh-agent` (Windows OpenSSH).
- ProxyJump (одиночный бастион или цепочка) — включается/выключается флагом.
- Автоперезапуск ssh‑процесса (retry с backoff).
- Вывод итоговых локальных портов в JSON (stdout + файл, если указан).

## Требования
- Windows 10/11 с установленным **OpenSSH Client** (обычно `C:\\Windows\\System32\\OpenSSH\\ssh.exe`).
- Java 11+ (рекомендуется).

## Быстрый старт
1) Скопируйте `config.example.json` в `config.json` и поправьте под себя.
2) Соберите JAR и запустите:

```powershell
# PowerShell из корня репозитория
.\scripts\build.ps1
.\scripts\run.ps1
```

или без скриптов:

```bat
javac src/main/java/PortTunnelOpenSSH.java
jar --create --file port-tunnel-oss-win.jar --main-class=PortTunnelOpenSSH -C src/main/java PortTunnelOpenSSH.class
java -jar port-tunnel-oss-win.jar config.json
```

## Пример конфига (ProxyJump отключён — «вариант 2»)

См. `config.example.json`, ключевые поля подробно описаны в README и в комментариях исходника.

## Подключение к Apache Ignite
После старта утилита печатает JSON с фактическими портами. Подключение к Ignite thin JDBC:

```
jdbc:ignite:thin://127.0.0.1:<выданный_localPort>
```

## Лицензия
[MIT](./LICENSE)
