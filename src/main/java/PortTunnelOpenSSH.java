// (c) Universal OpenSSH Port Forwarder for Windows — pure Java SE
// ============================================================================================
// ЭТОТ ФАЙЛ — полнофункциональная консольная утилита проброса портов через OpenSSH (ssh.exe).
// Ключевые особенности:
//  • Читает JSON-конфиг (без внешних зависимостей — встроенный простой парсер/писатель JSON).
//  • Опционально генерирует SSH-ключ (ssh-keygen.exe) и добавляет его в ssh-agent (ssh-add.exe).
//  • Поддерживает ProxyJump (бастион) — одиночный или цепочку хопов.
//  • Поднимает несколько локальных форвардов (-L) за один ssh-процесс.
//  • Автоперезапуск (retry) с экспоненциальным бэкоффом.
//  • Печатает в stdout JSON c ФАКТИЧЕСКИ выделенными локальными портами (когда localPort=0).
//
// БЫСТРЫЙ СТАРТ (из корня репозитория):
//   javac src/main/java/PortTunnelOpenSSH.java
//   jar --create --file port-tunnel-oss-win.jar --main-class=PortTunnelOpenSSH -C src/main/java PortTunnelOpenSSH.class
//   java -jar port-tunnel-oss-win.jar config.json
//
// СМ. README.md и config.example.json для подробностей.
// ============================================================================================

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;

public class PortTunnelOpenSSH {

    // ----------------------------------------------------------------------------------------
    // Точка входа. Принимает единственный аргумент — путь к JSON‑конфигу.
    // ----------------------------------------------------------------------------------------
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar port-tunnel-oss-win.jar <config.json>");
            System.exit(2);
        }
        Path cfgPath = Paths.get(args[0]);
        try {
            Map<String,Object> cfg = readJsonFile(cfgPath);
            new PortTunnelOpenSSH(cfg).run();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private final Map<String,Object> cfg;
    private final Logger log;

    public PortTunnelOpenSSH(Map<String,Object> cfg) {
        this.cfg = cfg;
        this.log = new Logger(optStr(cfg,"logLevel","info"));
    }

    // ----------------------------------------------------------------------------------------
    // Основной рабочий цикл: чтение конфига → (опционально) генерация ключа → запуск ssh
    // с временным конфигом → ожидание поднятия локальных портов → вывод JSON c портами →
    // удержание процесса и, при необходимости, автоперезапуск.
    // ----------------------------------------------------------------------------------------
    private void run() throws Exception {
        // --- Обязательные параметры удалённого SSH-хоста ---
        String sshHost = reqStr(cfg,"sshHost");
        int sshPort = optInt(cfg,"sshPort",22);
        String sshUser = reqStr(cfg,"sshUser");

        // --- Пути к исполняемым OpenSSH (можно просто "ssh"/"ssh-keygen"/"ssh-add", если в PATH) ---
        String sshPath = optStr(cfg,"opensshPath","ssh");
        String sshKeygenPath = optStr(cfg,"sshKeygenPath","ssh-keygen");
        String sshAddPath = optStr(cfg,"sshAddPath","ssh-add");

        // --- Поведение SSH ---
        boolean strict = optBool(cfg,"strictHostKeyChecking", true);   // строго проверять known_hosts?
        String knownHosts = optStr(cfg,"userKnownHostsFile", null);    // альтернативный файл known_hosts
        int keepaliveSec = optInt(cfg,"keepaliveSec", 60);             // ServerAliveInterval

        // --- ProxyJump (бастион) — можно выключить блоком { "enabled": false } ---
        Map<String,Object> pj = optObj(cfg,"proxyJump", Map.of());
        ProxyJump proxy = ProxyJump.from(pj);

        // --- Блок генерации ключа (необязательный) ---
        Map<String,Object> keygen = optObj(cfg,"keygen", Map.of());
        boolean keygenEnabled = optBool(keygen,"enabled", false);
        String identityFile = optStr(keygen,"identityFile", null);
        if (keygenEnabled) {
            if (identityFile == null || identityFile.isBlank())
                throw new IllegalArgumentException("keygen.identityFile is required when keygen.enabled=true");
            generateKeyIfNeeded(sshKeygenPath, keygen, log);
        }

        // --- Аутентификация: для OpenSSH-бэкенда используем ТОЛЬКО ключи ---
        Map<String,Object> auth = optObj(cfg,"auth", Map.of("method","key"));
        String method = optStr(auth,"method","key");
        if (!"key".equalsIgnoreCase(method)) {
            throw new IllegalArgumentException("OpenSSH mode uses key auth only. Set auth.method=\"key\".");
        }

        // --- Список форвардов (можно несколько). localPort=0 → выбрать свободный порт автоматически. ---
        List<Map<String,Object>> fwArr = reqArr(cfg,"forwards");
        List<Forward> forwards = new ArrayList<>();
        for (Map<String,Object> m : fwArr) {
            String lba = reqStr(m,"localBindAddr");         // адрес привязки локального сокета (обычно 127.0.0.1)
            int lp = optInt(m,"localPort",0);               // 0 → авто-порт
            String rh = reqStr(m,"remoteHost");             // удалённый хост (относительно целевого SSH-сервера)
            int rp = optInt(m,"remotePort",-1);             // порт удалённого сервиса
            if (rp <= 0) throw new IllegalArgumentException("remotePort must be > 0");
            if (lp == 0) lp = findFreePort(lba);
            forwards.add(new Forward(lba, lp, rh, rp));
        }

        // --- Если ключ только что генерили — добавим его в агент (упрощает работу с passphrase) ---
        if (keygenEnabled && optBool(keygen,"addToAgent", true)) {
            tryAddToAgent(sshAddPath, identityFile, log);
        }

        // --- Настройки вывода фактических портов ---
        Map<String,Object> outCfg = optObj(cfg,"output", Map.of());
        boolean printJson = optBool(outCfg,"printJson", true);
        String jsonPath = optStr(outCfg,"jsonPath", null);

        // --- Параметры авто-перезапуска ---
        RetryPolicy retry = RetryPolicy.from(cfg);

        // --- Runner: создаёт временный ssh_config, запускает ssh.exe, ждёт подъёма портов ---
        OpenSshRunner runner = new OpenSshRunner(
                sshPath, sshHost, sshPort, sshUser,
                identityFile, strict, knownHosts, keepaliveSec,
                proxy, forwards, log,
                printJson, jsonPath
        );

        // Короткая печать того, что будем поднимать
        log.info("Local forwards (план):");
        for (Forward f : forwards) log.info("  " + f);

        // Корректное завершение по Ctrl+C
        Runtime.getRuntime().addShutdownHook(new Thread(runner::stop, "tunnel-stop"));

        // Главный цикл: старт → ожидание → (emit JSON) → удержание → при падении — retry
        long delay = retry.initialDelayMs;
        while (true) {
            try {
                runner.start();
                runner.waitUp(Duration.ofSeconds(12));  // дожидаемся, когда локальные порты реально слушают
                runner.emitJsonOnce();                  // печатаем/сохраняем JSON с ФАКТИЧЕСКИМИ портами
                log.info("Tunnel is up. Press Ctrl+C to stop.");
                runner.waitForExit();                   // блокируемся, пока ssh.exe жив
                log.error("ssh process exited.");
            } catch (Exception e) {
                log.error("Tunnel error: " + e.getMessage());
                log.debug(stackTrace(e));
            }
            if (!retry.enabled) break;
            log.info("Retrying in " + delay + " ms ...");
            Thread.sleep(delay);
            delay = Math.min((long)(delay * retry.multiplier), retry.maxDelayMs);
        }
    }

    // =========================================================================================
    // ProxyJump: представление и генерация строк ssh_config для 'ProxyJump ...'
    // =========================================================================================
    private static final class ProxyJump {
        final boolean enabled;
        final String single;        // одиночный "user@host:port"
        final List<String> chain;   // цепочка ["user@h1:22","user@h2:2202", ...]

        private ProxyJump(boolean en, String single, List<String> chain) {
            this.enabled=en; this.single=single; this.chain=chain;
        }

        @SuppressWarnings("unchecked")
        static ProxyJump from(Map<String,Object> pj) {
            // Если блок пустой или выключен — просто не используем ProxyJump.
            if (pj==null || pj.isEmpty() || !optBool(pj,"enabled",false)) return new ProxyJump(false,null,null);

            // Если задана цепочка — собираем её; при необходимости добавляем user и порт по умолчанию 22
            List<Object> chainRaw = (List<Object>) pj.get("chain");
            if (chainRaw != null && !chainRaw.isEmpty()) {
                String defaultUser = optStr(pj,"user", null);
                List<String> chain = new ArrayList<>();
                for (Object o : chainRaw) {
                    String s = String.valueOf(o).trim();
                    if (!s.contains("@") && defaultUser != null) s = defaultUser + "@" + s;
                    if (!s.contains(":")) s = s + ":22";
                    chain.add(s);
                }
                return new ProxyJump(true, null, chain);
            }

            // Иначе ожидаем одиночный бастион
            String host = optStr(pj,"host", null);
            if (host==null || host.isBlank()) throw new IllegalArgumentException("proxyJump.host required (или proxyJump.chain)");
            int port = optInt(pj,"port",22);
            String user = optStr(pj,"user", null);
            String target = (user!=null && !user.isBlank()? user+"@" : "") + host + ":" + port;
            return new ProxyJump(true, target, null);
        }

        // Строки для ssh_config
        List<String> toConfigLines() {
            if (!enabled) return List.of();
            if (single != null) return List.of("  ProxyJump " + single);
            return List.of("  ProxyJump " + String.join(",", chain));
        }

        // Удобное строковое представление для JSON-вывода
        String asString() {
            if (!enabled) return null;
            if (single != null) return single;
            return String.join(",", chain);
        }
    }

    // =========================================================================================
    // Генерация ключа и добавление в ssh-agent
    // =========================================================================================
    private static void generateKeyIfNeeded(String sshKeygenPath, Map<String,Object> keygen, Logger log)
            throws IOException, InterruptedException {
        String identityFile = optStr(keygen,"identityFile", null);
        boolean overwrite = optBool(keygen,"overwriteIfExists", false);
        String type = optStr(keygen,"type","ed25519").toLowerCase(Locale.ROOT);
        int bits = optInt(keygen,"bits", 4096);
        String comment = optStr(keygen,"comment", "");
        String passphrase = optStr(keygen,"passphrase", null);

        Path priv = Paths.get(identityFile);
        Path pub = Paths.get(identityFile + ".pub");
        boolean exists = Files.exists(priv) || Files.exists(pub);

        if (exists && !overwrite) {
            log.info("Ключ уже существует, пропускаем генерацию: " + identityFile);
            return;
        }

        Files.createDirectories(priv.getParent()); // создаём каталог, если его ещё нет

        List<String> cmd = new ArrayList<>();
        cmd.add(sshKeygenPath);
        cmd.add("-t"); cmd.add(type.equals("rsa") ? "rsa" : "ed25519");
        if ("rsa".equals(type)) { cmd.add("-b"); cmd.add(String.valueOf(bits)); } // для RSA задаём битность
        cmd.add("-C"); cmd.add(comment == null ? "" : comment);                   // комментарий в ключе
        cmd.add("-f"); cmd.add(identityFile);                                     // файл приватного ключа
        cmd.add("-N"); cmd.add(passphrase == null ? "" : passphrase);             // passphrase (пустая строка = без пароля)

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = readAll(p.getInputStream());
        int code = p.waitFor();
        if (code != 0) throw new IOException("ssh-keygen завершился с кодом="+code+". Вывод:\n"+out);
        log.info("SSH ключ сгенерирован: " + identityFile);
    }

    private static void tryAddToAgent(String sshAddPath, String identityFile, Logger log) {
        if (identityFile == null || identityFile.isBlank()) return;
        try {
            List<String> cmd = List.of(sshAddPath, identityFile);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = readAll(p.getInputStream());
            int code = p.waitFor();
            if (code == 0) log.info("Ключ добавлен в ssh-agent: " + identityFile);
            else log.error("ssh-add завершился с кодом="+code+". Вывод:\n"+out);
        } catch (Exception e) { log.error("Ошибка ssh-add: " + e.getMessage()); }
    }

    // =========================================================================================
    // OpenSSH runner: генерирует ssh_config, запускает ssh.exe, ждёт поднятия портов, выводит JSON
    // =========================================================================================
    private static final class OpenSshRunner {
        private final String sshPath, host, user, knownHosts;
        private final int port, keepAlive;
        private final String identityFile;
        private final boolean strict;
        private final ProxyJump proxy;
        private final List<Forward> forwards;
        private final Logger log;

        private final boolean printJson;  // печатать JSON в stdout
        private final String jsonPath;    // и/или писать в файл
        private boolean jsonEmitted = false;

        private Process proc;
        private Path tempDir, sshConfig;

        OpenSshRunner(String sshPath, String host, int port, String user,
                      String identityFile, boolean strict, String knownHosts,
                      int keepAlive, ProxyJump proxy, List<Forward> forwards, Logger log,
                      boolean printJson, String jsonPath) {
            this.sshPath=sshPath; this.host=host; this.port=port; this.user=user;
            this.identityFile=identityFile; this.strict=strict; this.knownHosts=knownHosts;
            this.keepAlive=keepAlive; this.proxy=proxy; this.forwards=forwards; this.log=log;
            this.printJson = printJson; this.jsonPath = jsonPath;
        }

        // Запускает ssh.exe с временным ssh_config. Никаких интерактивных запросов (BatchMode yes).
        void start() throws Exception {
            cleanup(); // на случай повтора
            tempDir = Files.createTempDirectory("ptw-ssh-");
            sshConfig = tempDir.resolve("ssh_config");

            // Формируем минимальный, но достаточный ssh_config
            List<String> cfg = new ArrayList<>();
            cfg.add("Host target");
            cfg.add("  HostName " + host);
            cfg.add("  Port " + port);
            cfg.add("  User " + user);
            cfg.add("  ServerAliveInterval " + keepAlive);
            cfg.add("  TCPKeepAlive yes");
            cfg.add("  ExitOnForwardFailure yes"); // упасть, если форвард не удалось поднять
            cfg.add("  BatchMode yes");            // не задавать вопросов в консоли

            if (identityFile != null && !identityFile.isBlank())
                cfg.add("  IdentityFile " + identityFile.replace("\\","\\\\"));

            // Добавим ProxyJump (если включён)
            cfg.addAll(proxy.toConfigLines());

            // Изоляция или строгая проверка known_hosts
            if (strict) {
                if (knownHosts != null && !knownHosts.isBlank())
                    cfg.add("  UserKnownHostsFile " + knownHosts.replace("\\","\\\\"));
            } else {
                cfg.add("  StrictHostKeyChecking no");
                cfg.add("  UserKnownHostsFile NUL"); // Windows-эквивалент /dev/null
            }

            // Локальные форварды
            for (Forward f : forwards) {
                cfg.add(String.format("  LocalForward %s:%d %s:%d", f.lba, f.lp, f.rh, f.rp));
            }

            Files.writeString(sshConfig,
                    String.join(System.lineSeparator(), cfg)+System.lineSeparator(),
                    StandardCharsets.UTF_8);

            // Команда запуска ssh (используем alias "target" из ssh_config)
            List<String> cmd = new ArrayList<>();
            cmd.add(sshPath);
            cmd.add("-F"); cmd.add(sshConfig.toString());
            cmd.add("-N");                    // не запускать удалённую команду (только туннели)
            cmd.add("target");

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);     // stdout+stderr в один поток
            proc = pb.start();
            jsonEmitted = false;
            log.debug("Started OpenSSH: " + cmd);
        }

        // Ждём, пока все локальные порты станут доступными для подключения.
        void waitUp(Duration timeout) throws Exception {
            long deadline = System.nanoTime() + (timeout==null?Duration.ofSeconds(10):timeout).toNanos();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                while (System.nanoTime() < deadline) {
                    if (!proc.isAlive()) {
                        String out = drain(br);
                        throw new IOException("ssh exited early. Output:\n" + out);
                    }
                    boolean all = true;
                    for (Forward f : forwards) {
                        if (!canConnect(f.lba, f.lp, 200)) { all = false; break; }
                    }
                    if (all) { log.info("All forwards are up."); return; }
                    // Очищаем буфер вывода, чтобы процесс не блокировался при многословном ssh -v
                    while (br.ready()) br.readLine();
                    Thread.sleep(150);
                }
            }
            throw new IOException("Timeout waiting for local forwards.");
        }

        // Печатает JSON с "итоговой картой" форвардов (однократно после подъёма).
        void emitJsonOnce() {
            if (jsonEmitted) return;
            jsonEmitted = true;

            Map<String,Object> root = new LinkedHashMap<>();
            root.put("sshHost", host);
            root.put("sshPort", port);
            root.put("sshUser", user);
            root.put("proxyJump", proxy.asString());
            List<Map<String,Object>> arr = new ArrayList<>();
            for (Forward f : forwards) {
                Map<String,Object> m = new LinkedHashMap<>();
                m.put("localBindAddr", f.lba);
                m.put("localPort", f.lp);
                m.put("remoteHost", f.rh);
                m.put("remotePort", f.rp);
                arr.add(m);
            }
            root.put("forwards", arr);

            String json = toJson(root);
            if (printJson) System.out.println(json);
            if (jsonPath != null && !jsonPath.isBlank()) {
                try {
                    Path p = Paths.get(jsonPath);
                    Files.createDirectories(p.getParent());
                    Files.writeString(p, json, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                    log.info("Forwards JSON written to: " + p);
                } catch (IOException e) {
                    log.error("Failed to write forwards JSON: " + e.getMessage());
                }
            }
        }

        // Ожидаем завершение ssh.exe (обычно происходит по Ctrl+C), параллельно читаем вывод.
        void waitForExit() throws IOException, InterruptedException {
            pump(proc.getInputStream(), log);
            proc.waitFor();
        }

        // Остановка и зачистка временных файлов.
        void stop() {
            if (proc != null) proc.destroy();
            cleanup();
        }

        private void cleanup() {
            if (sshConfig != null) try { Files.deleteIfExists(sshConfig);} catch (IOException ignored){}
            if (tempDir != null) {
                try (var s = Files.list(tempDir)) { s.forEach(p->{try{Files.deleteIfExists(p);}catch(IOException ignored){}}); }
                catch (IOException ignored){}
                try { Files.deleteIfExists(tempDir);} catch (IOException ignored){}
            }
            sshConfig=null; tempDir=null;
        }
    }

    // =========================================================================================
    // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ (сеть, JSON, логирование, retry и т.п.)
    // =========================================================================================

    // Описание одного форварда (локально → удалённо).
    private static final class Forward {
        final String lba;  // local bind address (например, 127.0.0.1)
        final int lp;      // local port (0 → выбрать свободный)
        final String rh;   // remote host (с точки зрения удалённого SSH-сервера)
        final int rp;      // remote port (сервис на удалёнке)

        Forward(String lba,int lp,String rh,int rp){this.lba=lba;this.lp=lp;this.rh=rh;this.rp=rp;}
        public String toString(){ return lba+":"+lp+" -> "+rh+":"+rp; }
    }

    // Проверить, что к локальному порту можно подключиться.
    private static boolean canConnect(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) { s.connect(new InetSocketAddress(host, port), timeoutMs); return true; }
        catch (IOException e) { return false; }
    }

    // Подобрать свободный локальный порт, привязанный к указанному адресу.
    private static int findFreePort(String bindAddr) throws IOException {
        try (ServerSocket ss = new ServerSocket()) { ss.bind(new InetSocketAddress(bindAddr,0)); return ss.getLocalPort(); }
    }

    // Асинхронно «откачиваем» вывод процесса, чтобы не зависал на переполнении буфера.
    private static void pump(InputStream is, Logger log) {
        new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String ln; while ((ln = br.readLine()) != null) log.debug("[ssh] " + ln);
            } catch (IOException ignored) {}
        }, "ssh-out").start();
    }

    // Утилиты чтения stdout/stderr процесса.
    private static String readAll(InputStream is) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb=new StringBuilder(); String ln; while((ln=br.readLine())!=null) sb.append(ln).append('\n'); return sb.toString();
        } catch(IOException e){ return ""; }
    }
    private static String drain(BufferedReader br) throws IOException { StringBuilder sb=new StringBuilder(); String ln;
        while((ln=br.readLine())!=null) sb.append(ln).append('\n'); return sb.toString(); }

    // Простой JSON-писатель (для вывода результатов). Поддерживает Map/List/String/Number/Boolean/null.
    private static String toJson(Object v) {
        StringBuilder sb = new StringBuilder();
        writeJson(v, sb);
        return sb.toString();
    }
    @SuppressWarnings("unchecked")
    private static void writeJson(Object v, StringBuilder sb) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { sb.append('"').append(escape((String)v)).append('"'); return; }
        if (v instanceof Number || v instanceof Boolean) { sb.append(String.valueOf(v)); return; }
        if (v instanceof Map) {
            sb.append('{'); boolean first=true;
            for (var e : ((Map<String,Object>)v).entrySet()) {
                if (!first) sb.append(','); first=false;
                sb.append('"').append(escape(e.getKey())).append("\":");
                writeJson(e.getValue(), sb);
            }
            sb.append('}'); return;
        }
        if (v instanceof List) {
            sb.append('['); boolean first=true;
            for (Object x : (List<?>)v) { if (!first) sb.append(','); first=false; writeJson(x, sb); }
            sb.append(']'); return;
        }
        sb.append('"').append(escape(String.valueOf(v))).append('"');
    }
    private static String escape(String s){
        StringBuilder r=new StringBuilder();
        for(char c: s.toCharArray()){
            switch(c){
                case '"': r.append("\\\""); break;
                case '\\': r.append("\\\\"); break;
                case '\b': r.append("\\b"); break;
                case '\f': r.append("\\f"); break;
                case '\n': r.append("\\n"); break;
                case '\r': r.append("\\r"); break;
                case '\t': r.append("\\t"); break;
                default:
                    if (c < 32) r.append(String.format("\\u%04x",(int)c)); else r.append(c);
            }
        }
        return r.toString();
    }

    // Параметры авто‑перезапуска (retry with backoff).
    private static final class RetryPolicy {
        final boolean enabled; final long initialDelayMs, maxDelayMs; final double multiplier;
        RetryPolicy(boolean e,long i,long m,double k){enabled=e;initialDelayMs=i;maxDelayMs=m;multiplier=k;}
        static RetryPolicy from(Map<String,Object> cfg){
            Map<String,Object> r = optObj(cfg,"retry", Map.of());
            boolean en = optBool(r,"enabled", true);
            long id = optLong(r,"initialDelayMs", 1000);
            long md = optLong(r,"maxDelayMs", 30000);
            double mul = optDouble(r,"multiplier", 2.0);
            return new RetryPolicy(en,id,md,mul);
        }
    }

    // ===== ЛЁГКИЙ JSON‑ПАРСЕР (объекты/массивы/строки/числа/bool/null). Без зависимостей. =====
    private static Map<String,Object> readJsonFile(Path p) throws IOException {
        String s = Files.readString(p, StandardCharsets.UTF_8);
        return asObj(parseJson(s));
    }
    private static Object parseJson(String s){ return new JsonTok(s).parseValue(); }
    @SuppressWarnings("unchecked") private static Map<String,Object> asObj(Object o){ if(!(o instanceof Map)) throw new IllegalArgumentException("Root JSON must be object"); return (Map<String,Object>)o; }
    @SuppressWarnings("unchecked") private static List<Map<String,Object>> reqArr(Map<String,Object> m,String k){ Object v=m.get(k); if(!(v instanceof List)) throw new IllegalArgumentException("Missing array: "+k); return (List<Map<String,Object>>) v; }
    private static String reqStr(Map<String,Object> m,String k){ Object v=m.get(k); if(v==null) throw new IllegalArgumentException("Missing key: "+k); return String.valueOf(v); }
    private static String optStr(Map<String,Object> m,String k,String def){ Object v=m.get(k); return v==null?def:String.valueOf(v); }
    private static int optInt(Map<String,Object> m,String k,int def){ Object v=m.get(k); return v==null?def:Integer.parseInt(String.valueOf(v)); }
    private static long optLong(Map<String,Object> m,String k,long def){ Object v=m.get(k); return v==null?def:Long.parseLong(String.valueOf(v)); }
    private static double optDouble(Map<String,Object> m,String k,double def){ Object v=m.get(k); return v==null?def:Double.parseDouble(String.valueOf(v)); }
    private static boolean optBool(Map<String,Object> m,String k,boolean def){ Object v=m.get(k); return v==null?def:Boolean.parseBoolean(String.valueOf(v)); }
    @SuppressWarnings("unchecked") private static Map<String,Object> optObj(Map<String,Object> m,String k,Map<String,Object> def){ Object v=m.get(k); return v instanceof Map?(Map<String,Object>)v:def; }

    // Простой лексер/парсер JSON.
    private static final class JsonTok {
        final String s; int i=0,n;
        JsonTok(String s){this.s=s; this.n=s.length(); skip();}
        void skip(){ while(i<n){ char c=s.charAt(i); if(c<=32) i++; else break; } }
        char peek(){ return i<n? s.charAt(i): '\0'; } char next(){ return i<n? s.charAt(i++): '\0'; }
        Object parseValue(){ skip(); char c=peek();
            if (c=='{') return parseObj(); if (c=='[') return parseArr(); if (c=='"') return parseStr();
            if (c=='t'||c=='f') return parseBool(); if (c=='n') return parseNull(); return parseNum(); }
        Map<String,Object> parseObj(){ Map<String,Object> m=new LinkedHashMap<>(); expect('{'); skip();
            if (peek()=='}'){ next(); return m; }
            while(true){ String k=parseStr(); skip(); expect(':'); Object v=parseValue(); m.put(k,v); skip();
                char c=next(); if (c=='}') break; if (c!=',') throw err("expected , or }"); skip(); }
            return m; }
        List<Object> parseArr(){ List<Object> a=new ArrayList<>(); expect('['); skip();
            if (peek()==']'){ next(); return a; }
            while(true){ a.add(parseValue()); skip(); char c=next(); if (c==']') break; if (c!=',') throw err("expected , or ]"); skip(); }
            return a; }
        String parseStr(){ expect('"'); StringBuilder sb=new StringBuilder();
            while(true){ if(i>=n) throw err("unterminated string"); char c=next(); if(c=='"') break;
                if(c=='\\'){ char e=next();
                    switch(e){ case '"':sb.append('"');break; case '\\':sb.append('\\');break; case '/':sb.append('/');break;
                        case 'b':sb.append('\b');break; case 'f':sb.append('\f');break; case 'n':sb.append('\n');break;
                        case 'r':sb.append('\r');break; case 't':sb.append('\t');break; case 'u':
                            String hex=s.substring(i,i+4); sb.append((char)Integer.parseInt(hex,16)); i+=4; break;
                        default: throw err("bad escape"); } } else sb.append(c); }
            return sb.toString(); }
        Number parseNum(){ int st=i; boolean dot=false,exp=false; if(peek()=='-') next();
            while(i<n){ char c=peek();
                if(c>='0'&&c<='9'){ next(); continue; }
                if(c=='.'){ dot=true; next(); continue; }
                if(c=='e'||c=='E'){ exp=true; next(); if(peek()=='+'||peek()=='-') next(); continue; } break; }
            String t=s.substring(st,i);
            try { if(dot||exp) return Double.parseDouble(t); long v=Long.parseLong(t); return (v>=Integer.MIN_VALUE&&v<=Integer.MAX_VALUE)?(int)v:v; }
            catch(Exception e){ throw err("bad number: "+t); } }
        Boolean parseBool(){ if(match("true")) return true; if(match("false")) return false; throw err("bad bool"); }
        Object parseNull(){ if(match("null")) return null; throw err("bad null"); }
        boolean match(String w){ int L=w.length(); if(i+L<=n && s.regionMatches(i,w,0,L)){ i+=L; return true; } return false; }
        void expect(char ch){ if(next()!=ch) throw err("expected "+ch); }
        RuntimeException err(String m){ return new RuntimeException(m+" at pos "+i); }
    }

    // Простой логгер с уровнями (silent/error/info/debug)
    private static final class Logger {
        enum L { SILENT, ERROR, INFO, DEBUG }
        final L level;
        Logger(String lvl){
            switch(String.valueOf(lvl).toLowerCase(Locale.ROOT)){
                case "silent": level=L.SILENT; break;
                case "error":  level=L.ERROR;  break;
                case "debug":  level=L.DEBUG;  break;
                default:       level=L.INFO;   break;
            }
        }
        void info(String s){ if (level.ordinal()>=L.INFO.ordinal()) System.out.println(s); }
        void error(String s){ if (level.ordinal()>=L.ERROR.ordinal()) System.err.println(s); }
        void debug(String s){ if (level==L.DEBUG) System.out.println(s); }
    }

    private static String stackTrace(Throwable t){
        StringWriter sw=new StringWriter(); t.printStackTrace(new PrintWriter(sw)); return sw.toString();
    }
}
