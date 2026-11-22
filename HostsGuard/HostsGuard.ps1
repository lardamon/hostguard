# HostsGuard - следит за обходными IP в hosts и меняет их, только когда текущий перестал работать.
# Совместим с Windows PowerShell 5.1. Запускается от администратора/SYSTEM.
# Когда IP из списков умерли, сам спрашивает новые у DNS-сервисов обхода (GeoHide, Comss, DNS-AI, KeyOneDay).
#   -Group 'Gemini'      проверить только эти группы (через запятую) и поставить для них лучший IP
#   -Fastest             проверить все группы и поставить самый быстрый IP, даже если текущий работает
param([switch]$Fastest, [string]$Group = '')

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
if ($env:HG_DIR) { $Root = $env:HG_DIR }
$IsWin = ($env:OS -eq 'Windows_NT')
if ($env:HG_HOSTS) { $HostsPath = $env:HG_HOSTS } else { $HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }
if ($env:HG_CURL) { $Curl = $env:HG_CURL }
elseif ($IsWin -and (Test-Path (Join-Path $env:SystemRoot 'System32\curl.exe'))) { $Curl = Join-Path $env:SystemRoot 'System32\curl.exe' }
else { $Curl = 'curl' }
$LogPath = Join-Path $Root 'log.txt'
$BackupDir = Join-Path $Root 'backups'
$TmpDir = Join-Path $Root 'tmp'
$SourcePath = Join-Path $Root 'ips_source.txt'    # IP, скачанные из списка GeoHide
$FoundPath = Join-Path $Root 'ips_found.txt'      # IP, которые выдали DNS-сервисы обхода и которые реально ответили
# DNS-сервисы обхода: у них спрашиваем, какой обходной IP они выдают прямо сейчас (так находятся новые IP,
# когда старые умерли). Встроены в скрипт, чтобы работали и со старым config.txt; свои можно дописать в config.txt.
$DefaultDoh = @('https://geohide.ru/dns-query', 'https://eu.geohide.ru/dns-query', 'https://us.geohide.ru/dns-query', 'https://dns.comss.one/dns-query', 'https://dns.dns-ai.ru/dns-query', 'https://dns.keyoneday.ru/dns-query')
# Настоящие сети самих сайтов (Anthropic, Cloudflare, Google). IP из этих сетей - не обход: по нему Россия закрыта,
# а curl этого не отличит. Такие IP никогда не ставим, откуда бы они ни пришли.
$DefaultReal = @('160.79.104.0/21',
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '8.8.4.0/24', '8.8.8.0/24', '34.0.0.0/8', '35.184.0.0/13', '64.233.160.0/19', '66.102.0.0/20', '66.249.64.0/19', '72.14.192.0/18', '74.125.0.0/16', '108.177.0.0/17', '142.250.0.0/15', '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16', '192.178.0.0/15', '209.85.128.0/17', '216.58.192.0/19', '216.239.32.0/19',
    '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16')
$Inv = [Globalization.CultureInfo]::InvariantCulture
$DefaultIps = @('37.230.192.51', '46.8.158.6', '45.155.204.190', '5.175.161.3', '5.175.161.40', '45.13.237.213', '31.25.239.132', '143.20.64.192', '192.255.159.240', '192.255.159.241', '192.3.233.253', '107.175.76.134', '159.194.200.33', '193.233.112.67', '193.233.112.68', '193.233.112.88', '185.87.51.182', '185.246.223.127')   # если config.txt испорчен
$BeginMark = '# >>> HostsGuard: этот блок правится автоматически, домены и IP меняй в config.txt'
$EndMark = '# <<< HostsGuard'

function Log([string]$msg) {
    $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $msg
    Write-Host $line
    try { [IO.File]::AppendAllText($LogPath, $line + "`r`n", [Text.Encoding]::UTF8) } catch {}
}

# ---------- config ----------
function Read-Config($path) {
    $cfg = @{ settings = @{ interval = 60; timeout = 8; keep_backups = 10; ip_source = 'https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts'; source_hours = 12 }; ips = New-Object System.Collections.ArrayList; groups = New-Object System.Collections.ArrayList; doh = New-Object System.Collections.ArrayList; real = New-Object System.Collections.ArrayList }
    $sec = ''; $g = $null
    foreach ($raw in [IO.File]::ReadAllLines($path, [Text.Encoding]::UTF8)) {
        $l = $raw.Trim()
        if ($l -eq '' -or $l.StartsWith('#')) { continue }
        if ($l -match '^\[\s*group\s+(.+?)\s*\]$') {
            $sec = 'group'
            $g = @{ name = $Matches[1]; test = ''; bad = ''; pattern = ''; explicitTest = $false; domains = New-Object System.Collections.ArrayList }
            [void]$cfg.groups.Add($g); continue
        }
        if ($l -match '^\[\s*(\w+)\s*\]$') { $sec = $Matches[1].ToLower(); continue }
        if ($sec -eq 'settings' -and $l -match '^(\w+)\s*=\s*(.+)$') {
            $k = $Matches[1].ToLower(); $v = $Matches[2].Trim()
            if ($k -eq 'doh') { if ($v -match '^https://' -and -not $cfg.doh.Contains($v)) { [void]$cfg.doh.Add($v) } }   # строк doh может быть несколько
            else { $cfg.settings[$k] = $v }
            continue
        }
        if ($sec -eq 'real') { foreach ($t in ($l -split '\s+')) { if ($t -match '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$' -and -not $cfg.real.Contains($t)) { [void]$cfg.real.Add($t) } }; continue }
        if ($sec -eq 'ip') { foreach ($t in ($l -split '\s+')) { if ($t -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $cfg.ips.Contains($t)) { [void]$cfg.ips.Add($t) } }; continue }
        if ($sec -eq 'group') {
            if ($l -match '^(test|bad|pattern)\s*=\s*(.+)$') { $g[$Matches[1].ToLower()] = $Matches[2].Trim(); if ($Matches[1].ToLower() -eq 'test') { $g.explicitTest = $true }; continue }
            foreach ($t in ($l -split '\s+')) {
                $d = $t.ToLower()
                if ($d -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $d = "$d.frame.claudeusercontent.com" }
                if (-not $g.domains.Contains($d)) { [void]$g.domains.Add($d) }
            }
        }
    }
    foreach ($g in $cfg.groups) {
        if (-not $g.test -and $g.domains.Count -gt 0) { $g.test = 'https://' + $g.domains[0] + '/' }
    }
    return $cfg
}

function Read-IpFile($path) {
    $r = @()
    if (Test-Path $path) { foreach ($l in [IO.File]::ReadAllLines($path)) { $t = $l.Trim(); if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { $r += $t } } }
    return $r
}

# ---------- настоящий адрес сайта или обходной ----------
function Ip-ToNum([string]$ip) {
    $p = $ip.Split('.'); if ($p.Count -ne 4) { return $null }
    [double]$n = 0
    foreach ($o in $p) { $b = 0; if (-not [int]::TryParse($o, [ref]$b) -or $b -lt 0 -or $b -gt 255) { return $null }; $n = $n * 256 + $b }
    return $n
}
function Test-RealIp([string]$ip) {
    # $true = этот IP ставить нельзя: это сеть самого сайта, локальный адрес или мусор
    $n = Ip-ToNum $ip
    if ($null -eq $n) { return $true }
    foreach ($c in $script:RealNets) {
        $parts = $c.Split('/'); $base = Ip-ToNum $parts[0]
        if ($null -eq $base) { continue }
        $bits = 32; if ($parts.Count -gt 1) { [void][int]::TryParse($parts[1], [ref]$bits) }
        if ($bits -lt 0 -or $bits -gt 32) { continue }
        $size = [math]::Pow(2, 32 - $bits); $start = [math]::Floor($base / $size) * $size
        if ($n -ge $start -and $n -lt ($start + $size)) { return $true }
    }
    return $false
}

# Есть ли вообще интернет: открываем сайт, который в России точно не заблокирован.
function Test-Internet {
    $tmp = Join-Path $TmpDir 'inet.txt'
    foreach ($u in @('https://ya.ru/', 'https://www.rbc.ru/')) {
        $code = ''
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $code = [string](& $Curl -s -o $tmp --ssl-no-revoke --max-time 6 -w '%{http_code}' $u 2>$null) } catch {}
        $ErrorActionPreference = $old
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $c = 0; [void][int]::TryParse($code.Trim(), [ref]$c)
        if ($c -gt 0) { return $true }
    }
    return $false
}

# Свежий список IP из GitHub (GeoHide публикует свои адреса в шапке hosts). Не чаще раза в source_hours часов.
function Update-SourceIps($cfg) {
    $url = $cfg.settings.ip_source
    if (-not ($url -match '^https://')) { return }   # ip_source = нет - не скачивать
    $hours = 12; [void][int]::TryParse([string]$cfg.settings.source_hours, [ref]$hours)
    if ((Test-Path $SourcePath) -and ((Get-Date) - (Get-Item $SourcePath).LastWriteTime).TotalHours -lt $hours) { return }
    $tmp = Join-Path $TmpDir 'source.txt'
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Curl -s -L --ssl-no-revoke --max-time 20 -o $tmp $url 2>$null | Out-Null } catch {}
    $ErrorActionPreference = $old
    if (-not (Test-Path $tmp)) { Log 'список IP с GitHub не скачался - беру прошлый'; return }
    $ips = @()
    foreach ($l in [IO.File]::ReadAllLines($tmp, [Text.Encoding]::UTF8)) {
        $t = $l.Trim()
        if ($t -eq '') { continue }
        if (-not $t.StartsWith('#')) { break }           # шапка кончилась
        if ($t -match '^#\s*(\d{1,3}(\.\d{1,3}){3})\s*$') { $ips += $Matches[1] }
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    if ($ips.Count -eq 0) { Log 'в списке с GitHub не нашёл IP - беру прошлый'; return }
    $prev = @(Read-IpFile $SourcePath)
    [IO.File]::WriteAllLines($SourcePath, [string[]]$ips)
    $new = @($ips | Where-Object { $prev -notcontains $_ })
    if ($new.Count -and $prev.Count) { Log ('список IP с GitHub обновлён, новые: ' + ($new -join ', ')) }
}

# ---------- hosts ----------
function Read-Hosts($path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $enc = New-Object System.Text.UTF8Encoding($bom, $true)
    try { $text = $enc.GetString($bytes) } catch { $enc = [Text.Encoding]::Default; $text = $enc.GetString($bytes) }
    if ($bom -and $text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    return @{ text = $text; enc = $enc }
}

function Parse-Entry([string]$line) {
    # возвращает @{ip; names; comment} или $null для комментариев/пустых
    $body = $line; $comment = ''
    $i = $line.IndexOf('#')
    if ($i -ge 0) { $body = $line.Substring(0, $i); $comment = $line.Substring($i) }
    $parts = @($body.Trim() -split '\s+' | Where-Object { $_ -ne '' })
    if ($parts.Count -lt 2) { return $null }
    return @{ ip = $parts[0]; names = @($parts[1..($parts.Count - 1)]); comment = $comment }
}

# ---------- проверка (все IP параллельно) ----------
$script:probeN = 0
function Quote-Arg([string]$s) { if ($s -match '[\s"|%&^<>]') { return '"' + $s.Replace('"', '\"') + '"' } return $s }

function Start-Probe($group, [string]$target, [int]$timeout) {
    # target: IP, либо 'doh:<url>' - тогда IP подбирает сам DNS-сервис (так находятся новые IP)
    $script:probeN++
    $uri = [uri]$group.test
    $bodyFile = Join-Path $TmpDir ('p{0}.txt' -f $script:probeN)
    $a = @('-s', '-o', $bodyFile, '--ssl-no-revoke', '--max-time', "$timeout")
    if ($target.StartsWith('doh:')) { $a += @('-4', '--doh-url', $target.Substring(4)) } else { $a += @('--resolve', ($uri.Host + ':443:' + $target)) }
    $a += @('-w', '%{http_code}|%{time_total}|%{redirect_url}|%{remote_ip}', $group.test)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Curl
    $psi.Arguments = ($a | ForEach-Object { Quote-Arg $_ }) -join ' '
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = $null
    try { $p = [Diagnostics.Process]::Start($psi) } catch {}
    return @{ p = $p; target = $target; body = $bodyFile; outTask = $(if ($p) { $p.StandardOutput.ReadToEndAsync() } else { $null }); errTask = $(if ($p) { $p.StandardError.ReadToEndAsync() } else { $null }) }
}

function Finish-Probe($group, $pr, [int]$timeout) {
    $out = ''; $exit = -1
    if ($pr.p) {
        if (-not $pr.p.WaitForExit(($timeout + 10) * 1000)) { try { $pr.p.Kill() } catch {} }
        try { $out = $pr.outTask.Result.Trim() } catch {}
        try { $exit = $pr.p.ExitCode } catch {}
    }
    $p = $out.Split('|')
    $code = 0; $time = 99.0; $redir = ''; $rip = ''
    if ($p.Count -ge 2) { [void][int]::TryParse($p[0], [ref]$code); [void][double]::TryParse($p[1], [Globalization.NumberStyles]::Float, $Inv, [ref]$time) }
    if ($p.Count -ge 3) { $redir = $p[2] }
    if ($p.Count -ge 4) { $rip = $p[3] }
    $body = ''
    if (Test-Path $pr.body) {
        try { $body = [IO.File]::ReadAllText($pr.body); if ($body.Length -gt 300000) { $body = $body.Substring(0, 300000) } } catch {}
        Remove-Item $pr.body -Force -ErrorAction SilentlyContinue
    }
    $ip = $pr.target; $viaDns = $false
    if ($ip.StartsWith('doh:')) { $ip = $rip; $viaDns = $true; if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { $ip = '' } }
    # tier: 2 = хорошо (2xx/3xx), 1 = отвечает с ошибкой 4xx, 0 = мёртв/забанен
    $tier = 0; $why = "код $code"
    if ($code -eq 0) {
        # почему не ответил - по коду выхода curl, чтобы в журнале была причина, а не просто "нет"
        if ($exit -eq 28) { $why = "молчит (нет ответа за $timeout с)" }
        elseif ($exit -eq 7) { $why = 'не соединяется (порт закрыт или IP заблокирован)' }
        elseif ($exit -eq 35 -or $exit -eq 56 -or $exit -eq 52 -or $exit -eq 16 -or $exit -eq 92) { $why = 'соединение оборвано (сервер не обслуживает этот сайт или его режет провайдер)' }
        elseif ($exit -eq 60 -or $exit -eq 51 -or $exit -eq 77) { $why = 'чужой сертификат (это не обходной сервер)' }
        elseif ($exit -eq 6 -or $exit -eq 5) { $why = 'DNS-сервис не ответил' }
        elseif ($exit -eq 2 -or $exit -eq 4 -or $exit -eq 1) { $why = "curl на этом ПК не умеет такой запрос (код $exit)" }
        elseif ($exit -eq -1) { $why = 'curl не запустился' }
        else { $why = "нет ответа (curl код $exit)" }
    }
    elseif ($group.bad -and (($redir -and $redir.Contains($group.bad)) -or $body.Contains($group.bad))) { $why = "код $code -> $($group.bad) (Google забанил этот IP)" }
    elseif ($code -eq 429) { $why = 'код 429 (лимит)' }
    elseif ($code -ge 200 -and $code -lt 400) { $tier = 2 }
    elseif ($code -ge 400 -and $code -lt 500) { $tier = 1 }
    # DNS-сервис мог выдать настоящий адрес сайта вместо обходного - такой IP не берём
    if ($viaDns -and $tier -gt 0 -and (Test-RealIp $ip)) { $tier = 0; $why = 'DNS выдал настоящий адрес сайта, а не обходной' }
    return @{ ip = $ip; code = $code; time = $time; tier = $tier; why = $why; dns = $viaDns; target = $pr.target }
}

function Test-Many($group, [string[]]$targets, [int]$timeout) {
    $started = @(); foreach ($t in $targets) { $started += (Start-Probe $group $t $timeout) }
    $res = @(); foreach ($s in $started) { $res += (Finish-Probe $group $s $timeout) }
    return $res
}

function Fmt($r) {
    $tag = ''; if ($r.dns) { $tag = ' [найден через DNS]' }
    if ($r.tier -gt 0) { return ('{0} ({1}, {2} c){3}' -f $r.ip, $r.code, $r.time.ToString('0.00', $Inv), $tag) } else { return ('{0} ({1}){2}' -f $r.ip, $r.why, $tag) }
}

# ---------- основной ход ----------
# Замок от двойного запуска. Права даём SYSTEM и администраторам, чтобы фоновая задача (SYSTEM)
# и ручной запуск из cmd видели один и тот же замок, а не падали с "Отказано в доступе".
$mutex = $null
try {
    $created = $false
    if ($IsWin) {
        $sec = New-Object System.Security.AccessControl.MutexSecurity
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $sec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule($who, 'FullControl', 'Allow')))
        }
        $mutex = [System.Threading.Mutex]::new($false, 'Global\HostsGuard', [ref]$created, $sec)
    } else { $mutex = [System.Threading.Mutex]::new($false, 'HostsGuardTest') }
}
catch {
    Write-Host 'Сейчас идёт фоновая проверка (задача планировщика). Подожди минуту и запусти снова.'
    exit 0
}
try { $gotIt = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $gotIt = $true }
if (-not $gotIt) { Write-Host 'Уже идёт другая проверка, подожди минуту и запусти снова.'; exit 0 }
try {
    foreach ($d in @($BackupDir, $TmpDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null } }
    $cfg = Read-Config (Join-Path $Root 'config.txt')
    $timeout = [int]$cfg.settings.timeout
    Update-SourceIps $cfg

    # настоящие сети сайтов: встроенный список + секция [real] из config.txt
    $script:RealNets = @($DefaultReal) + @($cfg.real)
    # DNS-сервисы обхода: встроенные + строки doh из config.txt. use_dns = no - не спрашивать их совсем.
    $dohUrls = New-Object System.Collections.ArrayList
    if ([string]$cfg.settings.use_dns -notmatch '^(no|нет|0|off)$') { foreach ($u in @($DefaultDoh) + @($cfg.doh)) { if (-not $dohUrls.Contains($u)) { [void]$dohUrls.Add($u) } } }

    # все IP-кандидаты: config.txt + список с GitHub + те, что раньше выдали DNS-сервисы обхода.
    # IP из настоящих сетей сайтов выкидываем сразу.
    $allIps = New-Object System.Collections.ArrayList
    $foundIps = @(Read-IpFile $FoundPath)
    foreach ($ip in @($cfg.ips) + @(Read-IpFile $SourcePath) + $foundIps) { if (-not $allIps.Contains($ip) -and -not (Test-RealIp $ip)) { [void]$allIps.Add($ip) } }
    $newFound = New-Object System.Collections.ArrayList
    if ($cfg.ips.Count -eq 0) {
        Log ('в config.txt не нашёл ни одного IP (групп: {0}) - беру встроенный список' -f $cfg.groups.Count)
        foreach ($ip in $DefaultIps) { if (-not $allIps.Contains($ip)) { [void]$allIps.Add($ip) } }
    }
    if ($cfg.groups.Count -eq 0) { Log 'ОШИБКА: в config.txt нет ни одной группы - запусти УСТАНОВИТЬ.cmd ещё раз, он положит рабочий config.txt.'; exit 1 }

    $only = @(); if ($Group) { $only = @($Group -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }) }
    if ($only.Count) {
        $known = @($cfg.groups | ForEach-Object { $_.name.ToLower() })
        $miss = @($only | Where-Object { $known -notcontains $_ })
        if ($miss.Count) { Log ('нет такой группы в config.txt: ' + ($miss -join ', ')); exit 1 }
        Log ('--- проверка только: ' + $Group + ' ---')
    }

    $h = Read-Hosts $HostsPath
    $lines = @($h.text -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[-1] -eq '') { $lines = $lines[0..($lines.Count - 2)] }

    # что сейчас в hosts: имя -> IP (первая встреча побеждает, как у Windows)
    $nameIp = @{}; $nameOrder = New-Object System.Collections.ArrayList   # порядок как в hosts, чтобы файл не перемешивался
    foreach ($l in $lines) { $e = Parse-Entry $l; if ($e) { foreach ($n in $e.names) { $k = $n.ToLower(); if (-not $nameIp.ContainsKey($k)) { $nameIp[$k] = $e.ip; [void]$nameOrder.Add($k) } } } }

    # распределяем имена по группам: явный список, затем pattern (первая подходящая группа)
    $owner = @{}
    foreach ($g in $cfg.groups) { foreach ($d in $g.domains) { if (-not $owner.ContainsKey($d)) { $owner[$d] = $g } } }
    foreach ($n in $nameOrder) {
        if ($owner.ContainsKey($n)) { continue }
        foreach ($g in $cfg.groups) { if ($g.pattern -and $n -match $g.pattern) { $owner[$n] = $g; [void]$g.domains.Add($n); break } }
    }

    $changed = New-Object System.Collections.ArrayList
    $deadGroups = New-Object System.Collections.ArrayList
    $testedGroups = 0
    # сначала группы с явным test = (для них ищем новые IP через DNS), потом остальные - им достаются уже найденные IP
    $checkOrder = @($cfg.groups | Where-Object { $_.explicitTest }) + @($cfg.groups | Where-Object { -not $_.explicitTest })
    foreach ($g in $checkOrder) {
        $g.ip = $null
        if ($g.domains.Count -eq 0 -or -not $g.test) { continue }
        $testHost = ([uri]$g.test).Host.ToLower()
        $cur = $null
        if ($nameIp.ContainsKey($testHost)) { $cur = $nameIp[$testHost] }
        else {
            $votes = @{}
            foreach ($d in $g.domains) { if ($nameIp.ContainsKey($d)) { $votes[$nameIp[$d]] = 1 + [int]$votes[$nameIp[$d]] } }
            if ($votes.Count -gt 0) { $cur = ($votes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key }
        }
        if ($only.Count -and $only -notcontains $g.name.ToLower()) { $g.ip = $cur; continue }   # эту группу сейчас не трогаем
        $testedGroups++
        $force = ($Fastest -or $only.Count -gt 0)

        $rc = $null
        if ($cur -and -not $force) {
            $rc = @(Test-Many $g @($cur) $timeout)[0]
            if ($rc.tier -eq 0) { Start-Sleep -Seconds 3; $rc = @(Test-Many $g @($cur) $timeout)[0] }   # повтор, чтобы не дёргаться из-за случайного сбоя
            if ($rc.tier -eq 2) { Log ("[{0}] ок: {1}" -f $g.name, (Fmt $rc)); $g.ip = $cur; continue }
        }

        if ($rc) { Log ("[{0}] текущий {1} - проверяю все IP" -f $g.name, (Fmt $rc)) }
        elseif ($cur) { Log ("[{0}] проверяю все IP (сейчас стоит {1})" -f $g.name, $cur) }
        else { Log ("[{0}] в hosts нет - проверяю все IP" -f $g.name) }
        $targets = @($allIps | Where-Object { -not ($rc -and $_ -eq $cur) })
        # плюс спрашиваем DNS-сервисы обхода, какой IP они дают сейчас (только для групп с явным test = в config.txt)
        if ($g.explicitTest) { foreach ($u in $dohUrls) { $targets += ('doh:' + $u) } }
        $res = @(Test-Many $g $targets $timeout)
        foreach ($r in $res) { if ($r.dns -and $r.tier -gt 0 -and $r.ip -and -not $allIps.Contains($r.ip)) { [void]$newFound.Add($r.ip); [void]$allIps.Add($r.ip) } }
        if ($rc) { $res += $rc }
        # IP от DNS, который уже есть в списке, не дублируем
        $seen = @{}; $uniq = @()
        foreach ($r in ($res | Sort-Object @{ Expression = { $_.dns }; Descending = $false })) { if ($r.ip -and -not $seen.ContainsKey($r.ip)) { $seen[$r.ip] = 1; $uniq += $r } }
        $ok = @($uniq | Where-Object { $_.tier -gt 0 } | Sort-Object @{ Expression = { $_.tier }; Descending = $true }, @{ Expression = { $_.time }; Descending = $false })
        Log ('    рабочие: ' + $(if ($ok.Count) { ($ok | ForEach-Object { Fmt $_ }) -join ', ' } else { 'нет' }))
        $bannedNow = @($uniq | Where-Object { $_.why -like '*забанил*' })
        if ($bannedNow.Count) { Log ('    забанены Google: ' + (($bannedNow | ForEach-Object { $_.ip }) -join ', ')) }
        if ($ok.Count -eq 0) {
            # причины по каждому виду отказа - чтобы было видно, что именно не так
            $whyIp = @($res | Where-Object { -not $_.dns } | Group-Object { $_.why } | Sort-Object Count -Descending | ForEach-Object { '{0} - {1} шт' -f $_.Name, $_.Count })
            if ($whyIp.Count) { Log ('    IP из списка: ' + ($whyIp -join '; ')) }
            foreach ($r in @($res | Where-Object { $_.dns })) { Log ('    DNS {0}: {1}' -f ([uri]$r.target.Substring(4)).Host, $(if ($r.ip) { $r.ip + ' - ' + $r.why } else { $r.why })) }
            [void]$deadGroups.Add($g.name)
            Log ("    [{0}] рабочих IP в списке нет - оставляю как было" -f $g.name); $g.ip = $cur; continue
        }
        $best = $ok[0]
        if ($only.Count -and $cur) {
            # батник нейронки жмут, когда сайт не работает - значит ставим другой рабочий IP, не текущий
            $other = @($ok | Where-Object { $_.ip -ne $cur })
            if ($other.Count) { $best = $other[0] } else { Log '    других рабочих IP нет - оставляю текущий' }
        }
        if ($rc -and $rc.tier -ge $best.tier -and -not $force) { $g.ip = $cur; Log '    лучше текущего нет - оставляю'; continue }
        $g.ip = $best.ip
        if ($best.ip -ne $cur) { [void]$changed.Add(("{0}: {1} -> {2}" -f $g.name, $(if ($cur) { $cur } else { '(нет)' }), $best.ip)) }
        else { Log '    текущий и так лучший - оставляю' }
    }
    if ($deadGroups.Count) {
        if (Test-Internet) { Log ('ВНИМАНИЕ: сейчас нет рабочего IP для: ' + ($deadGroups -join ', ') + '. Интернет на ПК есть (ya.ru открылся) - значит, до тебя не отвечает ни один известный обходной сервер, причины выше. Через hosts эти сайты сейчас не открыть; скрипт продолжит искать новые IP при каждой проверке.') }
        else { Log ('ВНИМАНИЕ: на ПК сейчас нет интернета (ya.ru тоже не открылся) - дело не в IP. Не проверено: ' + ($deadGroups -join ', ') + '.') }
    }
    # запоминаем IP, которые выдали DNS-сервисы и которые ответили (не больше 60 последних)
    if ($newFound.Count) {
        $keepFound = @(@($foundIps) + @($newFound) | Select-Object -Last 60)
        try { [IO.File]::WriteAllLines($FoundPath, [string[]]$keepFound) } catch {}
        Log ('новые IP от DNS-сервисов обхода: ' + ($newFound -join ', '))
    }

    # собираем новый hosts: строки вне блока без управляемых имён + блок в конце
    $managed = @{}
    foreach ($g in $cfg.groups) { if ($g.ip) { foreach ($d in $g.domains) { $managed[$d] = $true } } }
    $out = New-Object System.Collections.ArrayList
    $inBlock = $false
    foreach ($l in $lines) {
        if ($l.StartsWith('# >>> HostsGuard')) { $inBlock = $true; continue }
        if ($l.StartsWith($EndMark)) { $inBlock = $false; continue }
        if ($inBlock) {
            # строки старого блока, чьи группы сейчас не обслуживаются, сохраняем
            $e = Parse-Entry $l
            if ($e) { $keep = @($e.names | Where-Object { -not $managed.ContainsKey($_.ToLower()) }); if ($keep.Count) { [void]$out.Add($e.ip + ' ' + ($keep -join ' ')) } }
            continue
        }
        $e = Parse-Entry $l
        if (-not $e) { [void]$out.Add($l); continue }
        $keep = @($e.names | Where-Object { -not $managed.ContainsKey($_.ToLower()) })
        if ($keep.Count -eq $e.names.Count) { [void]$out.Add($l) }
        elseif ($keep.Count -gt 0) { [void]$out.Add(($e.ip + ' ' + ($keep -join ' ') + ' ' + $e.comment).TrimEnd()) }
    }
    while ($out.Count -gt 0 -and $out[$out.Count - 1].Trim() -eq '') { $out.RemoveAt($out.Count - 1) }
    [void]$out.Add(''); [void]$out.Add($BeginMark)
    foreach ($g in $cfg.groups) {
        if (-not $g.ip) { continue }
        [void]$out.Add('# ' + $g.name)
        foreach ($d in $g.domains) { [void]$out.Add($g.ip + ' ' + $d) }
    }
    [void]$out.Add($EndMark)
    $newText = ($out -join "`r`n") + "`r`n"

    if ($newText -ceq $h.text) { Log 'hosts без изменений.' }
    else {
        $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $bak = Join-Path $BackupDir "hosts_$stamp.bak"
        try { Copy-Item -LiteralPath $HostsPath -Destination $bak -Force } catch {}
        if (-not (Test-Path $bak) -or (Get-Item $bak).Length -ne (Get-Item -LiteralPath $HostsPath).Length) {
            Log "ОШИБКА: не смог сделать копию hosts в $BackupDir - hosts НЕ меняю."; exit 2
        }
        $old = @(Get-ChildItem -Path $BackupDir -Filter 'hosts_*.bak' | Sort-Object Name -Descending)
        $keepN = [int]$cfg.settings.keep_backups
        if ($old.Count -gt $keepN) { $old[$keepN..($old.Count - 1)] | Remove-Item -Force }
        $fi = Get-Item -LiteralPath $HostsPath
        $ro = $fi.IsReadOnly
        if ($ro) { $fi.IsReadOnly = $false }
        $written = $false
        for ($try = 1; $try -le 5 -and -not $written; $try++) {
            try { [IO.File]::WriteAllText($HostsPath, $newText, $h.enc); $written = $true } catch { Start-Sleep -Seconds 2 }
        }
        if ($ro) { (Get-Item -LiteralPath $HostsPath).IsReadOnly = $true }
        if (-not $written) { Log 'ОШИБКА: не удалось записать hosts (занят антивирусом или нет прав администратора).'; exit 2 }
        if ($changed.Count) { foreach ($c in $changed) { Log ('ЗАМЕНА ' + $c) } } else { Log 'hosts переупорядочен (IP прежние).' }
        Log "копия старого hosts: backups\hosts_$stamp.bak"
        if ($IsWin) { & ipconfig /flushdns | Out-Null }
    }
    if ($changed.Count -and $IsWin) { Write-Host ''; Write-Host 'IP поменялся - закрой браузер полностью и открой заново.' -ForegroundColor Yellow }

    # журнал не больше 3000 строк
    try {
        $ll = [IO.File]::ReadAllLines($LogPath, [Text.Encoding]::UTF8)
        if ($ll.Count -gt 3000) { [IO.File]::WriteAllLines($LogPath, $ll[($ll.Count - 2000)..($ll.Count - 1)], [Text.Encoding]::UTF8) }
    } catch {}
}
catch { Log ('ОШИБКА: ' + $_.Exception.Message); exit 3 }
finally { $mutex.ReleaseMutex() }
