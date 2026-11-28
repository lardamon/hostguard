# Установка/удаление задачи HostsGuard в Планировщике Windows. Запускать от администратора.
param([switch]$Install, [switch]$Uninstall, [switch]$Restore)
$ErrorActionPreference = 'Stop'
$Dest = 'C:\HostsGuard'
$TaskName = 'HostsGuard'

try {
if ($Restore) {
    # вернуть самую свежую копию hosts из backups
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $b = Get-ChildItem -Path (Join-Path $PSScriptRoot 'backups') -Filter 'hosts_*.bak' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $b) { Write-Host 'Копий hosts нет - возвращать нечего.' -ForegroundColor Red; exit 1 }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Disable-ScheduledTask -TaskName $TaskName | Out-Null; Write-Host 'Фоновую проверку выключил (включится снова через УСТАНОВИТЬ.cmd).' }
    (Get-Item -LiteralPath $hosts).IsReadOnly = $false
    Copy-Item -LiteralPath $b.FullName -Destination $hosts -Force
    & ipconfig /flushdns | Out-Null
    Write-Host ('Вернул hosts из копии ' + $b.Name + '. Закрой браузер полностью и открой заново.') -ForegroundColor Green
    exit 0
}
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host 'Задача HostsGuard удалена. Проверки больше не запускаются.' -ForegroundColor Green
    } else { Write-Host 'Задачи HostsGuard нет - удалять нечего.' }
    # убираем из hosts блок HostsGuard (всё между "# >>> HostsGuard" и "# <<< HostsGuard"), остальное не трогаем
    if ($env:HG_HOSTS) { $hosts = $env:HG_HOSTS } else { $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }
    $bytes = [IO.File]::ReadAllBytes($hosts)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $text = (New-Object Text.UTF8Encoding($false)).GetString($bytes, $(if ($bom) { 3 } else { 0 }), $bytes.Length - $(if ($bom) { 3 } else { 0 }))
    $out = New-Object System.Collections.ArrayList; $inBlock = $false; $removed = 0
    foreach ($l in ($text -split "\r?\n")) {
        if ($l.StartsWith('# >>> HostsGuard')) { $inBlock = $true; $removed++; continue }
        if ($l.StartsWith('# <<< HostsGuard')) { $inBlock = $false; $removed++; continue }
        if ($inBlock) { $removed++; continue }
        [void]$out.Add($l)
    }
    if ($removed -eq 0) { Write-Host 'Блока HostsGuard в hosts нет - hosts не трогал.' }
    else {
        while ($out.Count -gt 0 -and $out[$out.Count - 1].Trim() -eq '') { $out.RemoveAt($out.Count - 1) }
        $bakDir = Join-Path $PSScriptRoot 'backups'
        if (-not (Test-Path $bakDir)) { New-Item -ItemType Directory -Path $bakDir | Out-Null }
        $bak = Join-Path $bakDir ('hosts_' + (Get-Date).ToString('yyyyMMdd_HHmmss') + '_до_удаления.bak')
        Copy-Item -LiteralPath $hosts -Destination $bak -Force
        (Get-Item -LiteralPath $hosts).IsReadOnly = $false
        [IO.File]::WriteAllText($hosts, (($out -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($bom)))
        try { & ipconfig /flushdns | Out-Null } catch {}
        Write-Host ('Убрал из hosts блок HostsGuard (' + $removed + ' строк). Копия прежнего hosts: ' + $bak) -ForegroundColor Green
        Write-Host 'Закрой браузер полностью и открой заново.' -ForegroundColor Green
    }
    Write-Host "Папку $Dest не трогал - удали сам, если нужно."
    exit 0
}

# 1. Копируем файлы в C:\HostsGuard (config.txt не перезаписываем, если он уже там есть)
$src = $PSScriptRoot
if ($src.TrimEnd('\') -ne $Dest) {
    if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Path $Dest | Out-Null }
    foreach ($f in Get-ChildItem -LiteralPath $src -File) {
        $target = Join-Path $Dest $f.Name
        if ($f.Name -eq 'config.txt' -and (Test-Path $target)) {
            # твой config оставляем, но только если в нём есть IP и группы - иначе кладём новый, а старый сохраняем
            $t = [IO.File]::ReadAllText($target)
            $okIp = ($t -match '(?m)^\s*\d{1,3}(\.\d{1,3}){3}\s*$'); $okGr = ($t -match '(?m)^\s*\[\s*group\s+')
            if ($okIp -and $okGr) { Write-Host 'config.txt в C:\HostsGuard уже есть - оставляю твой.'; continue }
            Copy-Item -LiteralPath $target -Destination (Join-Path $Dest 'config_old.txt') -Force
            Write-Host 'твой config.txt был испорчен (нет IP или групп) - сохранил его как config_old.txt и положил новый.' -ForegroundColor Yellow
        }
        if (@('log.txt', 'ips_found.txt', 'ips_proxy.txt', 'ips_source.txt', 'ips_lists.txt', 'last_good.txt') -contains $f.Name) { continue }   # журнал и найденные IP не затираем
        Copy-Item -LiteralPath $f.FullName -Destination $target -Force
    }
}
Get-ChildItem -LiteralPath $Dest -File | Unblock-File
Remove-Item (Join-Path $Dest 'ips_found.txt') -Force -ErrorAction SilentlyContinue   # от версии с ошибкой, больше не используется

# 2. Интервал из config.txt
$interval = 60
foreach ($l in [IO.File]::ReadAllLines((Join-Path $Dest 'config.txt'), [Text.Encoding]::UTF8)) {
    if ($l -match '^\s*interval\s*=\s*(\d+)') { $interval = [int]$Matches[1] }
}
if ($interval -lt 5) { $interval = 5 }

# 3. Задача: при включении ПК (через 1 мин) + каждые N минут, от SYSTEM, без окон
$script = Join-Path $Dest 'HostsGuard.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"') -WorkingDirectory $Dest
$tBoot = New-ScheduledTaskTrigger -AtStartup
$tBoot.Delay = 'PT1M'
$tRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $interval)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -Hidden
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($tBoot, $tRepeat) -Settings $settings -Principal $principal -Description 'Проверяет обходные IP в hosts и меняет нерабочие' -Force | Out-Null

Write-Host ''
Write-Host "Задача HostsGuard установлена: при включении ПК и каждые $interval мин." -ForegroundColor Green
Write-Host "Папка: $Dest   (config.txt - настройки, log.txt - журнал, backups - копии hosts)"
Write-Host ''
Write-Host 'Делаю первую проверку прямо сейчас...'
Write-Host ''
& $script
Start-Process explorer.exe $Dest
}
catch { Write-Host ('ОШИБКА: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }
