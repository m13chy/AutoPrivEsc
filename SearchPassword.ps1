param(
    [Parameter(Mandatory=$false)]
    [string]$Path = ".",
    
    [Parameter(Mandatory=$false)]
    [string[]]$FileExtensions = @("*.txt", "*.log", "*.config", "*.xml", "*.json", "*.ini", "*.properties", "*.yaml", "*.yml", "*.cfg", "*.conf", "*.env", "*.ps1", "*.bat", "*.cmd", "*.js", "*.py", "*.java", "*.cpp", "*.cs", "*.php", "*.html", "*.htm", "*.asp", "*.aspx", "*.jsp", "*.sql", "*.md", "*.doc", "*.docx", "*.pdf"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeDirectories = @("node_modules", ".git", "bin", "obj", "vendor", "__pycache__", ".vs", "target", "build", "dist"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeFiles = @("*.dll", "*.exe", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.zip", "*.rar", "*.7z", "*.tar", "*.gz"),
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSubdirectories = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxFileSizeMB = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowHelp,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput,
    
    [Parameter(Mandatory=$false)]
    [string]$CustomPatternsFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportFormatted
)

# Función para mostrar ayuda
function Show-Help {
    Write-Host "=== BUSCADOR AVANZADO DE CREDENCIALES Y CONTRASEÑAS ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DESCRIPCIÓN:" -ForegroundColor Yellow
    Write-Host "  Busca credenciales, contraseñas, tokens y claves en archivos usando patrones avanzados."
    Write-Host ""
    Write-Host "PARÁMETROS:" -ForegroundColor Yellow
    Write-Host "  -Path                 : Ruta donde buscar (por defecto: directorio actual)"
    Write-Host "  -FileExtensions       : Extensiones de archivo a buscar"
    Write-Host "  -ExcludeDirectories   : Directorios a excluir de la búsqueda"
    Write-Host "  -ExcludeFiles         : Patrones de archivos a excluir"
    Write-Host "  -IncludeSubdirectories: Buscar en subdirectorios (por defecto: sí)"
    Write-Host "  -OutputFile           : Archivo para guardar resultados"
    Write-Host "  -MaxFileSizeMB        : Tamaño máximo de archivo en MB (por defecto: 10)"
    Write-Host "  -CustomPatternsFile   : Archivo con patrones personalizados"
    Write-Host "  -ExportFormatted      : Exportar resultados formateados"
    Write-Host "  -VerboseOutput        : Mostrar salida detallada"
    Write-Host "  -ShowHelp             : Mostrar esta ayuda"
    Write-Host ""
    Write-Host "EJEMPLOS:" -ForegroundColor Yellow
    Write-Host "  .\BuscarPasswords.ps1"
    Write-Host "  .\BuscarPasswords.ps1 -Path 'C:\Proyectos' -MaxFileSizeMB 50"
    Write-Host "  .\BuscarPasswords.ps1 -OutputFile 'resultados.csv' -ExportFormatted"
    Write-Host "  .\BuscarPasswords.ps1 -ExcludeDirectories @('node_modules', '.git')"
    Write-Host "  .\BuscarPasswords.ps1 -CustomPatternsFile 'patrones.txt' -VerboseOutput"
    Write-Host ""
}

# Mostrar ayuda si se solicita
if ($ShowHelp) {
    Show-Help
    return
}

# Configuración de patrones de búsqueda
$PasswordPatterns = @{
    # Español
    "contraseña" = "contraseña\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "clave" = "clave\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "credencial" = "credencial\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "acceso" = "acceso\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Inglés básico
    "password" = "password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "passwd" = "passwd\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "pwd" = "pwd\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "pass" = "pass\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "secret" = "secret\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Bases de datos
    "db_password" = "db_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "database_password" = "database_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "mysql_password" = "mysql_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "postgres_password" = "postgres_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "mongo_password" = "mongo_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "redis_password" = "redis_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # APIs y servicios web
    "api_key" = "api_key\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "apikey" = "apikey\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "secret_key" = "secret_key\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "secretkey" = "secretkey\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "access_token" = "access_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "auth_token" = "auth_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "bearer_token" = "bearer_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "oauth_token" = "oauth_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "jwt_token" = "jwt_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Servicios y protocolos
    "ftp_password" = "ftp_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "smtp_password" = "smtp_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "ssh_password" = "ssh_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "vpn_password" = "vpn_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "http_password" = "http_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Cloud y servicios externos
    "aws_secret" = "aws_secret\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "azure_key" = "azure_key\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "google_api_key" = "google_api_key\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "firebase_key" = "firebase_key\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Aplicaciones y frameworks
    "django_secret" = "django_secret\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "rails_secret" = "rails_secret\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "spring_password" = "spring_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Desarrollo y herramientas
    "github_token" = "github_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "gitlab_token" = "gitlab_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "npm_token" = "npm_token\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "docker_password" = "docker_password\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "kubernetes_secret" = "kubernetes_secret\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    
    # Patrones avanzados
    "connection_string" = "connection.string\s*[=:]\s*[`"']?([^`"'\s\r\n]+)"
    "jdbc_url" = "jdbc:.*password=([^&`"'\s]+)"
    "connection_url" = ".*://[^:]+:([^@]+)@.*"
    
    # Variables de entorno comunes
    "env_password" = "PASSWORD\s*=\s*([^\s]+)"
    "env_secret" = "SECRET\s*=\s*([^\s]+)"
    "env_key" = "KEY\s*=\s*([^\s]+)"
    "env_token" = "TOKEN\s*=\s*([^\s]+)"
}

# Cargar patrones personalizados si se especifica
if ($CustomPatternsFile -and (Test-Path $CustomPatternsFile)) {
    try {
        $customPatterns = Get-Content $CustomPatternsFile | Where-Object { $_ -and $_.Trim() -notmatch "^#" }
        foreach ($patternLine in $customPatterns) {
            $parts = $patternLine -split "=", 2
            if ($parts.Count -eq 2) {
                $PasswordPatterns[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
        Write-Host "✓ Patrones personalizados cargados: $($customPatterns.Count)" -ForegroundColor Green
    }
    catch {
        Write-Warning "No se pudieron cargar los patrones personalizados: $($_.Exception.Message)"
    }
}

# Función para detectar el encoding del archivo
function Get-FileEncoding {
    param([string]$FilePath)
    
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -eq 0) { return 'UTF8' }
    
    # Detección simple de BOM
    if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return 'UTF8' }
    if ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return 'Unicode' }
    if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return 'Unicode' }
    if ($bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) { return 'UTF32' }
    
    return 'UTF8'
}

# Función para buscar contraseñas en un archivo
function Search-PasswordsInFile {
    param([string]$FilePath)
    
    $results = @()
    
    try {
        # Verificar tamaño del archivo
        $fileSize = (Get-Item $FilePath).Length / 1MB
        if ($fileSize -gt $MaxFileSizeMB) {
            if ($VerboseOutput) {
                Write-Host "  ⚠  Saltando archivo grande: $([System.IO.Path]::GetFileName($FilePath)) ($($fileSize.ToString('0.00')) MB)" -ForegroundColor Yellow
            }
            return $results
        }
        
        # Detectar encoding
        $encoding = Get-FileEncoding -FilePath $FilePath
        
        # Leer contenido del archivo
        $content = Get-Content -Path $FilePath -Encoding $encoding -ErrorAction Stop
        
        for ($lineNumber = 0; $lineNumber -lt $content.Count; $lineNumber++) {
            $line = $content[$lineNumber]
            
            foreach ($patternName in $PasswordPatterns.Keys) {
                $pattern = $PasswordPatterns[$patternName]
                $matches = [regex]::Matches($line, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                
                foreach ($match in $matches) {
                    if ($match.Groups.Count -gt 1) {
                        $password = $match.Groups[1].Value.Trim()
                        
                        if (Test-ValidPassword -Password $password -Pattern $patternName) {
                            $results += [PSCustomObject]@{
                                File = $FilePath
                                LineNumber = $lineNumber + 1
                                Pattern = $patternName
                                PatternRegex = $pattern
                                FullLine = ($line.Trim() -replace '\s+', ' ').Substring(0, [Math]::Min(200, $line.Trim().Length))
                                Password = $password
                                PasswordLength = $password.Length
                                Strength = Get-PasswordStrength -Password $password
                                RiskLevel = Get-RiskLevel -Pattern $patternName -Password $password
                                FileSizeMB = $fileSize
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        if ($VerboseOutput) {
            Write-Warning "No se pudo leer el archivo: $FilePath - Error: $($_.Exception.Message)"
        }
    }
    
    return $results
}

# Función para validar si es una contraseña real
function Test-ValidPassword {
    param([string]$Password, [string]$Pattern)
    
    # Excluir placeholders y valores obvios
    $exclusionPatterns = @(
        "^\*+$", "^x+$", "^\.+$", "^\$\{.*\}$", "^%.*%$", "^\[.*\]$", "^\(.*\)$",
        "placeholder", "example", "sample", "test", "demo", "fake", "dummy",
        "changeme", "password", "secret", "token", "key", "null", "undefined",
        "true", "false", "yes", "no", "admin", "root", "user", "username"
    )
    
    foreach ($exclusion in $exclusionPatterns) {
        if ($Password -match $exclusion -or $Password -eq "") {
            return $false
        }
    }
    
    # Longitud mínima
    if ($Password.Length -lt 3) {
        return $false
    }
    
    return $true
}

# Función para evaluar la fortaleza de la contraseña
function Get-PasswordStrength {
    param([string]$Password)
    
    $score = 0
    $length = $Password.Length
    
    # Puntos por longitud
    if ($length -ge 8) { $score += 1 }
    if ($length -ge 12) { $score += 1 }
    if ($length -ge 16) { $score += 1 }
    
    # Caracteres diversos
    if ($Password -cmatch "[a-z]") { $score += 1 }
    if ($Password -cmatch "[A-Z]") { $score += 1 }
    if ($Password -cmatch "\d") { $score += 1 }
    if ($Password -cmatch "[^a-zA-Z0-9]") { $score += 1 }
    
    # Bonus por complejidad
    $uniqueChars = ($Password.ToCharArray() | Group-Object | Measure-Object).Count
    if ($uniqueChars -ge ($length * 0.8)) { $score += 1 }
    
    switch ($score) {
        { $_ -le 2 } { return "Muy Débil" }
        3 { return "Débil" }
        4 { return "Media" }
        5 { return "Fuerte" }
        { $_ -ge 6 } { return "Muy Fuerte" }
        default { return "Desconocida" }
    }
}

# Función para evaluar el nivel de riesgo
function Get-RiskLevel {
    param([string]$Pattern, [string]$Password)
    
    $highRiskPatterns = @("api_key", "secret_key", "access_token", "jwt_token", "aws_secret", "private_key")
    $mediumRiskPatterns = @("password", "passwd", "pwd", "database_password", "ssh_password")
    
    if ($highRiskPatterns -contains $Pattern) { return "Alto" }
    if ($mediumRiskPatterns -contains $Pattern) { return "Medio" }
    
    $strength = Get-PasswordStrength -Password $Password
    if ($strength -in @("Fuerte", "Muy Fuerte")) { return "Medio" }
    
    return "Bajo"
}

# Función principal
function Start-PasswordSearch {
    Write-Host "=== BUSCADOR AVANZADO DE CREDENCIALES ===" -ForegroundColor Cyan
    Write-Host "Ruta de búsqueda: $Path" -ForegroundColor White
    Write-Host "Extensiones incluidas: $($FileExtensions.Count)" -ForegroundColor White
    Write-Host "Excluir directorios: $($ExcludeDirectories -join ', ')" -ForegroundColor White
    Write-Host "Tamaño máximo archivo: $MaxFileSizeMB MB" -ForegroundColor White
    Write-Host "Patrones de búsqueda: $($PasswordPatterns.Count)" -ForegroundColor White
    Write-Host ""
    
    # Verificar que la ruta existe
    if (-not (Test-Path $Path)) {
        Write-Error "La ruta especificada no existe: $Path"
        return
    }
    
    # Construir parámetros de búsqueda
    $searchParams = @{
        Path = $Path
        Include = $FileExtensions
        File = $true
        ErrorAction = "SilentlyContinue"
    }
    
    if ($IncludeSubdirectories) { $searchParams['Recurse'] = $true }
    
    # Obtener archivos para analizar
    $allFiles = Get-ChildItem @searchParams | 
                Where-Object { 
                    $isExcluded = $false
                    foreach ($excludeDir in $ExcludeDirectories) {
                        if ($_.FullName -match [regex]::Escape($excludeDir)) {
                            $isExcluded = $true
                            break
                        }
                    }
                    foreach ($excludeFile in $ExcludeFiles) {
                        if ($_.Name -like $excludeFile) {
                            $isExcluded = $true
                            break
                        }
                    }
                    -not $isExcluded
                }
    
    if (-not $allFiles) {
        Write-Warning "No se encontraron archivos con los criterios especificados."
        return
    }
    
    Write-Host "Archivos a analizar: $($allFiles.Count)" -ForegroundColor Green
    if ($VerboseOutput) {
        Write-Host "Archivos encontrados:" -ForegroundColor Gray
        $allFiles | Select-Object -First 20 | ForEach-Object { 
            Write-Host "  📄 $($_.Name) ($([Math]::Round($_.Length/1KB, 2)) KB)" -ForegroundColor DarkGray 
        }
        if ($allFiles.Count -gt 20) {
            Write-Host "  ... y $($allFiles.Count - 20) más" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    
    $allResults = @()
    $fileCount = 0
    $totalFiles = $allFiles.Count
    
    foreach ($file in $allFiles) {
        $fileCount++
        $percentComplete = [math]::Round(($fileCount / $totalFiles) * 100, 2)
        
        Write-Progress -Activity "Analizando archivos" -Status "$fileCount/$totalFiles ($percentComplete%) - $($file.Name)" -PercentComplete $percentComplete
        
        $results = Search-PasswordsInFile -FilePath $file.FullName
        if ($results) {
            $allResults += $results
            if ($VerboseOutput) {
                Write-Host "  ✓ $($file.Name): $($results.Count) credenciales encontradas" -ForegroundColor Green
            }
        }
    }
    
    Write-Progress -Activity "Analizando archivos" -Completed
    
    # Mostrar resultados
    Show-Results -Results $allResults
}

# Función para mostrar resultados
function Show-Results {
    param([array]$Results)
    
    if ($Results.Count -gt 0) {
        Write-Host "=== RESULTADOS DE LA BÚSQUEDA ===" -ForegroundColor Red
        Write-Host "Total de credenciales encontradas: $($Results.Count)" -ForegroundColor Red
        Write-Host ""
        
        # Agrupar por nivel de riesgo
        $riskGroups = $Results | Group-Object -Property RiskLevel
        
        foreach ($riskGroup in $riskGroups) {
            $riskColor = switch ($riskGroup.Name) {
                "Alto" { "Red" }
                "Medio" { "Yellow" }
                "Bajo" { "Green" }
                default { "White" }
            }
            
            Write-Host "Nivel de Riesgo $($riskGroup.Name): $($riskGroup.Count) credenciales" -ForegroundColor $riskColor
            
            foreach ($result in $riskGroup.Group | Select-Object -First 5) {
                Write-Host "  📍 $([System.IO.Path]::GetFileName($result.File)):Línea $($result.LineNumber)" -ForegroundColor Gray
                Write-Host "     Patrón: $($result.Pattern)" -ForegroundColor Cyan
                Write-Host "     Valor: $($result.Password)" -ForegroundColor Yellow
                Write-Host "     Fortaleza: $($result.Strength)" -ForegroundColor Magenta
                Write-Host "     Contexto: $($result.FullLine)" -ForegroundColor DarkGray
                Write-Host ""
            }
            
            if ($riskGroup.Count -gt 5) {
                Write-Host "  ... y $($riskGroup.Count - 5) más" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        
        # Estadísticas detalladas
        Write-Host "=== ESTADÍSTICAS DETALLADAS ===" -ForegroundColor Cyan
        
        $strengthStats = $Results | Group-Object -Property Strength
        Write-Host "Fortaleza de contraseñas:" -ForegroundColor White
        foreach ($stat in $strengthStats) {
            Write-Host "  $($stat.Name): $($stat.Count)" -ForegroundColor Gray
        }
        
        $patternStats = $Results | Group-Object -Property Pattern | Sort-Object Count -Descending | Select-Object -First 10
        Write-Host "Patrones más comunes:" -ForegroundColor White
        foreach ($stat in $patternStats) {
            Write-Host "  $($stat.Name): $($stat.Count)" -ForegroundColor Gray
        }
        
        # Guardar resultados si se especifica
        if ($OutputFile) {
            Save-Results -Results $Results -OutputFile $OutputFile
        }
        
    } else {
        Write-Host "✅ No se encontraron credenciales expuestas." -ForegroundColor Green
    }
}

# Función para guardar resultados
function Save-Results {
    param([array]$Results, [string]$OutputFile)
    
    try {
        if ($ExportFormatted) {
            $formattedResults = $Results | ForEach-Object {
                [PSCustomObject]@{
                    Archivo = $_.File
                    Linea = $_.LineNumber
                    Patron = $_.Pattern
                    Credencial = $_.Password
                    Longitud = $_.PasswordLength
                    Fortaleza = $_.Strength
                    Riesgo = $_.RiskLevel
                    Tamaño_Archivo_MB = $_.FileSizeMB
                    Fecha_Detectado = $_.Timestamp
                    Contexto = $_.FullLine
                }
            }
            $formattedResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        } else {
            $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        }
        
        Write-Host "✓ Resultados guardados en: $OutputFile" -ForegroundColor Green
        Write-Host "  Registros exportados: $($Results.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Error "No se pudo guardar el archivo: $($_.Exception.Message)"
    }
}

# Manejo de errores global
trap {
    Write-Error "Error durante la ejecución: $($_.Exception.Message)"
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    break
}

# Ejecutar búsqueda
if ($VerboseOutput) {
    Write-Host "Iniciando búsqueda con configuración avanzada..." -ForegroundColor Cyan
}

Start-PasswordSearch
