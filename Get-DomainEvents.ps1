# Rango de tiempo
$startTime = (Get-Date).AddDays(-7)

# IDs relevantes
$eventIDs = @(4740, 4768, 4771)

# Función para limpiar la IP
function Clean-IP {
    param([string]$ip)
    if ([string]::IsNullOrEmpty($ip) -or $ip -eq '-') { return "N/A" }
    return $ip -replace '^::ffff:', ''
}

# Lista para guardar resultados
$resultados = @()

# Obtener eventos
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = $eventIDs
    StartTime = $startTime
} -ErrorAction SilentlyContinue

# Procesar eventos
foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $id = $event.Id
    $time = $event.TimeCreated
    $obj = $null

    switch ($id) {
        4740 {
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            $caller = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallerComputerName" } | Select-Object -ExpandProperty '#text'
            $obj = [PSCustomObject]@{
                Evento  = "Bloqueo de cuenta (4740)"
                Usuario = $user
                Equipo  = $caller
                IP      = "N/A"
                Fecha   = $time
            }
            Write-Output "[X] $time - Cuenta bloqueada: $user desde equipo: $caller"
        }
        4768 {
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            $ipRaw = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty '#text'
            $ip = Clean-IP $ipRaw
            $obj = [PSCustomObject]@{
                Evento  = "Solicitud TGT (4768)"
                Usuario = $user
                Equipo  = "N/A"
                IP      = $ip
                Fecha   = $time
            }
            Write-Output "[+] $time - Solicitud TGT (4768): $user desde IP: $ip"
        }
        4771 {
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
            $ipRaw = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty '#text'
            $ip = Clean-IP $ipRaw
            $obj = [PSCustomObject]@{
                Evento  = "Fallo Kerberos (4771)"
                Usuario = $user
                Equipo  = "N/A"
                IP      = $ip
                Fecha   = $time
            }
            Write-Output "[-] $time - Fallo Kerberos (4771): $user desde IP: $ip"
        }
 
    }

    if ($obj) { $resultados += $obj }
}

# Exportar a CSV
$csvPath = "$PSScriptRoot\EventLogReport.csv"
$resultados | Sort-Object Fecha | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Output "`nReporte exportado a: $csvPath"
Write-Output "`nReporte exportado a: $csvPath"
Write-Host "Presione cualquier tecla para continuar..."
[void][System.Console]::ReadKey($true)


