function SendTelegramMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$botToken,
        
        [Parameter(Mandatory=$true)]
        [string]$chatId,
        
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    
    $url = "https://api.telegram.org/bot$botToken/sendMessage"
    $params = @{
        chat_id = $chatId
        text = $message
    }
    $jsonParams = $params | ConvertTo-Json
    $headers = @{
        "Content-Type" = "application/json"
    }
    Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $jsonParams
}


function CheckVirusTotal {
    param (
        [Parameter(Mandatory=$true)]
        [string]$processHash
    )
    
    $apiKey = "#ur_VT_Api_here"
    $url = "https://www.virustotal.com/vtapi/v2/file/report"
    $params = @{
        apikey = $apiKey
        resource = $processHash
    }
    $response = Invoke-RestMethod -Uri $url -Method Get -Body $params
    if ($response.response_code -eq 1 -and $response.positives -gt 2) {
        return $true
    }
    return $false
}


function GetVirusTotalRating {
    param (
        [Parameter(Mandatory=$true)]
        [string]$processHash
    )
    
    $apiKey = "Ur_VT_API_HERE"
    $url = "https://www.virustotal.com/vtapi/v2/file/report"
    $params = @{
        apikey = $apiKey
        resource = $processHash
    }
    $response = Invoke-RestMethod -Uri $url -Method Get -Body $params
    if ($response.response_code -eq 1) {
        return $response.positives
    }
    return 0
}

# Main logic
try {
    $botToken = "ur_BOT_TOKEN"
    $chatId = "ur_CHAT_ID"

    # Retrieve process information
    $processes = Get-WmiObject -Class Win32_Process
    foreach ($process in $processes) {
        $processName = $process.Name
        $processId = $process.ProcessId
        $processPath = $process.ExecutablePath
        $parentProcessId = $process.ParentProcessId
        $parentProcess = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $parentProcessId"
        $childProcesses = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ParentProcessId = $processId"
        $startTime = $process.CreationDate
        $user = $process.GetOwner().User
        $privilege = $process.GetOwner().Domain

        # Additional logic to retrieve registry keys, DLLs, and network connections for the process
        $regKeys = @()
        
        $dlls = @()
        
        $networkConnections = @()
        

        # Check with VirusTotal
        if ($processPath -ne $null) {
            $processHash = (Get-FileHash -Path $processPath -Algorithm MD5).Hash
            $isMaliciousOrUnknown = CheckVirusTotal -processHash $processHash

            # Send alert if process is malicious or unknown
            if ($isMaliciousOrUnknown) {
                $virusTotalRating = GetVirusTotalRating -processHash $processHash
                $message = @"
Malicious or unknown process detected!
Process Name: $processName
Process ID: $processId
Process Path: $processPath
Parent Process ID: $($parentProcess.ProcessId)
Parent Process Name: $($parentProcess.Name)
Child Processes: $($childProcesses | ForEach-Object { $_.ProcessId })
Start Time: $startTime
User: $user
Privilege: $privilege
Registry Keys: $($regKeys -join ', ')
DLLs: $($dlls -join ', ')
Network Connections: $($networkConnections -join ', ')
VirusTotal Rating: $virusTotalRating
"@
                SendTelegramMessage -botToken $botToken -chatId $chatId -message $message
            }
        }
    }
} catch {
    Write-Host "Failed to import module: $($module)"
}