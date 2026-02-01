param (
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "<<SERVERURL>>",
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "<<FILEPATH>>",
    [Parameter(Mandatory = $false)]
    [string]$AuthKey = "<<AUTHKEY>>"
)
$ErrorActionPreference = "Stop"
$uploadUrl = "$ServerUrl/upload"

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-ServerConnectivity {
    <#
    .SYNOPSIS
        Tests server connectivity and returns detailed diagnostic information.
    .DESCRIPTION
        Performs comprehensive connectivity checks including DNS resolution and TCP port connectivity.
    .OUTPUTS
        PSCustomObject with Success, Reason, ErrorCode, Host, Port, ResolvedIPs, and Exception properties.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$TimeoutMs = 5000
    )

    $result = [PSCustomObject]@{
        Success     = $false
        Reason      = "Unknown error"
        ErrorCode   = "Unknown"
        Host        = $null
        Port        = $null
        ResolvedIPs = @()
        Exception   = $null
    }

    # Step 1: Parse URL
    try {
        $uri = [Uri]$Url
        $result.Host = $uri.Host
        
        # Validate host is not empty
        if ([string]::IsNullOrWhiteSpace($result.Host)) {
            $result.Reason = "Invalid URL format - no host specified: $Url"
            $result.ErrorCode = "InvalidUrl"
            return $result
        }
        
        $result.Port = if ($uri.IsDefaultPort) {
            if ($uri.Scheme -eq 'https') { 443 } elseif ($uri.Scheme -eq 'http') { 80 } else { $uri.Port }
        } else {
            $uri.Port
        }
    }
    catch {
        $result.Reason = "Invalid URL format: $Url"
        $result.ErrorCode = "InvalidUrl"
        $result.Exception = $_.Exception.Message
        return $result
    }

    # Step 2: DNS Resolution
    try {
        $dnsResult = [System.Net.Dns]::GetHostAddresses($result.Host)
        if ($dnsResult.Count -eq 0) {
            $result.Reason = "DNS resolved but returned no IP addresses for '$($result.Host)'"
            $result.ErrorCode = "DnsResolutionFailed"
            return $result
        }
        $result.ResolvedIPs = @($dnsResult | ForEach-Object { $_.ToString() })
    }
    catch [System.Net.Sockets.SocketException] {
        $result.Reason = "DNS resolution failed for '$($result.Host)': Host not found"
        $result.ErrorCode = "DnsResolutionFailed"
        $result.Exception = $_.Exception.Message
        return $result
    }
    catch {
        $result.Reason = "DNS resolution failed for '$($result.Host)': $($_.Exception.Message)"
        $result.ErrorCode = "DnsResolutionFailed"
        $result.Exception = $_.Exception.Message
        return $result
    }

    # Step 3: TCP Connection Test
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($result.Host, $result.Port, $null, $null)
        
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $result.Reason = "Connection timed out after ${TimeoutMs}ms - server '$($result.Host):$($result.Port)' did not respond"
            $result.ErrorCode = "ConnectionTimeout"
            return $result
        }
        
        $client.EndConnect($iar)
        $result.Success = $true
        $result.Reason = "Connected successfully to $($result.Host):$($result.Port)"
        $result.ErrorCode = "None"
        return $result
    }
    catch [System.Net.Sockets.SocketException] {
        $socketError = $_.Exception.SocketErrorCode
        switch ($socketError) {
            'ConnectionRefused' {
                $result.Reason = "Connection refused - server '$($result.Host):$($result.Port)' is not accepting connections (port may be closed or service not running)"
                $result.ErrorCode = "ConnectionRefused"
            }
            'HostUnreachable' {
                $result.Reason = "Host unreachable - cannot route to '$($result.Host)' (check network path/firewall)"
                $result.ErrorCode = "HostUnreachable"
            }
            'NetworkUnreachable' {
                $result.Reason = "Network unreachable - no route to network for '$($result.Host)'"
                $result.ErrorCode = "NetworkUnreachable"
            }
            'TimedOut' {
                $result.Reason = "Connection timed out - server '$($result.Host):$($result.Port)' did not respond"
                $result.ErrorCode = "ConnectionTimeout"
            }
            default {
                $result.Reason = "Socket error connecting to '$($result.Host):$($result.Port)': $socketError"
                $result.ErrorCode = "SocketError"
            }
        }
        $result.Exception = $_.Exception.Message
        return $result
    }
    catch {
        $result.Reason = "Failed to connect to '$($result.Host):$($result.Port)': $($_.Exception.Message)"
        $result.ErrorCode = "Unknown"
        $result.Exception = $_.Exception.Message
        return $result
    }
    finally {
        if ($client) { 
            try { $client.Close() } catch { }
        }
    }
}

function Get-DetailedHttpError {
    <#
    .SYNOPSIS
        Analyzes HTTP response and returns detailed error information.
    #>
    param(
        [int]$StatusCode,
        [string]$ReasonPhrase,
        [string]$ResponseBody
    )
    
    $result = [PSCustomObject]@{
        ErrorCode   = "HttpError"
        Reason      = "HTTP $StatusCode $ReasonPhrase"
        Suggestion  = $null
    }
    
    switch ($StatusCode) {
        401 {
            $result.ErrorCode = "AuthenticationFailed"
            $result.Reason = "Authentication failed (HTTP 401)"
            $result.Suggestion = "Verify AUTH_KEY is correct and matches server configuration"
        }
        403 {
            $result.ErrorCode = "AuthorizationFailed"
            $result.Reason = "Access denied (HTTP 403)"
            $result.Suggestion = "Check if the AUTH_KEY has sufficient permissions"
        }
        404 {
            $result.ErrorCode = "EndpointNotFound"
            $result.Reason = "Upload endpoint not found (HTTP 404)"
            $result.Suggestion = "Verify the ServerUrl is correct and includes the correct path"
        }
        413 {
            $result.ErrorCode = "PayloadTooLarge"
            $result.Reason = "File too large (HTTP 413)"
            $result.Suggestion = "Reduce file size or check server upload limits"
        }
        { $_ -ge 500 -and $_ -lt 600 } {
            $result.ErrorCode = "ServerError"
            $result.Reason = "Server error (HTTP $StatusCode)"
            $result.Suggestion = "Check server logs for more details"
        }
    }
    
    if ($ResponseBody) {
        $result.Reason += " - $ResponseBody"
    }
    
    return $result
}

function Get-DetailedExceptionError {
    <#
    .SYNOPSIS
        Analyzes exception and returns detailed error information.
    #>
    param(
        [System.Exception]$Exception
    )
    
    $result = [PSCustomObject]@{
        ErrorCode   = "Unknown"
        Reason      = $Exception.Message
        Suggestion  = $null
    }
    
    # Unwrap AggregateException
    $innerEx = $Exception
    while ($innerEx -is [System.AggregateException] -and $innerEx.InnerException) {
        $innerEx = $innerEx.InnerException
    }
    
    if ($innerEx -is [System.Net.Http.HttpRequestException]) {
        $httpEx = $innerEx
        if ($httpEx.InnerException -is [System.Net.WebException]) {
            $webEx = $httpEx.InnerException
            switch ($webEx.Status) {
                'ConnectFailure' {
                    $result.ErrorCode = "ConnectionFailed"
                    $result.Reason = "Connection failed - could not establish connection to server"
                    $result.Suggestion = "Check network connectivity, firewall rules, and that the server is running"
                }
                'Timeout' {
                    $result.ErrorCode = "Timeout"
                    $result.Reason = "Request timed out"
                    $result.Suggestion = "Check network speed and server responsiveness"
                }
                'SecureChannelFailure' {
                    $result.ErrorCode = "TlsError"
                    $result.Reason = "TLS/SSL error - certificate validation failed or protocol mismatch"
                    $result.Suggestion = "Check TLS/SSL certificate validity and ensure TLS 1.2+ is enabled"
                }
                'TrustFailure' {
                    $result.ErrorCode = "TlsError"
                    $result.Reason = "TLS/SSL certificate trust failure"
                    $result.Suggestion = "Verify server certificate is trusted or use -SkipCertificateCheck if appropriate"
                }
                'NameResolutionFailure' {
                    $result.ErrorCode = "DnsResolutionFailed"
                    $result.Reason = "DNS resolution failed - could not resolve server hostname"
                    $result.Suggestion = "Verify server hostname is correct and DNS is working"
                }
                default {
                    $result.ErrorCode = "NetworkError"
                    $result.Reason = "Network error: $($webEx.Status) - $($webEx.Message)"
                }
            }
        }
    }
    elseif ($innerEx -is [System.Threading.Tasks.TaskCanceledException]) {
        $result.ErrorCode = "Timeout"
        $result.Reason = "Request timed out"
        $result.Suggestion = "Check network speed and server responsiveness"
    }
    elseif ($innerEx -is [System.IO.FileNotFoundException]) {
        $result.ErrorCode = "FileNotFound"
        $result.Reason = "File not found: $($innerEx.FileName)"
        $result.Suggestion = "Verify the file path is correct"
    }
    elseif ($innerEx -is [System.UnauthorizedAccessException]) {
        $result.ErrorCode = "AccessDenied"
        $result.Reason = "Access denied to file"
        $result.Suggestion = "Check file permissions"
    }
    
    return $result
}

try {
    $computername = $env:COMPUTERNAME
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    
    # Pre-flight connectivity check with detailed diagnostics
    Write-ColorMessage "Checking server connectivity..." "Cyan"
    $connResult = Test-ServerConnectivity -Url $uploadUrl -TimeoutMs 5000
    
    if (-not $connResult.Success) {
        Write-ColorMessage "Server connectivity check failed!" "Red"
        Write-ColorMessage "  Target: $($connResult.Host):$($connResult.Port)" "Yellow"
        Write-ColorMessage "  Error: $($connResult.Reason)" "Red"
        if ($connResult.ResolvedIPs.Count -gt 0) {
            Write-ColorMessage "  Resolved IPs: $($connResult.ResolvedIPs -join ', ')" "Gray"
        }
        Write-ColorMessage "  Error Code: $($connResult.ErrorCode)" "Yellow"
        exit 1
    }
    
    Write-ColorMessage "Server reachable at $($connResult.Host):$($connResult.Port)" "Green"
    
    Add-Type -AssemblyName System.Net.Http

    $httpClient = $null
    $content = $null
    $fileStream = $null
    $fileContent = $null

    try {
        $httpClient = [System.Net.Http.HttpClient]::new()
        [void]$httpClient.DefaultRequestHeaders.Add("X-Auth-Key", $AuthKey)

        $content = [System.Net.Http.MultipartFormDataContent]::new()
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileNameFinal = "$computername`_$serialNumber`_$fileName"
        $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
        $content.Add($fileContent, "file", $fileNameFinal)

        Write-ColorMessage "Uploading $fileNameFinal..." "Cyan"
        $response = $httpClient.PostAsync($uploadUrl, $content).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result

        if (-not $response.IsSuccessStatusCode) {
            $errorDetails = Get-DetailedHttpError -StatusCode ([int]$response.StatusCode) -ReasonPhrase $response.ReasonPhrase -ResponseBody $responseContent
            Write-ColorMessage "Upload failed!" "Red"
            Write-ColorMessage "  Error: $($errorDetails.Reason)" "Red"
            Write-ColorMessage "  Error Code: $($errorDetails.ErrorCode)" "Yellow"
            if ($errorDetails.Suggestion) {
                Write-ColorMessage "  Suggestion: $($errorDetails.Suggestion)" "Cyan"
            }
            exit 1
        }

        Write-ColorMessage "Upload successful!" "Green"
        return $responseContent
    }
    finally {
        if ($fileContent) { $fileContent.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
        if ($content) { $content.Dispose() }
        if ($httpClient) { $httpClient.Dispose() }
    }
}
catch {
    $errorDetails = Get-DetailedExceptionError -Exception $_.Exception
    Write-ColorMessage "File upload failed!" "Red"
    Write-ColorMessage "  Error: $($errorDetails.Reason)" "Red"
    Write-ColorMessage "  Error Code: $($errorDetails.ErrorCode)" "Yellow"
    if ($errorDetails.Suggestion) {
        Write-ColorMessage "  Suggestion: $($errorDetails.Suggestion)" "Cyan"
    }
    exit 1
}