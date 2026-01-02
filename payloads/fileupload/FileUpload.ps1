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

try {
    $computername = $env:COMPUTERNAME
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
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

        $response = $httpClient.PostAsync($uploadUrl, $content).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result

        if (-not $response.IsSuccessStatusCode) {
            throw "Upload failed: HTTP $([int]$response.StatusCode) $($response.ReasonPhrase) - $responseContent"
        }

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
    Write-ColorMessage "File upload failed: $($_.Exception.Message)" "Red"
    exit 1
}