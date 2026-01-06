# Test property access on JSON objects (simulating strict mode behavior)
$testJson = '{}'
$config = $testJson | ConvertFrom-Json

Write-Host "Testing property access patterns:" -ForegroundColor Cyan

# Pattern 1: Direct access (might error in strict mode)
Write-Host "`n1. Direct access: `$config.orgProgramDataFolder"
try {
    if ($config.orgProgramDataFolder) {
        Write-Host "   Result: '$($config.orgProgramDataFolder)'" -ForegroundColor Green
    } else {
        Write-Host "   Result: (null/empty/false)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# Pattern 2: PSObject.Properties check (safest)
Write-Host "`n2. PSObject.Properties.Match check"
try {
    if ($config.PSObject.Properties.Match('orgProgramDataFolder').Count -gt 0) {
        Write-Host "   Property exists: $($config.orgProgramDataFolder)" -ForegroundColor Green
    } else {
        Write-Host "   Property does not exist" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# Pattern 3: Check if property exists before access
Write-Host "`n3. Get-Member check"
try {
    if (($config | Get-Member -Name 'orgProgramDataFolder' -MemberType NoteProperty) -ne $null) {
        Write-Host "   Property exists: $($config.orgProgramDataFolder)" -ForegroundColor Green
    } else {
        Write-Host "   Property does not exist" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
}
