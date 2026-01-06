# Test JSON parsing scenarios
$testCases = @(
    @{
        Name = "Complete config"
        Json = '{"orgProgramDataFolder": "My App", "extraFolders": [{"name": "CustomLogs", "path": "Users\\Public\\Documents\\MyLogs"}]}'
    },
    @{
        Name = "Only orgProgramDataFolder"
        Json = '{"orgProgramDataFolder": "My App"}'
    },
    @{
        Name = "Only extraFolders"
        Json = '{"extraFolders": [{"name": "CustomLogs", "path": "Users\\Public\\Documents\\MyLogs"}]}'
    },
    @{
        Name = "Empty object"
        Json = '{}'
    }
)

foreach ($test in $testCases) {
    Write-Host "`n=== Testing: $($test.Name) ===" -ForegroundColor Cyan
    try {
        $config = $test.Json | ConvertFrom-Json
        Write-Host "  Parse: SUCCESS" -ForegroundColor Green
        
        # Test property access
        if ($config.orgProgramDataFolder) {
            Write-Host "  orgProgramDataFolder: $($config.orgProgramDataFolder)" -ForegroundColor Yellow
        } else {
            Write-Host "  orgProgramDataFolder: (not set)" -ForegroundColor Gray
        }
        
        if ($config.extraFolders) {
            Write-Host "  extraFolders: $($config.extraFolders.Count) items" -ForegroundColor Yellow
        } else {
            Write-Host "  extraFolders: (not set)" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  Parse: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
}
