<#
.SYNOPSIS
    AppInst File Manager – minimal WPF GUI for uploads / downloads.
.DESCRIPTION
    • List   – GET  /uploads   (X-Auth-Key header)
    • Download – GET  /download  (X-Auth-Key + X-Filename headers) → saves to chosen folder
    • Upload  – POST /upload    (multipart/form-data, field name "file")
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms      # for FolderBrowserDialog & OpenFileDialog

# ── Defaults ──────────────────────────────────────────────────────────────────
$script:BaseUrl  = "https://appinst.jvsautomate.com"
$script:AuthKey  = ""
$script:SavePath = "E:\"

# ── XAML ──────────────────────────────────────────────────────────────────────
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="AppInst File Manager" Height="620" Width="960"
    WindowStartupLocation="CenterScreen"
    Background="#1E1E2E" Foreground="#CDD6F4">

    <Window.Resources>
        <!-- Accent colours (Catppuccin-ish dark) -->
        <SolidColorBrush x:Key="AccentBrush"   Color="#89B4FA"/>
        <SolidColorBrush x:Key="BgBrush"       Color="#1E1E2E"/>
        <SolidColorBrush x:Key="SurfaceBrush"  Color="#313244"/>
        <SolidColorBrush x:Key="TextBrush"     Color="#CDD6F4"/>
        <SolidColorBrush x:Key="SubTextBrush"  Color="#A6ADC8"/>
        <SolidColorBrush x:Key="GreenBrush"    Color="#A6E3A1"/>
        <SolidColorBrush x:Key="RedBrush"      Color="#F38BA8"/>

        <Style TargetType="Button">
            <Setter Property="Background"  Value="{StaticResource SurfaceBrush}"/>
            <Setter Property="Foreground"  Value="{StaticResource TextBrush}"/>
            <Setter Property="Padding"     Value="14,6"/>
            <Setter Property="Margin"      Value="4"/>
            <Setter Property="FontSize"    Value="13"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor"      Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#45475A"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Opacity" Value="0.45"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background"  Value="{StaticResource SurfaceBrush}"/>
            <Setter Property="Foreground"  Value="{StaticResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="Padding"     Value="6,4"/>
            <Setter Property="FontSize"    Value="13"/>
            <Setter Property="CaretBrush"  Value="{StaticResource TextBrush}"/>
        </Style>

        <Style TargetType="PasswordBox">
            <Setter Property="Background"  Value="{StaticResource SurfaceBrush}"/>
            <Setter Property="Foreground"  Value="{StaticResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="Padding"     Value="6,4"/>
            <Setter Property="FontSize"    Value="13"/>
        </Style>
    </Window.Resources>

    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Row 0 – Settings bar -->
        <Border Grid.Row="0" Background="#313244" CornerRadius="6" Padding="10" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="260"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="200"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="Auth Key" VerticalAlignment="Center" Margin="0,0,8,0"
                           Foreground="{StaticResource SubTextBrush}" FontSize="12"/>
                <Grid Grid.Column="1">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <PasswordBox Grid.Column="0" Name="pbAuthKey" VerticalAlignment="Center"/>
                    <TextBox Grid.Column="0" Name="tbAuthKeyPlain" VerticalAlignment="Center" Visibility="Collapsed"/>
                    <Button Grid.Column="1" Name="btnToggleAuth" Content="Show" Padding="10,4" FontSize="12"
                            VerticalAlignment="Center" Margin="6,0,0,0"/>
                </Grid>
                <TextBlock Grid.Column="2" Text="Base URL" VerticalAlignment="Center" Margin="12,0,8,0"
                           Foreground="{StaticResource SubTextBrush}" FontSize="12"/>
                <TextBox Grid.Column="3" Name="tbBaseUrl" VerticalAlignment="Center"/>
                <TextBlock Grid.Column="4" Text="Save To" VerticalAlignment="Center" Margin="12,0,8,0"
                           Foreground="{StaticResource SubTextBrush}" FontSize="12"/>
                <Grid Grid.Column="5">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox Grid.Column="0" Name="tbSavePath" VerticalAlignment="Center"/>
                    <Button  Grid.Column="1" Name="btnBrowse" Content="…" Padding="8,4" FontSize="14"
                             VerticalAlignment="Center"/>
                </Grid>
            </Grid>
        </Border>

        <!-- Row 1 – Action buttons -->
        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,8">
            <Button Name="btnRefresh"  Content="⟳  Refresh List" FontSize="14"
                    Background="#89B4FA" Foreground="#1E1E2E" Padding="18,7"/>
            <Button Name="btnDownload" Content="⬇  Download Selected" FontSize="14"
                    Background="#A6E3A1" Foreground="#1E1E2E" Padding="18,7" IsEnabled="False"/>
            <Button Name="btnUpload"   Content="⬆  Upload File…" FontSize="14"
                    Background="#F9E2AF" Foreground="#1E1E2E" Padding="18,7"/>
            <Button Name="btnDelete"  Content="🗑  Delete Selected" FontSize="14"
                    Background="#F38BA8" Foreground="#1E1E2E" Padding="18,7" IsEnabled="False"/>
        </StackPanel>

        <!-- Row 2 – DataGrid -->
        <DataGrid Grid.Row="2" Name="dgFiles"
                  AutoGenerateColumns="False" IsReadOnly="True"
                  SelectionMode="Extended" SelectionUnit="FullRow"
                  Background="#181825" Foreground="{StaticResource TextBrush}"
                  RowBackground="#1E1E2E" AlternatingRowBackground="#242436"
                  BorderBrush="#45475A" BorderThickness="1"
                  GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#313244"
                  HeadersVisibility="Column" CanUserResizeRows="False"
                  FontSize="12.5" ColumnHeaderHeight="30" RowHeight="26">
            <DataGrid.ColumnHeaderStyle>
                <Style TargetType="DataGridColumnHeader">
                    <Setter Property="Background"  Value="#313244"/>
                    <Setter Property="Foreground"  Value="{StaticResource AccentBrush}"/>
                    <Setter Property="Padding"     Value="8,4"/>
                    <Setter Property="FontWeight"  Value="SemiBold"/>
                    <Setter Property="BorderBrush" Value="#45475A"/>
                    <Setter Property="BorderThickness" Value="0,0,1,1"/>
                </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.Columns>
                <DataGridTextColumn Header="Filename" Binding="{Binding filename}" Width="*">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock"><Setter Property="Padding" Value="6,0"/></Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Size (MB)" Binding="{Binding sizeMB}" Width="90">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="HorizontalAlignment" Value="Right"/>
                            <Setter Property="Padding" Value="0,0,8,0"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Uploaded" Binding="{Binding uploadedAt}" Width="110">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock"><Setter Property="Padding" Value="6,0"/></Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
            </DataGrid.Columns>
        </DataGrid>

        <!-- Row 3 – Progress bar -->
        <ProgressBar Grid.Row="3" Name="pbProgress" Height="4" Margin="0,8,0,0"
                     Background="#313244" Foreground="#89B4FA" Visibility="Collapsed"
                     IsIndeterminate="True"/>

        <!-- Row 4 – Status bar -->
        <Border Grid.Row="4" Margin="0,6,0,0">
            <TextBlock Name="tbStatus" Text="Ready" FontSize="12"
                       Foreground="{StaticResource SubTextBrush}"/>
        </Border>
    </Grid>
</Window>
"@

# ── Build window ──────────────────────────────────────────────────────────────
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Named controls
$pbAuthKey   = $window.FindName("pbAuthKey")
$tbAuthKeyPlain = $window.FindName("tbAuthKeyPlain")
$btnToggleAuth = $window.FindName("btnToggleAuth")
$tbBaseUrl   = $window.FindName("tbBaseUrl")
$tbSavePath  = $window.FindName("tbSavePath")
$btnBrowse   = $window.FindName("btnBrowse")
$btnRefresh  = $window.FindName("btnRefresh")
$btnDownload = $window.FindName("btnDownload")
$btnUpload   = $window.FindName("btnUpload")
$btnDelete   = $window.FindName("btnDelete")
$dgFiles     = $window.FindName("dgFiles")
$pbProgress  = $window.FindName("pbProgress")
$tbStatus    = $window.FindName("tbStatus")

$pbAuthKey.Password = $script:AuthKey
$tbAuthKeyPlain.Text = $script:AuthKey
$tbBaseUrl.Text = $script:BaseUrl
$tbSavePath.Text = $script:SavePath

# ── Helpers ───────────────────────────────────────────────────────────────────
function Set-Status {
    param([string]$Msg, [string]$Color = "#A6ADC8")
    $tbStatus.Text       = $Msg
    $tbStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($Color)
}

function Show-Busy  { $pbProgress.Visibility = "Visible" }
function Hide-Busy  { $pbProgress.Visibility = "Collapsed" }

function Get-AuthKeyText {
    if ($pbAuthKey.Visibility -eq "Visible") { return $pbAuthKey.Password.Trim() }
    return $tbAuthKeyPlain.Text.Trim()
}

function Get-BaseUrl {
    $baseUrl = $tbBaseUrl.Text.Trim().TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($baseUrl)) {
        throw "Base URL is required."
    }
    return $baseUrl
}

function Get-AuthHeaders {
    @{ "X-Auth-Key" = Get-AuthKeyText }
}

$btnToggleAuth.Add_Click({
    if ($pbAuthKey.Visibility -eq "Visible") {
        $tbAuthKeyPlain.Text = $pbAuthKey.Password
        $pbAuthKey.Visibility = "Collapsed"
        $tbAuthKeyPlain.Visibility = "Visible"
        $btnToggleAuth.Content = "Hide"
        return
    }

    $pbAuthKey.Password = $tbAuthKeyPlain.Text
    $tbAuthKeyPlain.Visibility = "Collapsed"
    $pbAuthKey.Visibility = "Visible"
    $btnToggleAuth.Content = "Show"
})

# ── Browse folder ─────────────────────────────────────────────────────────────
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.SelectedPath = $tbSavePath.Text
    if ($dlg.ShowDialog() -eq "OK") { $tbSavePath.Text = $dlg.SelectedPath }
})

# ── Refresh list ──────────────────────────────────────────────────────────────
$btnRefresh.Add_Click({
    try {
        Show-Busy
        Set-Status "Fetching file list…"
        $btnRefresh.IsEnabled = $false

        $headers = Get-AuthHeaders
        $baseUrl = Get-BaseUrl
        $resp    = Invoke-RestMethod -Uri "$baseUrl/uploads" -Headers $headers -ErrorAction Stop
        $files   = $resp.files | Sort-Object -Property uploadedAt

        # Add sizeMB property for display
        $rows = foreach ($f in $files) {
            [PSCustomObject]@{
                filename   = $f.filename
                size       = $f.size
                sizeMB     = "{0:N1}" -f ($f.size / 1MB)
                uploadedAt = $f.uploadedAt
            }
        }

        $dgFiles.ItemsSource = @($rows)
        Set-Status "$($rows.Count) file(s) loaded" "#A6E3A1"
    }
    catch {
        Set-Status "Error: $_" "#F38BA8"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Refresh Error",
            "OK", "Error") | Out-Null
    }
    finally {
        $btnRefresh.IsEnabled = $true
        Hide-Busy
    }
})

# ── Enable/disable Download button on selection ──────────────────────────────
$dgFiles.Add_SelectionChanged({
    $hasSelection = ($dgFiles.SelectedItems.Count -gt 0)
    $btnDownload.IsEnabled = $hasSelection
    $btnDelete.IsEnabled   = $hasSelection
})

# ── Download selected ────────────────────────────────────────────────────────
$btnDownload.Add_Click({
    $selected = @($dgFiles.SelectedItems)
    if ($selected.Count -eq 0) { return }

    $saveTo = $tbSavePath.Text.TrimEnd('\')
    if (-not (Test-Path $saveTo)) {
        [System.Windows.MessageBox]::Show("Save path does not exist: $saveTo",
            "Download", "OK", "Warning") | Out-Null
        return
    }

    $btnDownload.IsEnabled = $false
    Show-Busy
    $total   = $selected.Count
    $current = 0
    try {
        $baseUrl = Get-BaseUrl
    }
    catch {
        Set-Status "Error: $_" "#F38BA8"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Download Error",
            "OK", "Error") | Out-Null
        $btnDownload.IsEnabled = ($dgFiles.SelectedItems.Count -gt 0)
        Hide-Busy
        return
    }

    foreach ($item in $selected) {
        $current++
        $fn = $item.filename
        Set-Status "Downloading $current/$total – $fn …"

        try {
            $headers = Get-AuthHeaders
            $headers["X-Filename"] = $fn
            $outFile = Join-Path $saveTo $fn

            Invoke-RestMethod -Uri "$baseUrl/download" `
                              -Headers $headers `
                              -OutFile $outFile `
                              -ErrorAction Stop

            Set-Status "Saved: $outFile" "#A6E3A1"
        }
        catch {
            Set-Status "Failed: $fn – $_" "#F38BA8"
            $answer = [System.Windows.MessageBox]::Show(
                "Failed to download ${fn}:`n$($_.Exception.Message)`n`nContinue with remaining files?",
                "Download Error", "YesNo", "Error")
            if ($answer -eq "No") { break }
        }
    }

    if ($current -eq $total) {
        Set-Status "Downloaded $total file(s) to $saveTo" "#A6E3A1"
    }
    $btnDownload.IsEnabled = ($dgFiles.SelectedItems.Count -gt 0)
    Hide-Busy
})

# ── Delete selected ───────────────────────────────────────────────────────────
$btnDelete.Add_Click({
    $selected = @($dgFiles.SelectedItems)
    if ($selected.Count -eq 0) { return }

    $confirm = [System.Windows.MessageBox]::Show(
        "Delete $($selected.Count) file(s) from the server?`n`nThis cannot be undone.",
        "Confirm Delete", "YesNo", "Warning")
    if ($confirm -ne "Yes") { return }

    $btnDelete.IsEnabled = $false
    Show-Busy
    $total   = $selected.Count
    $current = 0
    $deleted = 0
    try {
        $baseUrl = Get-BaseUrl
    }
    catch {
        Set-Status "Error: $_" "#F38BA8"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Delete Error",
            "OK", "Error") | Out-Null
        $btnDelete.IsEnabled = ($dgFiles.SelectedItems.Count -gt 0)
        Hide-Busy
        return
    }

    foreach ($item in $selected) {
        $current++
        $fn = $item.filename
        Set-Status "Deleting $current/$total – $fn …"

        try {
            $headers = Get-AuthHeaders
            $headers["X-Filename"] = $fn

            Invoke-RestMethod -Uri "$baseUrl/uploads" `
                              -Method Delete `
                              -Headers $headers `
                              -ErrorAction Stop

            $deleted++
            Set-Status "Deleted: $fn" "#A6E3A1"
        }
        catch {
            Set-Status "Failed: $fn – $_" "#F38BA8"
            $answer = [System.Windows.MessageBox]::Show(
                "Failed to delete ${fn}:`n$($_.Exception.Message)`n`nContinue with remaining files?",
                "Delete Error", "YesNo", "Error")
            if ($answer -eq "No") { break }
        }
    }

    Set-Status "Deleted $deleted of $total file(s)" "#A6E3A1"
    $btnDelete.IsEnabled = ($dgFiles.SelectedItems.Count -gt 0)
    Hide-Busy

    # Auto-refresh the list
    if ($deleted -gt 0) { $btnRefresh.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
})

# ── Upload file ───────────────────────────────────────────────────────────────
$btnUpload.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title  = "Select file to upload"
    $dlg.Filter = "All files (*.*)|*.*|ZIP files (*.zip)|*.zip"
    if ($dlg.ShowDialog() -ne "OK") { return }

    $filePath = $dlg.FileName
    $fileName = [System.IO.Path]::GetFileName($filePath)

    $confirm = [System.Windows.MessageBox]::Show(
        "Upload $($fileName)?", "Confirm Upload", "YesNo", "Question")
    if ($confirm -ne "Yes") { return }

    try {
        Show-Busy
        Set-Status "Uploading $fileName …"
        $btnUpload.IsEnabled = $false
        $baseUrl = Get-BaseUrl

        # Build multipart form
        Add-Type -AssemblyName System.Net.Http
        $httpClient  = [System.Net.Http.HttpClient]::new()
        $httpClient.DefaultRequestHeaders.Add("X-Auth-Key", (Get-AuthKeyText))

        $form    = [System.Net.Http.MultipartFormDataContent]::new()
        $stream  = [System.IO.File]::OpenRead($filePath)
        $content = [System.Net.Http.StreamContent]::new($stream)
        $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new("application/octet-stream")
        $form.Add($content, "file", $fileName)

        $response = $httpClient.PostAsync("$baseUrl/upload", $form).GetAwaiter().GetResult()
        $body     = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        $stream.Dispose()
        $httpClient.Dispose()

        if ($response.IsSuccessStatusCode) {
            $json = $body | ConvertFrom-Json
            Set-Status "Uploaded: $($json.savedAs)  ($([math]::Round($json.size/1MB,1)) MB)" "#A6E3A1"
            [System.Windows.MessageBox]::Show(
                "Upload successful!`nSaved as: $($json.savedAs)",
                "Upload", "OK", "Information") | Out-Null
        }
        else {
            throw "Server returned $($response.StatusCode): $body"
        }
    }
    catch {
        Set-Status "Upload failed: $_" "#F38BA8"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Upload Error",
            "OK", "Error") | Out-Null
    }
    finally {
        $btnUpload.IsEnabled = $true
        Hide-Busy
    }
})

# ── Show ──────────────────────────────────────────────────────────────────────
$window.ShowDialog() | Out-Null
