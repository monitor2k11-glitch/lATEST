<#
.SYNOPSIS
    Probe — a WPF-based URL Status & Web Diagnostics tool.

.DESCRIPTION
    Performs real DNS resolution, TCP connect timing, TLS handshake + certificate
    inspection, and a full HTTP request (status, headers, redirects, body) against
    any URL, then renders the results in a dark-themed WPF dashboard with a health
    score, traffic-light signals, a timing breakdown, plain-English "smart insights",
    and tabs for Headers / SSL / Performance / Raw response / JSON.

    Unlike a browser-based version of this tool, PowerShell is not subject to CORS,
    so it can report genuine DNS/TCP/TLS timings and real certificate details
    (issuer, expiry, thumbprint) for any reachable host.

.NOTES
    Requires Windows (WPF). Works on Windows PowerShell 5.1 out of the box.
    On PowerShell 7+, WPF apps must run in a single-threaded apartment:
        pwsh -sta -File .\Probe.ps1
#>

# ---------------------------------------------------------------------------
# Assemblies
# ---------------------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Net.Http

# ---------------------------------------------------------------------------
# XAML — UI layout
# ---------------------------------------------------------------------------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PROBE — URL Status &amp; Web Diagnostics" Height="900" Width="1180"
        WindowStartupLocation="CenterScreen"
        Background="#0B1115" FontFamily="Segoe UI">
    <Window.Resources>
        <SolidColorBrush x:Key="BgBrush" Color="#0B1115"/>
        <SolidColorBrush x:Key="PanelBrush" Color="#111A20"/>
        <SolidColorBrush x:Key="PanelRaisedBrush" Color="#152128"/>
        <SolidColorBrush x:Key="LineBrush" Color="#1F2E37"/>
        <SolidColorBrush x:Key="TextBrush" Color="#DBE6EA"/>
        <SolidColorBrush x:Key="TextDimBrush" Color="#8BA0AA"/>
        <SolidColorBrush x:Key="TextFaintBrush" Color="#54666F"/>
        <SolidColorBrush x:Key="AccentBrush" Color="#5FD0C9"/>
        <SolidColorBrush x:Key="AccentDarkBrush" Color="#04211F"/>
        <SolidColorBrush x:Key="GreenBrush" Color="#6FD08A"/>
        <SolidColorBrush x:Key="AmberBrush" Color="#E8B657"/>
        <SolidColorBrush x:Key="RedBrush" Color="#E8636B"/>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{DynamicResource PanelRaisedBrush}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,7"/>
            <Setter Property="CaretBrush" Value="{DynamicResource AccentBrush}"/>
            <Setter Property="FontFamily" Value="Consolas"/>
        </Style>
        <Style TargetType="PasswordBox">
            <Setter Property="Background" Value="{DynamicResource PanelRaisedBrush}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,7"/>
            <Setter Property="FontFamily" Value="Consolas"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="{DynamicResource PanelRaisedBrush}"/>
            <Setter Property="Foreground" Value="#0B1115"/>
            <Setter Property="FontFamily" Value="Consolas"/>
        </Style>
        <Style TargetType="Button" x:Key="GhostBtn">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{DynamicResource TextDimBrush}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="Button" x:Key="PrimaryBtn">
            <Setter Property="Background" Value="{DynamicResource AccentBrush}"/>
            <Setter Property="Foreground" Value="{DynamicResource AccentDarkBrush}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="18,8"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="TabItem">
            <Setter Property="Foreground" Value="{DynamicResource TextFaintBrush}"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="14,8"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Grid Grid.Row="0" Margin="0,0,0,16">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="❯ PROBE" FontFamily="Consolas" FontWeight="Bold" FontSize="18" Foreground="{DynamicResource AccentBrush}"/>
                <TextBlock Text="  url status &amp; web diagnostics · powershell edition" FontFamily="Consolas" FontSize="11" Foreground="{DynamicResource TextFaintBrush}" VerticalAlignment="Bottom" Margin="0,0,0,2"/>
            </StackPanel>
            <StackPanel Grid.Column="1" Orientation="Horizontal">
                <Button x:Name="ThemeBtn" Content="◐ Theme" Style="{StaticResource GhostBtn}" Margin="0,0,8,0"/>
                <Button x:Name="ResetBtn" Content="↺ Reset" Style="{StaticResource GhostBtn}"/>
            </StackPanel>
        </Grid>
        <Border Grid.Row="0" VerticalAlignment="Bottom" BorderBrush="{DynamicResource LineBrush}" BorderThickness="0,0,0,1" Margin="0,0,0,-16"/>

        <!-- Input panel -->
        <Border Grid.Row="1" Background="{DynamicResource PanelBrush}" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" Padding="18" Margin="0,16,0,16">
            <StackPanel>
                <TextBlock Text="TARGET" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,10"/>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="110"/>
                        <ColumnDefinition Width="120"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="UrlBox" Grid.Column="0" Margin="0,0,10,0" FontSize="14"
                             Text="" ToolTip="example.com or https://api.example.com/health"/>
                    <ComboBox x:Name="MethodBox" Grid.Column="1" Margin="0,0,10,0" SelectedIndex="0">
                        <ComboBoxItem Content="GET"/>
                        <ComboBoxItem Content="HEAD"/>
                        <ComboBoxItem Content="POST"/>
                        <ComboBoxItem Content="OPTIONS"/>
                    </ComboBox>
                    <Button x:Name="AnalyzeBtn" Grid.Column="2" Content="Analyze" Style="{StaticResource PrimaryBtn}"/>
                </Grid>

                <Expander x:Name="AdvExpander" Header="Auth &amp; advanced options" Foreground="{DynamicResource TextFaintBrush}"
                          FontFamily="Consolas" FontSize="11" Margin="0,14,0,0">
                    <StackPanel Margin="0,14,0,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="16"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock Text="BASIC AUTH — USER" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,4"/>
                                <TextBox x:Name="BasicUserBox"/>
                            </StackPanel>
                            <StackPanel Grid.Column="2">
                                <TextBlock Text="BASIC AUTH — PASSWORD" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,4"/>
                                <PasswordBox x:Name="BasicPassBox"/>
                            </StackPanel>
                        </Grid>
                        <TextBlock Text="BEARER TOKEN" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,12,0,4"/>
                        <TextBox x:Name="BearerBox"/>
                        <TextBlock Text="CUSTOM HEADERS (one per line, Name: Value)" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,12,0,4"/>
                        <TextBox x:Name="HeadersBox" Height="70" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
                        <Grid Margin="0,12,0,0">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="20"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="60"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <CheckBox x:Name="IgnoreCertChk" Grid.Column="0" Content="Ignore certificate errors (still reports them)"
                                      Foreground="{DynamicResource TextDimBrush}" FontFamily="Consolas" FontSize="11.5" VerticalAlignment="Center"/>
                            <TextBlock Grid.Column="2" Text="Timeout (s)" Foreground="{DynamicResource TextDimBrush}" FontFamily="Consolas" FontSize="11.5" VerticalAlignment="Center"/>
                            <TextBox x:Name="TimeoutBox" Grid.Column="3" Text="8" VerticalAlignment="Center" Padding="6,4" Margin="8,0,0,0"/>
                        </Grid>
                    </StackPanel>
                </Expander>

                <WrapPanel x:Name="RecentPanel" Margin="0,12,0,0"/>
            </StackPanel>
        </Border>

        <!-- Results -->
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="ResultsPanel" Visibility="Collapsed">

                <TextBlock x:Name="StatusLine" FontFamily="Consolas" FontSize="12" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,12"/>

                <Grid Margin="0,0,0,14">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="180"/>
                        <ColumnDefinition Width="14"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <Border Grid.Column="0" Background="{DynamicResource PanelBrush}" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" Padding="10">
                        <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                            <Border x:Name="ScoreTile" Width="96" Height="96" CornerRadius="48" BorderThickness="4" BorderBrush="{DynamicResource GreenBrush}">
                                <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                                    <TextBlock x:Name="ScoreNumText" Text="—" FontFamily="Consolas" FontSize="28" FontWeight="Bold"
                                               Foreground="{DynamicResource TextBrush}" HorizontalAlignment="Center"/>
                                    <TextBlock Text="HEALTH" FontFamily="Consolas" FontSize="8" Foreground="{DynamicResource TextFaintBrush}" HorizontalAlignment="Center"/>
                                </StackPanel>
                            </Border>
                            <TextBlock x:Name="ScoreVerdictText" Text="awaiting scan" FontFamily="Consolas" FontSize="10.5"
                                       Foreground="{DynamicResource TextFaintBrush}" HorizontalAlignment="Center" Margin="0,10,0,0"/>
                        </StackPanel>
                    </Border>

                    <WrapPanel x:Name="SignalsPanel" Grid.Column="2"/>
                </Grid>

                <Border Background="{DynamicResource PanelBrush}" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" Padding="16" Margin="0,0,0,14">
                    <StackPanel>
                        <TextBlock Text="TIMING BREAKDOWN" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,10"/>
                        <StackPanel x:Name="TimelinePanel"/>
                        <TextBlock x:Name="TimingNote" FontFamily="Consolas" FontSize="10.5" Foreground="{DynamicResource TextFaintBrush}"
                                   Margin="0,8,0,0" TextWrapping="Wrap"
                                   Text="DNS / TCP / TLS are measured on a dedicated probe connection; TTFB / Download are measured on the actual HTTP request connection."/>
                    </StackPanel>
                </Border>

                <Border Background="{DynamicResource PanelBrush}" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" Padding="16" Margin="0,0,0,14">
                    <StackPanel>
                        <TextBlock Text="SMART INSIGHTS" FontFamily="Consolas" FontSize="10" Foreground="{DynamicResource TextFaintBrush}" Margin="0,0,0,6"/>
                        <StackPanel x:Name="InsightsPanel"/>
                    </StackPanel>
                </Border>

                <Border Background="{DynamicResource PanelBrush}" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1">
                    <TabControl x:Name="ResultTabs" Background="Transparent" BorderThickness="0" Margin="0">
                        <TabItem Header="HEADERS">
                            <ScrollViewer MaxHeight="360" VerticalScrollBarVisibility="Auto">
                                <StackPanel x:Name="HeadersTabPanel" Margin="16"/>
                            </ScrollViewer>
                        </TabItem>
                        <TabItem Header="SSL / CERT">
                            <ScrollViewer MaxHeight="360" VerticalScrollBarVisibility="Auto">
                                <StackPanel x:Name="SslTabPanel" Margin="16"/>
                            </ScrollViewer>
                        </TabItem>
                        <TabItem Header="PERFORMANCE">
                            <ScrollViewer MaxHeight="360" VerticalScrollBarVisibility="Auto">
                                <StackPanel x:Name="PerfTabPanel" Margin="16"/>
                            </ScrollViewer>
                        </TabItem>
                        <TabItem Header="RAW RESPONSE">
                            <TextBox x:Name="RawTabBox" Margin="16" Height="340" FontFamily="Consolas" FontSize="11.5"
                                     TextWrapping="Wrap" AcceptsReturn="True" IsReadOnly="True" VerticalScrollBarVisibility="Auto"/>
                        </TabItem>
                        <TabItem Header="JSON">
                            <TextBox x:Name="JsonTabBox" Margin="16" Height="340" FontFamily="Consolas" FontSize="11.5"
                                     TextWrapping="Wrap" AcceptsReturn="True" IsReadOnly="True" VerticalScrollBarVisibility="Auto"/>
                        </TabItem>
                    </TabControl>
                </Border>

                <TextBlock Text=" " Height="20"/>
            </StackPanel>
        </ScrollViewer>
    </Grid>
</Window>
'@

# ---------------------------------------------------------------------------
# Load window
# ---------------------------------------------------------------------------
$reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($xaml)))
$window = [Windows.Markup.XamlReader]::Load($reader)

$controls = @{}
foreach ($name in @('UrlBox','MethodBox','AnalyzeBtn','ThemeBtn','ResetBtn','AdvExpander',
                     'BasicUserBox','BasicPassBox','BearerBox','HeadersBox','IgnoreCertChk','TimeoutBox',
                     'RecentPanel','ResultsPanel','StatusLine','ScoreTile','ScoreNumText','ScoreVerdictText',
                     'SignalsPanel','TimelinePanel','TimingNote','InsightsPanel','ResultTabs',
                     'HeadersTabPanel','SslTabPanel','PerfTabPanel','RawTabBox','JsonTabBox')) {
    $controls[$name] = $window.FindName($name)
}

# ---------------------------------------------------------------------------
# Theme handling
# ---------------------------------------------------------------------------
$script:IsDark = $true
$darkColors  = @{ Bg='#0B1115'; Panel='#111A20'; PanelRaised='#152128'; Line='#1F2E37'; Text='#DBE6EA'; TextDim='#8BA0AA'; TextFaint='#54666F' }
$lightColors = @{ Bg='#EEF2F3'; Panel='#FFFFFF'; PanelRaised='#F6F8F9'; Line='#D7DFE2'; Text='#182226'; TextDim='#5A6B72'; TextFaint='#93A3A9' }

function Set-Theme {
    param([bool]$Dark)
    $c = if ($Dark) { $darkColors } else { $lightColors }
    $window.Resources['BgBrush']          = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.Bg))
    $window.Resources['PanelBrush']       = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.Panel))
    $window.Resources['PanelRaisedBrush'] = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.PanelRaised))
    $window.Resources['LineBrush']        = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.Line))
    $window.Resources['TextBrush']        = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.Text))
    $window.Resources['TextDimBrush']     = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.TextDim))
    $window.Resources['TextFaintBrush']   = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($c.TextFaint))
    $window.Background = $window.Resources['BgBrush']
    $controls.ThemeBtn.Content = if ($Dark) { '◐ Theme' } else { '◑ Theme' }
}
Set-Theme -Dark $true
$controls.ThemeBtn.Add_Click({ $script:IsDark = -not $script:IsDark; Set-Theme -Dark $script:IsDark })

# ---------------------------------------------------------------------------
# Recent URL history (persisted to %TEMP%\probe_recent.json)
# ---------------------------------------------------------------------------
$recentFile = Join-Path $env:TEMP 'probe_recent.json'

function Get-RecentUrls {
    if (Test-Path $recentFile) {
        try { return @(Get-Content $recentFile -Raw | ConvertFrom-Json) } catch { return @() }
    }
    return @()
}
function Save-RecentUrl {
    param([string]$Url)
    $list = @(Get-RecentUrls | Where-Object { $_ -ne $Url })
    $list = @($Url) + $list
    $list = $list | Select-Object -First 5
    $list | ConvertTo-Json | Set-Content $recentFile
    Render-RecentChips
}
function Render-RecentChips {
    $controls.RecentPanel.Children.Clear()
    foreach ($u in (Get-RecentUrls)) {
        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = $u
        $btn.Tag = $u
        $btn.Margin = '0,0,8,8'
        $btn.Padding = '10,5'
        $btn.FontFamily = 'Consolas'
        $btn.FontSize = 11
        $btn.Background = $window.Resources['PanelRaisedBrush']
        $btn.Foreground = $window.Resources['TextDimBrush']
        $btn.BorderBrush = $window.Resources['LineBrush']
        $btn.Cursor = 'Hand'
        $btn.Add_Click({
            param($sender,$e)
            $controls.UrlBox.Text = $sender.Tag
            Start-Analysis
        })
        $controls.RecentPanel.Children.Add($btn) | Out-Null
    }
}
Render-RecentChips

# ---------------------------------------------------------------------------
# Diagnostics engine (runs on a background PowerShell instance)
# ---------------------------------------------------------------------------
$DiagBlock = {
    param(
        [string]$Url,
        [string]$Method,
        [int]$TimeoutSec,
        [hashtable]$Headers,
        [bool]$IgnoreCertErrors
    )

    $report = @{
        TargetUrl = $Url
        Method    = $Method
        Timing    = @{}
        Http      = @{ Status = $null; StatusText = ''; Headers = @{}; FinalUrl = $null }
        Security  = @{}
        Content   = @{}
        Errors    = @()
    }

    try {
        $uri = [Uri]$Url
    } catch {
        $report.Errors += "INVALID_URL: $($_.Exception.Message)"
        return $report
    }

    $hostname = $uri.Host
    $port     = if ($uri.Port -gt 0) { $uri.Port } elseif ($uri.Scheme -eq 'https') { 443 } else { 80 }
    $isHttps  = $uri.Scheme -eq 'https'
    $report.Security.IsHttps = $isHttps

    # --- DNS ---
    $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($hostname)
        $dnsSw.Stop()
        $report.Timing.Dns = $dnsSw.Elapsed.TotalMilliseconds
        $report.Content.ResolvedIPs = ($addresses | ForEach-Object { $_.IPAddressToString }) -join ', '
    } catch {
        $dnsSw.Stop()
        $report.Errors += "DNS_FAILED: Could not resolve host '$hostname'. $($_.Exception.Message)"
        return $report
    }

    # --- TCP connect ---
    $targetIp = $addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if (-not $targetIp) { $targetIp = $addresses[0] }

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpSw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $tcpClient.BeginConnect($targetIp, $port, $null, $null)
        $connected = $iar.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)
        if (-not $connected) {
            $tcpSw.Stop()
            $report.Errors += "TIMEOUT: TCP connect to $($targetIp):$port did not complete within $TimeoutSec s."
            return $report
        }
        $tcpClient.EndConnect($iar)
        $tcpSw.Stop()
        $report.Timing.Tcp = $tcpSw.Elapsed.TotalMilliseconds
    } catch {
        $tcpSw.Stop()
        $report.Errors += "CONNECTION_REFUSED: Could not open a TCP connection to $($targetIp):$port. $($_.Exception.Message)"
        return $report
    }

    # --- TLS handshake + certificate ---
    if ($isHttps) {
        try {
            $script:certErrorsSeen = $null
            $script:remoteCert = $null
            $validationCallback = {
                param($sender, $certificate, $chain, $sslPolicyErrors)
                $script:certErrorsSeen = $sslPolicyErrors
                $script:remoteCert = $certificate
                return $true
            }
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $validationCallback)
            $tlsSw = [System.Diagnostics.Stopwatch]::StartNew()
            $sslStream.AuthenticateAsClient($hostname)
            $tlsSw.Stop()
            $report.Timing.Tls = $tlsSw.Elapsed.TotalMilliseconds
            $report.Security.SslProtocol = $sslStream.SslProtocol.ToString()
            $report.Security.CipherAlgorithm = $sslStream.CipherAlgorithm.ToString()

            if ($script:remoteCert) {
                $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($script:remoteCert)
                $report.Security.CertSubject      = $cert2.Subject
                $report.Security.CertIssuer       = $cert2.Issuer
                $report.Security.CertNotBefore    = $cert2.NotBefore.ToString('u')
                $report.Security.CertNotAfter     = $cert2.NotAfter.ToString('u')
                $report.Security.CertThumbprint   = $cert2.Thumbprint
                $daysLeft = ($cert2.NotAfter - (Get-Date)).TotalDays
                $report.Security.CertDaysRemaining = [math]::Round($daysLeft, 1)
                $report.Security.CertValid = ($script:certErrorsSeen -eq [System.Net.Security.SslPolicyErrors]::None)
                $report.Security.CertPolicyErrors = $script:certErrorsSeen.ToString()
            }
            $sslStream.Close()
        } catch {
            $report.Errors += "TLS_HANDSHAKE_FAILED: $($_.Exception.Message)"
        }
    }
    $tcpClient.Close()

    # --- HTTP request (separate connection via HttpClient) ---
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $true
        if ($IgnoreCertErrors) {
            $handler.ServerCertificateCustomValidationCallback = { $true }
        }
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

        $httpMethod = switch ($Method) {
            'GET'     { [System.Net.Http.HttpMethod]::Get }
            'POST'    { [System.Net.Http.HttpMethod]::Post }
            'HEAD'    { [System.Net.Http.HttpMethod]::Head }
            'OPTIONS' { [System.Net.Http.HttpMethod]::Options }
            default   { [System.Net.Http.HttpMethod]::Get }
        }

        $request = New-Object System.Net.Http.HttpRequestMessage($httpMethod, $uri)
        if ($Headers) {
            foreach ($key in $Headers.Keys) {
                try { $request.Headers.TryAddWithoutValidation($key, $Headers[$key]) | Out-Null } catch {}
            }
        }

        $httpSw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $ttfb = $httpSw.Elapsed.TotalMilliseconds

        $bodyText = ''
        if ($Method -ne 'HEAD') {
            $bodyText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
        $httpSw.Stop()
        $total = $httpSw.Elapsed.TotalMilliseconds

        $report.Timing.Ttfb     = $ttfb
        $report.Timing.Download = [math]::Max(0, $total - $ttfb)

        $tlsMs = if ($report.Timing.Tls) { $report.Timing.Tls } else { 0 }
        $report.Timing.Total = $report.Timing.Dns + $report.Timing.Tcp + $tlsMs + $total

        $report.Http.Status     = [int]$response.StatusCode
        $report.Http.StatusText = $response.ReasonPhrase
        $report.Http.FinalUrl   = $response.RequestMessage.RequestUri.ToString()

        $allHeaders = @{}
        foreach ($h in $response.Headers)         { $allHeaders[$h.Key] = ($h.Value -join ', ') }
        foreach ($h in $response.Content.Headers)  { $allHeaders[$h.Key] = ($h.Value -join ', ') }
        $report.Http.Headers = $allHeaders

        $report.Content.ContentType     = $allHeaders['Content-Type']
        $report.Content.ContentEncoding = $allHeaders['Content-Encoding']
        $report.Content.CacheControl    = $allHeaders['Cache-Control']
        $report.Content.Server          = $allHeaders['Server']
        $report.Content.ContentLength   = $allHeaders['Content-Length']
        $report.Content.BodySize        = $bodyText.Length
        $report.Content.RawSnippet      = if ($bodyText.Length -gt 20000) { $bodyText.Substring(0,20000) } else { $bodyText }

        $titlePattern = '<title[^>]*>([^<]*)</title>'
        $descPattern  = 'name=[\x22\x27]description[\x22\x27][^>]*content=[\x22\x27]([^\x22\x27]*)[\x22\x27]'
        $vpPattern    = 'name=[\x22\x27]viewport[\x22\x27][^>]*content=[\x22\x27]([^\x22\x27]*)[\x22\x27]'

        $m = [regex]::Match($bodyText, $titlePattern, 'IgnoreCase')
        if ($m.Success) { $report.Content.Title = $m.Groups[1].Value.Trim() }
        $m = [regex]::Match($bodyText, $descPattern, 'IgnoreCase')
        if ($m.Success) { $report.Content.Description = $m.Groups[1].Value }
        $m = [regex]::Match($bodyText, $vpPattern, 'IgnoreCase')
        if ($m.Success) { $report.Content.Viewport = $m.Groups[1].Value }

        $client.Dispose()
    } catch {
        $report.Errors += "HTTP_REQUEST_FAILED: $($_.Exception.Message)"
        $tlsMs = if ($report.Timing.Tls) { $report.Timing.Tls } else { 0 }
        $report.Timing.Total = $report.Timing.Dns + $report.Timing.Tcp + $tlsMs
    }

    return $report
}

# ---------------------------------------------------------------------------
# Score + insights builder (runs on UI thread, fast/local — no I/O)
# ---------------------------------------------------------------------------
function Build-ScoreAndInsights {
    param($Report)

    $score = 100
    $signals = New-Object System.Collections.Generic.List[object]
    $insights = New-Object System.Collections.Generic.List[object]

    if ($Report.Errors -and $Report.Errors.Count -gt 0) {
        foreach ($e in $Report.Errors) {
            $level = 'err'
            $text = $e
            $insights.Add(@{ Level = $level; Text = $text })
        }
        $signals.Add(@{ Label='Reachability'; Value='Unreachable'; Level='err' })
        return @{ Score = 0; Signals = $signals; Insights = $insights }
    }

    $status = $Report.Http.Status
    if ($status -ge 200 -and $status -lt 300) {
        $signals.Add(@{ Label='Status'; Value="$status OK"; Level='ok' })
    } elseif ($status -ge 300 -and $status -lt 400) {
        $signals.Add(@{ Label='Status'; Value="$status Redirect"; Level='warn' })
        $score -= 10
        $insights.Add(@{ Level='warn'; Text="Server responded with a $status redirect" + $(if ($Report.Http.FinalUrl -and $Report.Http.FinalUrl -ne $Report.TargetUrl) { " to $($Report.Http.FinalUrl)" } else { "" }) + "." })
    } elseif ($status -eq 401) {
        $signals.Add(@{ Label='Status'; Value='401 Unauthorized'; Level='err' })
        $score -= 40
        $insights.Add(@{ Level='err'; Text='401 Unauthorized — the server requires valid credentials. Check Basic Auth / Bearer token in advanced options.' })
    } elseif ($status -eq 403) {
        $signals.Add(@{ Label='Status'; Value='403 Forbidden'; Level='err' })
        $score -= 40
        $insights.Add(@{ Level='err'; Text='403 Forbidden — the server understood the request but refused it. Unlike 401, credentials alone may not fix this; check IP allow-lists, WAF rules, or resource permissions.' })
    } elseif ($status -eq 404) {
        $signals.Add(@{ Label='Status'; Value='404 Not Found'; Level='err' })
        $score -= 35
        $insights.Add(@{ Level='err'; Text='404 Not Found — the requested path does not exist on this server.' })
    } elseif ($status -ge 500) {
        $signals.Add(@{ Label='Status'; Value="$status Server Error"; Level='err' })
        $score -= 45
        $insights.Add(@{ Level='err'; Text="$status server error — the failure is on the server/application side. Check server-side logs." })
    } elseif ($status -ge 400) {
        $signals.Add(@{ Label='Status'; Value="$status Client Error"; Level='err' })
        $score -= 30
    } else {
        $signals.Add(@{ Label='Status'; Value="$status"; Level='warn' })
    }

    if ($Report.Security.IsHttps) {
        $signals.Add(@{ Label='Transport'; Value='HTTPS'; Level='ok' })
        if ($Report.Security.CertValid -eq $false) {
            $score -= 30
            $insights.Add(@{ Level='err'; Text="TLS certificate failed validation ($($Report.Security.CertPolicyErrors)). Browsers will show a warning to visitors." })
        }
        if ($Report.Security.CertDaysRemaining -ne $null) {
            if ($Report.Security.CertDaysRemaining -lt 0) {
                $score -= 35
                $insights.Add(@{ Level='err'; Text='TLS certificate has already EXPIRED.' })
            } elseif ($Report.Security.CertDaysRemaining -lt 14) {
                $score -= 15
                $insights.Add(@{ Level='warn'; Text="TLS certificate expires in $($Report.Security.CertDaysRemaining) days — renew soon." })
            } elseif ($Report.Security.CertDaysRemaining -lt 30) {
                $insights.Add(@{ Level='info'; Text="TLS certificate expires in $($Report.Security.CertDaysRemaining) days." })
            }
        }
        $hsts = $Report.Http.Headers['Strict-Transport-Security']
        if (-not $hsts) {
            $score -= 5
            $insights.Add(@{ Level='warn'; Text='No Strict-Transport-Security header — without HSTS, browsers can still be tricked into an initial insecure HTTP connection.' })
        }
    } else {
        $signals.Add(@{ Label='Transport'; Value='HTTP only'; Level='err' })
        $score -= 25
        $insights.Add(@{ Level='err'; Text='Site is served over plain HTTP, not HTTPS — traffic is unencrypted.' })
    }

    $ttfb = $Report.Timing.Ttfb
    if ($ttfb -ne $null) {
        $level = if ($ttfb -lt 300) { 'ok' } elseif ($ttfb -lt 1000) { 'warn' } else { 'err' }
        $signals.Add(@{ Label='TTFB'; Value=('{0:N0} ms' -f $ttfb); Level=$level })
        if ($ttfb -gt 1000) {
            $score -= 12
            $insights.Add(@{ Level='warn'; Text="Time to first byte is $([math]::Round($ttfb)) ms — slower than the ~800ms threshold generally considered responsive." })
        }
    }

    $encoding = $Report.Content.ContentEncoding
    if ($encoding) {
        $signals.Add(@{ Label='Compression'; Value=$encoding; Level='ok' })
    } else {
        $signals.Add(@{ Label='Compression'; Value='None detected'; Level='warn' })
        $clen = $Report.Content.ContentLength
        if ($clen -and [int64]$clen -gt 50000) {
            $score -= 8
            $insights.Add(@{ Level='warn'; Text="Response is $clen bytes with no Content-Encoding header — gzip/br compression doesn't appear to be enabled." })
        }
    }

    if (-not $Report.Content.CacheControl) {
        $insights.Add(@{ Level='info'; Text='No Cache-Control header — repeat requests will re-fetch the full response instead of using a cache.' })
    }
    if ($Report.Content.Server) {
        $insights.Add(@{ Level='info'; Text="Server header exposes: $($Report.Content.Server). Consider suppressing this in production to reduce fingerprinting surface." })
    }
    if (-not $Report.Http.Headers['Content-Security-Policy']) {
        $insights.Add(@{ Level='info'; Text='No Content-Security-Policy header detected.' })
    }
    if (-not $Report.Http.Headers['X-Frame-Options'] -and -not $Report.Http.Headers['Content-Security-Policy']) {
        $insights.Add(@{ Level='info'; Text='No X-Frame-Options or frame-ancestors policy found — page may be embeddable in a clickjacking iframe.' })
    }

    if ($insights.Count -eq 0) {
        $insights.Add(@{ Level='ok'; Text='No notable issues detected across all checks.' })
    }

    $score = [math]::Max(0, [math]::Min(100, [math]::Round($score)))
    return @{ Score = $score; Signals = $signals; Insights = $insights }
}

# ---------------------------------------------------------------------------
# UI rendering helpers
# ---------------------------------------------------------------------------
function Get-LevelBrush {
    param([string]$Level)
    switch ($Level) {
        'ok'   { return $window.Resources['GreenBrush'] }
        'warn' { return $window.Resources['AmberBrush'] }
        'err'  { return $window.Resources['RedBrush'] }
        default { return $window.Resources['AccentBrush'] }
    }
}

function New-KvTable {
    param([hashtable[]]$Rows)
    $panel = New-Object System.Windows.Controls.StackPanel
    foreach ($row in $Rows) {
        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = '0,0,0,6'
        $col1 = New-Object System.Windows.Controls.ColumnDefinition; $col1.Width = 240
        $col2 = New-Object System.Windows.Controls.ColumnDefinition
        $grid.ColumnDefinitions.Add($col1); $grid.ColumnDefinitions.Add($col2)

        $k = New-Object System.Windows.Controls.TextBlock
        $k.Text = $row.Key
        $k.FontFamily = 'Consolas'; $k.FontSize = 11.5
        $k.Foreground = $window.Resources['TextFaintBrush']
        [System.Windows.Controls.Grid]::SetColumn($k, 0)

        $v = New-Object System.Windows.Controls.TextBlock
        $v.Text = $(if ($null -eq $row.Value -or $row.Value -eq '') { '—' } else { [string]$row.Value })
        $v.FontFamily = 'Consolas'; $v.FontSize = 11.5
        $v.TextWrapping = 'Wrap'
        $v.Foreground = $window.Resources['TextBrush']
        [System.Windows.Controls.Grid]::SetColumn($v, 1)

        $grid.Children.Add($k) | Out-Null
        $grid.Children.Add($v) | Out-Null
        $panel.Children.Add($grid) | Out-Null
    }
    return $panel
}

function Update-ResultsUI {
    param($Report, $ScoreData)

    $controls.ResultsPanel.Visibility = 'Visible'
    $controls.StatusLine.Text = "Target: $($Report.TargetUrl)   |   Method: $($Report.Method)   |   Scanned: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # score tile
    $score = $ScoreData.Score
    $controls.ScoreNumText.Text = "$score"
    $color = if ($score -ge 80) { $window.Resources['GreenBrush'] } elseif ($score -ge 50) { $window.Resources['AmberBrush'] } else { $window.Resources['RedBrush'] }
    $controls.ScoreTile.BorderBrush = $color
    $controls.ScoreVerdictText.Foreground = $color
    $controls.ScoreVerdictText.Text = if ($score -ge 80) { 'healthy' } elseif ($score -ge 50) { 'needs attention' } else { 'critical issues' }

    # signals
    $controls.SignalsPanel.Children.Clear()
    foreach ($sig in $ScoreData.Signals) {
        $border = New-Object System.Windows.Controls.Border
        $border.Background = $window.Resources['PanelBrush']
        $border.BorderBrush = $window.Resources['LineBrush']
        $border.BorderThickness = 1
        $border.Padding = '12,10'
        $border.Margin = '0,0,10,10'
        $border.Width = 160
        $border.BorderThickness = New-Object System.Windows.Thickness(3,1,1,1)
        $border.BorderBrush = Get-LevelBrush -Level $sig.Level

        $sp = New-Object System.Windows.Controls.StackPanel
        $k = New-Object System.Windows.Controls.TextBlock
        $k.Text = $sig.Label.ToUpper()
        $k.FontFamily = 'Consolas'; $k.FontSize = 9.5
        $k.Foreground = $window.Resources['TextFaintBrush']
        $v = New-Object System.Windows.Controls.TextBlock
        $v.Text = $sig.Value
        $v.FontFamily = 'Consolas'; $v.FontSize = 15; $v.FontWeight = 'Bold'
        $v.Foreground = Get-LevelBrush -Level $sig.Level
        $v.Margin = '0,4,0,0'
        $sp.Children.Add($k) | Out-Null
        $sp.Children.Add($v) | Out-Null
        $border.Child = $sp
        $controls.SignalsPanel.Children.Add($border) | Out-Null
    }

    # timeline
    $controls.TimelinePanel.Children.Clear()
    $rows = @(
        @{ Label='DNS';      Value=$Report.Timing.Dns },
        @{ Label='TCP';      Value=$Report.Timing.Tcp },
        @{ Label='TLS';      Value=$Report.Timing.Tls },
        @{ Label='TTFB';     Value=$Report.Timing.Ttfb },
        @{ Label='Download'; Value=$Report.Timing.Download },
        @{ Label='Total';    Value=$Report.Timing.Total }
    )
    $maxVal = ($rows | Where-Object { $_.Value } | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
    if (-not $maxVal -or $maxVal -eq 0) { $maxVal = 1 }
    foreach ($row in $rows) {
        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = '0,0,0,8'
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = 90
        $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = '*'
        $c3 = New-Object System.Windows.Controls.ColumnDefinition; $c3.Width = 80
        $grid.ColumnDefinitions.Add($c1); $grid.ColumnDefinitions.Add($c2); $grid.ColumnDefinitions.Add($c3)

        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text = $row.Label; $lbl.FontFamily='Consolas'; $lbl.FontSize=11; $lbl.Foreground=$window.Resources['TextDimBrush']
        $lbl.VerticalAlignment = 'Center'
        [System.Windows.Controls.Grid]::SetColumn($lbl,0)

        $track = New-Object System.Windows.Controls.Border
        $track.Background = $window.Resources['PanelRaisedBrush']
        $track.Height = 8
        $track.CornerRadius = New-Object System.Windows.CornerRadius(4)
        [System.Windows.Controls.Grid]::SetColumn($track,1)
        if ($row.Value) {
            $pct = [math]::Max(0.02, [double]$row.Value / [double]$maxVal)
            $fill = New-Object System.Windows.Controls.Border
            $fill.Background = $window.Resources['AccentBrush']
            $fill.Height = 8
            $fill.CornerRadius = New-Object System.Windows.CornerRadius(4)
            $fill.HorizontalAlignment = 'Left'
            $fill.Width = [double]280 * $pct
            $track.Child = $fill
        }

        $val = New-Object System.Windows.Controls.TextBlock
        $val.Text = if ($row.Value) { '{0:N0} ms' -f $row.Value } else { 'n/a' }
        $val.FontFamily='Consolas'; $val.FontSize=11; $val.Foreground=$window.Resources['TextDimBrush']
        $val.HorizontalAlignment='Right'; $val.VerticalAlignment='Center'
        [System.Windows.Controls.Grid]::SetColumn($val,2)

        $grid.Children.Add($lbl) | Out-Null
        $grid.Children.Add($track) | Out-Null
        $grid.Children.Add($val) | Out-Null
        $controls.TimelinePanel.Children.Add($grid) | Out-Null
    }

    # insights
    $controls.InsightsPanel.Children.Clear()
    foreach ($ins in $ScoreData.Insights) {
        $row = New-Object System.Windows.Controls.StackPanel
        $row.Orientation = 'Horizontal'
        $row.Margin = '0,6,0,6'
        $icon = New-Object System.Windows.Controls.TextBlock
        $icon.Text = switch ($ins.Level) { 'ok' {'✓'} 'warn' {'!'} 'err' {'✕'} default {'i'} }
        $icon.FontFamily = 'Consolas'; $icon.Width = 20
        $icon.Foreground = Get-LevelBrush -Level $ins.Level
        $txt = New-Object System.Windows.Controls.TextBlock
        $txt.Text = $ins.Text
        $txt.FontSize = 12.5
        $txt.TextWrapping = 'Wrap'
        $txt.Width = 900
        $txt.Foreground = $window.Resources['TextDimBrush']
        $row.Children.Add($icon) | Out-Null
        $row.Children.Add($txt) | Out-Null
        $controls.InsightsPanel.Children.Add($row) | Out-Null
    }

    # headers tab
    $hRows = @(@{Key='Status'; Value="$($Report.Http.Status) $($Report.Http.StatusText)"})
    $hRows += @{Key='Final URL'; Value=$Report.Http.FinalUrl}
    if ($Report.Http.Headers) {
        foreach ($k in ($Report.Http.Headers.Keys | Sort-Object)) {
            $hRows += @{Key=$k; Value=$Report.Http.Headers[$k]}
        }
    }
    $controls.HeadersTabPanel.Children.Clear()
    $controls.HeadersTabPanel.Children.Add((New-KvTable -Rows $hRows)) | Out-Null

    # ssl tab
    $sRows = @(
        @{Key='Resolved IPs'; Value=$Report.Content.ResolvedIPs}
        @{Key='Protocol'; Value= if ($Report.Security.IsHttps) {'HTTPS (encrypted)'} else {'HTTP (unencrypted)'}}
    )
    if ($Report.Security.IsHttps) {
        $sRows += @{Key='TLS protocol'; Value=$Report.Security.SslProtocol}
        $sRows += @{Key='Cipher'; Value=$Report.Security.CipherAlgorithm}
        $sRows += @{Key='Certificate valid'; Value=$Report.Security.CertValid}
        $sRows += @{Key='Policy errors'; Value=$Report.Security.CertPolicyErrors}
        $sRows += @{Key='Subject'; Value=$Report.Security.CertSubject}
        $sRows += @{Key='Issuer'; Value=$Report.Security.CertIssuer}
        $sRows += @{Key='Valid from'; Value=$Report.Security.CertNotBefore}
        $sRows += @{Key='Valid until'; Value=$Report.Security.CertNotAfter}
        $sRows += @{Key='Days remaining'; Value=$Report.Security.CertDaysRemaining}
        $sRows += @{Key='Thumbprint'; Value=$Report.Security.CertThumbprint}
        $sRows += @{Key='HSTS'; Value=$Report.Http.Headers['Strict-Transport-Security']}
    }
    $sRows += @{Key='Content-Security-Policy'; Value=$Report.Http.Headers['Content-Security-Policy']}
    $sRows += @{Key='X-Frame-Options'; Value=$Report.Http.Headers['X-Frame-Options']}
    $controls.SslTabPanel.Children.Clear()
    $controls.SslTabPanel.Children.Add((New-KvTable -Rows $sRows)) | Out-Null

    # performance tab
    $pRows = @(
        @{Key='DNS lookup'; Value= if($Report.Timing.Dns){'{0:N1} ms' -f $Report.Timing.Dns}}
        @{Key='TCP connect'; Value= if($Report.Timing.Tcp){'{0:N1} ms' -f $Report.Timing.Tcp}}
        @{Key='TLS handshake'; Value= if($Report.Timing.Tls){'{0:N1} ms' -f $Report.Timing.Tls}}
        @{Key='TTFB'; Value= if($Report.Timing.Ttfb){'{0:N1} ms' -f $Report.Timing.Ttfb}}
        @{Key='Download'; Value= if($Report.Timing.Download){'{0:N1} ms' -f $Report.Timing.Download}}
        @{Key='Total (est.)'; Value= if($Report.Timing.Total){'{0:N1} ms' -f $Report.Timing.Total}}
        @{Key='Body size (decoded)'; Value= if($Report.Content.BodySize){"$($Report.Content.BodySize) bytes"}}
        @{Key='Content-Length header'; Value=$Report.Content.ContentLength}
        @{Key='Content-Type'; Value=$Report.Content.ContentType}
        @{Key='Content-Encoding'; Value=$Report.Content.ContentEncoding}
        @{Key='Cache-Control'; Value=$Report.Content.CacheControl}
        @{Key='Server header'; Value=$Report.Content.Server}
        @{Key='Page title'; Value=$Report.Content.Title}
        @{Key='Meta description'; Value=$Report.Content.Description}
        @{Key='Meta viewport'; Value=$Report.Content.Viewport}
    )
    $controls.PerfTabPanel.Children.Clear()
    $controls.PerfTabPanel.Children.Add((New-KvTable -Rows $pRows)) | Out-Null

    # raw tab
    $controls.RawTabBox.Text = if ($Report.Content.RawSnippet) { $Report.Content.RawSnippet } else { '(no body captured — HEAD request or request failed before a response was received)' }

    # json tab
    $jsonClone = $Report | ConvertTo-Json -Depth 6
    $controls.JsonTabBox.Text = $jsonClone
}

# ---------------------------------------------------------------------------
# Async run + poll (keeps the UI responsive during the scan)
# ---------------------------------------------------------------------------
$script:CurrentPs = $null
$script:CurrentAsync = $null
$script:PollTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:PollTimer.Interval = [TimeSpan]::FromMilliseconds(150)

$script:PollTimer.Add_Tick({
    if ($null -eq $script:CurrentAsync) { return }
    if ($script:CurrentAsync.IsCompleted) {
        $script:PollTimer.Stop()
        try {
            $resultCollection = $script:CurrentPs.EndInvoke($script:CurrentAsync)
            $report = $resultCollection[0]
            $scoreData = Build-ScoreAndInsights -Report $report
            Update-ResultsUI -Report $report -ScoreData $scoreData
        } catch {
            [System.Windows.MessageBox]::Show("Diagnostics failed: $($_.Exception.Message)", 'Probe') | Out-Null
        } finally {
            $script:CurrentPs.Dispose()
            $script:CurrentPs = $null
            $script:CurrentAsync = $null
            $controls.AnalyzeBtn.IsEnabled = $true
            $controls.AnalyzeBtn.Content = 'Analyze'
        }
    }
})

function Start-Analysis {
    $rawUrl = $controls.UrlBox.Text.Trim()
    if (-not $rawUrl) {
        [System.Windows.MessageBox]::Show('Enter a URL, e.g. example.com or https://example.com/path', 'Probe') | Out-Null
        return
    }
    if ($rawUrl -notmatch '^https?://') { $rawUrl = "https://$rawUrl" }
    $controls.UrlBox.Text = $rawUrl

    $method = ($controls.MethodBox.SelectedItem).Content.ToString()
    $timeoutSec = 8
    [int]::TryParse($controls.TimeoutBox.Text, [ref]$timeoutSec) | Out-Null
    if ($timeoutSec -lt 1) { $timeoutSec = 8 }
    if ($timeoutSec -gt 30) { $timeoutSec = 30 }

    $headers = @{}
    foreach ($line in $controls.HeadersBox.Text -split "`r?`n") {
        if ($line.Trim() -and $line.Contains(':')) {
            $idx = $line.IndexOf(':')
            $k = $line.Substring(0,$idx).Trim()
            $v = $line.Substring($idx+1).Trim()
            if ($k) { $headers[$k] = $v }
        }
    }
    $bearer = $controls.BearerBox.Text.Trim()
    if ($bearer) { $headers['Authorization'] = "Bearer $bearer" }
    $bUser = $controls.BasicUserBox.Text
    $bPass = $controls.BasicPassBox.Password
    if ($bUser -or $bPass) {
        $pair = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$($bUser):$($bPass)"))
        $headers['Authorization'] = "Basic $pair"
    }
    $ignoreCert = [bool]$controls.IgnoreCertChk.IsChecked

    $controls.AnalyzeBtn.IsEnabled = $false
    $controls.AnalyzeBtn.Content = 'Analyzing…'

    $ps = [PowerShell]::Create()
    $ps.AddScript($DiagBlock.ToString()) | Out-Null
    $ps.AddParameters(@{
        Url = $rawUrl
        Method = $method
        TimeoutSec = $timeoutSec
        Headers = $headers
        IgnoreCertErrors = $ignoreCert
    }) | Out-Null

    $script:CurrentPs = $ps
    $script:CurrentAsync = $ps.BeginInvoke()
    $script:PollTimer.Start()

    Save-RecentUrl -Url $rawUrl
}

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
$controls.AnalyzeBtn.Add_Click({ Start-Analysis })
$controls.UrlBox.Add_KeyDown({
    param($sender,$e)
    if ($e.Key -eq 'Return') { Start-Analysis }
})
$controls.ResetBtn.Add_Click({
    $controls.UrlBox.Text = ''
    $controls.BasicUserBox.Text = ''
    $controls.BasicPassBox.Password = ''
    $controls.BearerBox.Text = ''
    $controls.HeadersBox.Text = ''
    $controls.IgnoreCertChk.IsChecked = $false
    $controls.TimeoutBox.Text = '8'
    $controls.MethodBox.SelectedIndex = 0
    $controls.ResultsPanel.Visibility = 'Collapsed'
})

# ---------------------------------------------------------------------------
# Show window
# ---------------------------------------------------------------------------
$window.ShowDialog() | Out-Null
