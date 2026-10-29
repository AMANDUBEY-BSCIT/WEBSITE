$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$cloudflared = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$pythonArguments = @()

if (-not (Test-Path -LiteralPath $cloudflared -PathType Leaf)) {
    Write-Host "Cloudflare Tunnel executable was not found at: $cloudflared" -ForegroundColor Red
    Write-Host "Install cloudflared or update the executable path in start_public.ps1."
    exit 1
}

if (Test-Path -LiteralPath $python -PathType Leaf) {
    $pythonArguments = @("app.py")
} else {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $python = $launcher.Source
    } else {
        $launcher = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $launcher) {
            Write-Host "Python was not found. Install Python 3.10 or newer and enable its PATH option." -ForegroundColor Red
            exit 1
        }
        $python = $launcher.Source
    }
    $pythonArguments = @("app.py")
}

Push-Location $projectRoot
try {
    & $python -c "import flask, dotenv, PIL"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Required Python packages are missing for the selected interpreter." -ForegroundColor Red
        if ($python -like "*\.venv\Scripts\python.exe") {
            Write-Host 'Install them with: .\.venv\Scripts\python.exe -m pip install -r requirements.txt'
        } else {
            Write-Host 'Install them with: py -m pip install -r requirements.txt'
        }
        exit 1
    }
} finally {
    Pop-Location
}

$listeners = @(Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue)
if ($listeners.Count -gt 0) {
    foreach ($listener in $listeners) {
        $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)"
        $isPython = $owner -and [System.IO.Path]::GetFileName($owner.ExecutablePath) -match '^pythonw?\.exe$'
        $runsApp = $owner -and $owner.CommandLine -match '(?i)(^|[\s""\\/])app\.py(["\s]|$)'

        if (-not ($isPython -and $runsApp)) {
            Write-Host "Port 5000 is already used by another process (PID $($listener.OwningProcess))." -ForegroundColor Red
            Write-Host "Stop that service or configure it to use another port before starting BookBridge."
            exit 1
        }
    }

    Write-Host "BookBridge's Python app.py is already listening on port 5000; reusing it." -ForegroundColor Cyan
} else {
    Write-Host "Starting BookBridge on port 5000 in a separate window..."
    try {
        $server = Start-Process -FilePath $python -ArgumentList $pythonArguments -WorkingDirectory $projectRoot -PassThru
    } catch {
        Write-Host "Could not start Flask: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $ready = $false
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($server.HasExited) {
            Write-Host "Flask exited during startup (exit code $($server.ExitCode)). Check the Flask window for the error." -ForegroundColor Red
            exit 1
        }

        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connection = $client.BeginConnect("127.0.0.1", 5000, $null, $null)
            if ($connection.AsyncWaitHandle.WaitOne(250, $false) -and $client.Connected) {
                $ready = $true
                break
            }
        } catch {
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 250
    }

    if (-not $ready) {
        Write-Host "Flask did not begin listening on port 5000 within 30 seconds." -ForegroundColor Red
        Write-Host "Check the Flask window for startup errors, missing packages, or a port conflict."
        exit 1
    }
    Write-Host "Flask is listening on port 5000." -ForegroundColor Green
}

Write-Host "`nStarting the temporary Cloudflare Tunnel. Keep this window open." -ForegroundColor Cyan
Write-Host "The public HTTPS address will appear below when Cloudflare creates it.`n"

$urlShown = $false
& $cloudflared tunnel --url http://localhost:5000 2>&1 | ForEach-Object {
    $line = "$_"
    if (-not $urlShown -and $line -match '(https://[a-zA-Z0-9-]+\.trycloudflare\.com)') {
        Write-Host "`nPUBLIC HTTPS URL: $($Matches[1])" -ForegroundColor Green
        Write-Host "Open this URL in mobile Chrome. Keep both Flask and this tunnel running.`n"
        $urlShown = $true
    }

    if ($line -match '(?i)\b(error|failed|failure)\b') {
        Write-Host $line -ForegroundColor Red
    } else {
        Write-Host $line
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "`nCloudflare Tunnel stopped with exit code $LASTEXITCODE." -ForegroundColor Red
    Write-Host "Check your internet connection, firewall/proxy settings, and cloudflared installation."
    exit $LASTEXITCODE
}
