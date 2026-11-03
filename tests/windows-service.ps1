# Disposable, synthetic Windows SCM integration check for hosted CI runners.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$backend = (Resolve-Path 'target/release/genyra-snitch.exe').Path
$data = Join-Path $env:RUNNER_TEMP ('genyra-service-' + [guid]::NewGuid())
if (Get-Service GenyraSnitch -ErrorAction SilentlyContinue) {
    throw 'Refusing to modify an existing GenyraSnitch service'
}
New-Item -ItemType Directory $data | Out-Null
try {
    & $backend service install --data-dir $data
    # CI has the SDK import libraries, not a live-capture driver. Only this
    # disposable registration gets --demo; production service setup does not.
    $line = '"' + $backend + '" --service-run --demo --data-dir "' + $data + '" --bind 127.0.0.1 --port 0 --no-browser'
    & sc.exe config GenyraSnitch 'binPath=' $line | Out-Null
    $previousToken = $null
    foreach ($round in 1..2) {
        & $backend service start --data-dir $data
        $ready = $false
        foreach ($attempt in 1..200) {
            if (Test-Path (Join-Path $data 'collector.json')) {
                $endpoint = Get-Content (Join-Path $data 'collector.json') -Raw | ConvertFrom-Json
                $token = (Get-Content (Join-Path $data 'api_token.txt') -Raw).Trim()
                try {
                    $diagnostics = Invoke-RestMethod ($endpoint.url + '/diagnostics') -Headers @{ 'X-Snitch-Token' = $token } -TimeoutSec 2
                    if ($diagnostics.product -eq 'Genyra Snitch' -and $diagnostics.capture.demo) {
                        $ready = $true
                        break
                    }
                } catch { }
            }
            Start-Sleep -Milliseconds 100
        }
        if (!$ready) { throw 'SCM collector did not become ready' }
        if ($previousToken -and $previousToken -ne $token) { throw 'Restart replaced the local identity' }
        $previousToken = $token
        $headers = @{ 'X-Snitch-Token' = $token }
        if ($round -eq 1) {
            Invoke-RestMethod ($endpoint.url + '/settings') -Method Post -Headers $headers -ContentType 'application/json' -Body '{"settings":{"retention_hours":73}}' | Out-Null
        } else {
            $settings = Invoke-RestMethod ($endpoint.url + '/settings') -Headers $headers
            if ($settings.settings.retention_hours -ne 73) { throw 'Service restart lost saved settings' }
        }
        & $backend service stop --data-dir $data
        foreach ($attempt in 1..200) {
            if ((Get-Service GenyraSnitch).Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 100
        }
        if ((Get-Service GenyraSnitch).Status -ne 'Stopped') { throw 'SCM stop did not finish' }
        if (Test-Path (Join-Path $data 'collector.json')) { throw 'Stopped service left a live endpoint' }
    }
    Write-Host 'Windows SCM start, stop, restart, identity and persistence checks passed (synthetic data).'
} finally {
    if (Get-Service GenyraSnitch -ErrorAction SilentlyContinue) {
        & $backend service uninstall --data-dir $data
    }
    Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue
}
