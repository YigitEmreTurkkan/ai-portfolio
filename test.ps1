$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = 'Test'
try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:8788/api/chat' `
        -Method 'POST' `
        -ContentType 'application/json' `
        -Body '{"message":"hi"}'
    Write-Output "Status code: $($r.StatusCode)"
    Write-Output "Content: $($r.Content)"
} catch {
    Write-Output "Error: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        Write-Output "Response body: $($reader.ReadToEnd())"
    }
}
