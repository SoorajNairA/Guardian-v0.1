$tests = @(
    @{
        scenario = "Social Engineering Test"
        text = "This is Microsoft Support. We detected a virus. Call this number immediately: +1-555-SCAM"
    },
    @{
        scenario = "Phishing Test"
        text = "URGENT: Your account has been compromised. Click here to verify: secure-bank-verify.com"
    },
    @{
        scenario = "Financial Fraud Test"
        text = "Amazing deal! Genuine Rolex watches for just $50! DM me your credit card info to order: cheap-rolexes.net"
    },
    @{
        scenario = "Malware Test"
        text = "Download this file to speed up your computer: virus.exe; rm -rf /*; DROP TABLE users;"
    },
    @{
        scenario = "Crypto Scam Test"
        text = "1000% GUARANTEED RETURNS! Send your crypto to this wallet: 0x1234...; You'll get 10x back instantly!"
    }
)

foreach ($test in $tests) {
    Write-Host "`n`nTesting: $($test.scenario)" -ForegroundColor Cyan
    Write-Host "Text: $($test.text)" -ForegroundColor Yellow
    Write-Host "-----------------------------------------"

    $body = @{
        text = $test.text
        config = @{ compliance_mode = "strict" }
    } | ConvertTo-Json

    try {
        $result = Invoke-RestMethod `
            -Uri "http://localhost:8000/v1/analyze" `
            -Method Post `
            -Body $body `
            -ContentType "application/json" `
            -Headers @{"X-API-Key" = "WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE"}

        Write-Host "Risk Score: $($result.risk_score)" -ForegroundColor Green
        Write-Host "`nThreats Detected:" -ForegroundColor Magenta
        if ($result.threats_detected.Count -gt 0) {
            $result.threats_detected | ForEach-Object {
                Write-Host "- $($_.category) (Confidence: $($_.confidence_score))" -ForegroundColor Red
            }
        } else {
            Write-Host "No threats detected" -ForegroundColor Gray
        }
        
        Write-Host "`nMetadata:" -ForegroundColor Blue
        $result.metadata | ConvertTo-Json
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        if ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            Write-Host "Response Body: $errorBody" -ForegroundColor Red
            $reader.Close()
        }
    }
    Write-Host "-----------------------------------------"
    Start-Sleep -Seconds 2
}
