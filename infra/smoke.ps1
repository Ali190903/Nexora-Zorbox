$ErrorActionPreference = 'Stop'

function Wait-HttpOk {
  param(
    [string]$Url,
    [int]$TimeoutSec = 30
  )
  $stopAt = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $stopAt) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Method GET -Uri $Url -TimeoutSec 5
      if ($r.StatusCode -eq 200) { return $true }
    } catch {}
    Start-Sleep -Seconds 1
  }
  return $false
}

Write-Host '== Checking service health =='
if (-not (Wait-HttpOk 'http://localhost:8080/healthz' 60)) { throw 'orchestrator not healthy' }
if (-not (Wait-HttpOk 'http://localhost:8090/healthz' 60)) { throw 'reporter not healthy' }
if (-not (Wait-HttpOk 'http://localhost:8070/healthz' 60)) { throw 'ti-enrichment not healthy' }
Write-Host 'Health OK'

Write-Host '== Hitting metrics endpoints =='
Invoke-WebRequest -UseBasicParsing http://localhost:8080/metrics | Out-Null
Invoke-WebRequest -UseBasicParsing http://localhost:8090/metrics | Out-Null
Invoke-WebRequest -UseBasicParsing http://localhost:8070/metrics | Out-Null
Write-Host 'Metrics OK'

# Use curl for proper multipart file upload on Windows
Write-Host '== Submitting analyze job =='
$sample = Join-Path $PSScriptRoot 'sample.bin'
Set-Content -NoNewline -Path $sample -Value ([System.Text.Encoding]::UTF8.GetBytes('hello zorbox'))
$curlOut = & curl -s -X POST -F "file=@`"$sample`"" http://localhost:8080/analyze
try { $resp = $curlOut | ConvertFrom-Json } catch { throw "invalid JSON from analyze: $curlOut" }
if (-not $resp.job_id) { throw 'analyze did not return job_id' }
Write-Host ('Job ID: ' + $resp.job_id)

Write-Host '== Polling result =='
$jid = $resp.job_id
for ($i=0; $i -lt 30; $i++) {
  $r = Invoke-RestMethod -Method Get -Uri ("http://localhost:8080/result/"+$jid)
  if ($r.state -eq 'done' -or $r.state -eq 'failed') { $res=$r; break }
  Start-Sleep -Seconds 1
}
if (-not $res) { throw 'result did not complete in time' }
Write-Host ('Final state: ' + $res.state)
if ($res.export) {
  Write-Host ('Exports: ' + ($res.export | ConvertTo-Json -Compress))
  if ($res.export.pdf_url) {
    $pdfUrl = 'http://localhost:8090' + $res.export.pdf_url
    Write-Host ('Fetching PDF: ' + $pdfUrl)
    Invoke-WebRequest -UseBasicParsing $pdfUrl | Out-Null
  }
}

Write-Host '== Reporter direct test =='
$payload = @{ id = 't1'; score = @{ total = 42; rules = @() }; ti = @{ domains = @(); ips = @() } } | ConvertTo-Json -Depth 5
$rr = Invoke-RestMethod -Method Post -Uri 'http://localhost:8090/report' -Body $payload -ContentType 'application/json'
if (-not $rr.pdf_url) { throw 'reporter did not return pdf_url' }
Write-Host ('Reporter URLs: ' + ($rr | ConvertTo-Json -Compress))

Write-Host '== TI enrichment test =='
$tiBody = @{ domains = @('evil.example'); ips = @('1.2.3.4'); hashes = @() } | ConvertTo-Json
$tiResp = Invoke-RestMethod -Method Post -Uri 'http://localhost:8070/enrich' -Body $tiBody -ContentType 'application/json'
if (-not $tiResp.reputation) { throw 'ti enrichment failed' }
Write-Host ('TI reputation sample: ' + ($tiResp.reputation | ConvertTo-Json -Compress))

Write-Host 'All checks passed.' -ForegroundColor Green
