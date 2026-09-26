# AuthTwin ingest lab smoke — file import only, no AuthTwin run/replay.
$ErrorActionPreference = "Stop"
$base = "http://127.0.0.1:8000"
$sample = Join-Path (Split-Path $PSScriptRoot -Parent) "sample_data\sample_authtwin_findings.json"
if (-not (Test-Path $sample)) { throw "missing sample: $sample" }

$health = Invoke-RestMethod -Uri "$base/api/health" -Method Get
Write-Host "health=$($health | ConvertTo-Json -Compress)"

$eng = Invoke-RestMethod -Uri "$base/api/engagements" -Method Post -ContentType "application/json" -Body '{"name":"AuthTwin Smoke","client":"Lab"}'
$eid = $eng.id
Write-Host "engagement_id=$eid"

$form = @{
  engagement_id = $eid
  tool = "authtwin"
  file = Get-Item -LiteralPath $sample
}
# Use curl.exe for reliable multipart on Windows
$curlOut = & curl.exe -s -X POST "$base/api/imports" -F "engagement_id=$eid" -F "tool=authtwin" -F "file=@$sample"
Write-Host "import_raw=$curlOut"
$imp = $curlOut | ConvertFrom-Json
$n = [int]$imp.observations_created
Write-Host "observations_created=$n"

# List finding groups for engagement if endpoint exists
$groups = $null
try {
  $groups = Invoke-RestMethod -Uri "$base/api/finding-groups?engagement_id=$eid" -Method Get
} catch {
  try { $groups = Invoke-RestMethod -Uri "$base/api/engagements/$eid/finding-groups" -Method Get } catch { $groups = $null }
}
if ($groups) {
  Write-Host "finding_groups_count=$($groups.Count)"
  $groups | ForEach-Object { Write-Host ("group id=$($_.id) key=$($_.group_key) obs=$($_.observation_count) title=$($_.title)") }
}

if ($n -eq 3) {
  Write-Host "PASS AuthTwin import smoke: engagement=$eid observations=3"
  exit 0
} else {
  Write-Host "FAIL expected 3 observations got $n"
  exit 1
}
