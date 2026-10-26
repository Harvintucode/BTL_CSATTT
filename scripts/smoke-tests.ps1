# Run from the project root after `docker compose up --build -d`.
# Only targets localhost:8080 and synthetic seeded records.
$ErrorActionPreference = "Stop"
$base = "http://localhost:8080"
$pass = 0
$fail = 0
function Check($name, [scriptblock]$test) {
  try { & $test; Write-Host "[PASS] $name" -ForegroundColor Green; $script:pass++ }
  catch { Write-Host "[FAIL] $name :: $($_.Exception.Message)" -ForegroundColor Red; $script:fail++ }
}
function Login($user, $password) {
  Invoke-RestMethod -Method Post "$base/api/auth/login" -ContentType "application/json" -Body (@{username=$user;password=$password} | ConvertTo-Json)
}
function StatusCode($action) {
  try { & $action | Out-Null; return 200 }
  catch { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }; throw }
}

Check "1. Only frontend port published; DB/backend private" {
  # Use the resolved Compose model instead of regex-matching YAML text.
  $cfg = docker compose config --format json | ConvertFrom-Json
  foreach ($svc in @("db","backend")) {
    $ports = $cfg.services.$svc.ports
    if ($ports -and @($ports).Count -gt 0) { throw "$svc should not publish ports (found $(@($ports).Count))" }
  }
  if (-not $cfg.services.frontend.ports) { throw "frontend should publish the web port" }
  $health = Invoke-RestMethod "$base/api/health"
  if ($health.status -ne "UP") { throw "Health endpoint is not UP" }
}
Check "2. Login returns bearer token and role" {
  $r = Login "huy" "123456"
  if (-not $r.token -or $r.user.role -ne "CUSTOMER") { throw "Expected token and CUSTOMER role" }
  $script:token = $r.token
}
Check "3. CUSTOMER cannot access admin security events" {
  $status = StatusCode { Invoke-RestMethod "$base/api/admin/security-events" -Headers @{Authorization="Bearer $script:token"} }
  if ($status -ne 403) { throw "Expected 403 for CUSTOMER role, got $status" }
}
Check "3b. Requests without a token get 401" {
  $status = StatusCode { Invoke-RestMethod "$base/api/wallets" }
  if ($status -ne 401) { throw "Expected 401 without token, got $status" }
}
Check "4. Brute-force defense returns 429 in fixed mode" {
  $mode = (Invoke-RestMethod "$base/api/health").mode
  if ($mode -ne "FIXED") { Write-Host "  Skipped assertion: LAB_MODE is $mode, expected fixed mode for this test." -ForegroundColor Yellow; return }
  $name = "no-such-user-smoke"
  1..5 | ForEach-Object { $null = StatusCode { Invoke-RestMethod -Method Post "$base/api/auth/login" -ContentType "application/json" -Body (@{username=$name;password="wrong"} | ConvertTo-Json) } }
  $status = StatusCode { Invoke-RestMethod -Method Post "$base/api/auth/login" -ContentType "application/json" -Body (@{username=$name;password="wrong"} | ConvertTo-Json) }
  if ($status -ne 429) { throw "Expected 429 after threshold, got $status" }
}
Check "5. SQL search endpoint responds in lab" {
  $r = Invoke-RestMethod "$base/api/lab/customer-search?q=huy"
  if ($null -eq $r) { throw "No response" }
  # For V2, parameter binding is asserted by code review + harmless regression query.
  $safe = Invoke-RestMethod "$base/api/lab/customer-search?q=%25"
  if ($null -eq $safe) { throw "Expected a valid JSON response" }
}
Check "6. IDOR: user Huy cannot read Bob's wallet in fixed mode" {
  $mode = (Invoke-RestMethod "$base/api/health").mode
  $status = StatusCode { Invoke-RestMethod "$base/api/wallets/2" -Headers @{Authorization="Bearer $script:token"} }
  if ($mode -eq "FIXED" -and $status -ne 403) { throw "Expected 403, got $status" }
  if ($mode -eq "VULNERABLE" -and $status -ne 200) { throw "Expected 200 in isolated vulnerable demo, got $status" }
}
Check "7. HTTP lab status and scenario catalog are available" {
  $scenarios = Invoke-RestMethod "$base/api/lab/scenarios"
  $required = @("RECON_PORT_SCAN","EXPOSED_SERVICE","BRUTE_FORCE","SQL_INJECTION","IDOR","HTTP_SNIFFING")
  $keys = @($scenarios | ForEach-Object { $_.scenario_key })
  foreach ($key in $required) { if ($key -notin $keys) { throw "Missing scenario $key" } }
  Write-Host "  Note: sniffing/TLS is a manual localhost-only demonstration; Compose currently uses HTTP and must not be exposed publicly." -ForegroundColor Yellow
}
Check "8. Transfer is recorded as simulated and appears in history" {
  $body = @{destinationAccount="190000009022";destinationName="Bob Nguyen";amount=1000;note="smoke test"} | ConvertTo-Json
  $r = Invoke-RestMethod -Method Post "$base/api/transfers" -Headers @{Authorization="Bearer $script:token"} -ContentType "application/json" -Body $body
  if ($r.status -ne "SIMULATED" -or -not $r.id) { throw "Expected SIMULATED transfer with id" }
  $history = @(Invoke-RestMethod "$base/api/transfers" -Headers @{Authorization="Bearer $script:token"})
  if (-not ($history | Where-Object { $_.id -eq $r.id })) { throw "New transfer id $($r.id) missing from history" }
}
Check "9. Invalid transfer is rejected with 400" {
  $body = @{destinationAccount="abc";destinationName="X";amount=1000} | ConvertTo-Json
  $status = StatusCode { Invoke-RestMethod -Method Post "$base/api/transfers" -Headers @{Authorization="Bearer $script:token"} -ContentType "application/json" -Body $body }
  if ($status -ne 400) { throw "Expected 400, got $status" }
}
Check "10. ADMIN can read security events" {
  $admin = Login "admin" "admin123"
  $events = Invoke-RestMethod "$base/api/admin/security-events" -Headers @{Authorization="Bearer $($admin.token)"}
  if ($null -eq $events) { throw "No response" }
}
Write-Host "`nSmoke test summary: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
