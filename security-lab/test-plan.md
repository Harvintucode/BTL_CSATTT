# Test plan — localhost only

Run only against `http://localhost:8080`, using seeded synthetic users.

## Test 1: Recon / exposed ports
```powershell
docker compose ps
docker compose port db 3306
docker compose port backend 8080
```
Expected (V2): only frontend has a published host port; DB/backend produce no host port mapping.

V1 comparison (loopback only): start with `docker compose -f docker-compose.yml -f docker-compose.v1-exposed.yml up -d`; `docker compose port db 3306` now returns `127.0.0.1:3306` and `docker compose port backend 8080` returns `127.0.0.1:8081`. Record the difference, then return to V2 with `docker compose -f docker-compose.yml up -d --force-recreate db backend`.

## Test 2: Brute-force
Send six incorrect logins for a lab username in `LAB_MODE=fixed`; first five should be 401 and subsequent attempt 429 (subject to counter reset/restart). In vulnerable mode, repeated failures remain 401. Check `/api/admin/security-events` as admin for event records.

## Test 3: SQL injection regression
Request `GET /api/lab/customer-search?q=alice` and record the response in both modes. In fixed mode the input is always a bound parameter and cannot change SQL syntax. Only use safe test strings on this local endpoint.

## Test 4: IDOR
Login as huy and get token. Request `/api/wallets/2`. Fixed mode: 403. Vulnerable mode: response exposes synthetic Bob wallet and records an event. Do not use real account data.

## Test 5: HTTP sniffing
Only in a controlled local lab, capture a request to localhost using synthetic credentials/data and document that HTTP is plaintext. The current Compose config is intentionally local HTTP; do not claim TLS is implemented. The hardened deployment target must terminate TLS at reverse proxy and redirect HTTP to HTTPS.

## Test 6: service exposure
Inspect Compose port mappings and Docker networks (`docker compose config`, `docker network inspect`). In V2 the MySQL service has no `ports` and is only attached to the internal `private` network; the backend has no host port mapping. The V1 override (`docker-compose.v1-exposed.yml`) is the only file that adds them.
