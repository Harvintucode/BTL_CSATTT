# NovaBank Mini Cyber Range — Docker Compose

Backend được tổ chức theo Controller → Service → Repository, tích hợp frontend HTML/JS đã cung cấp, JWT authentication, BCrypt password hashing, role-based access cho admin, MySQL private network, event log và kịch bản V1/V2.

> Chỉ dành cho môi trường lab localhost. Không dùng dữ liệu thật, không publish backend/database, không chạy chế độ vulnerable trên mạng công cộng. Chuyển tiền chỉ ghi bản ghi mô phỏng, không thay đổi số dư và không chuyển tiền thật.

## 1. Yêu cầu
- Docker Desktop đang chạy
- Docker Compose v2
- Cổng `8080` chưa bị chiếm

## 2. Khởi động tất cả bằng Docker Compose
Tại thư mục gốc dự án:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

Mở `http://localhost:8080/` để vào trang đăng nhập. Health check: `http://localhost:8080/api/health`.

Tài khoản demo:
- `huy / 123456` — CUSTOMER
- `bob / 123456` — CUSTOMER
- `admin / admin123` — ADMIN

Tài khoản demo được seed khi backend khởi động. Mật khẩu được lưu dưới dạng BCrypt hash.

## 3. Chạy V1/V2
Mặc định `.env` dùng `LAB_MODE=fixed`.

Để demo V1, sửa `.env` thành `LAB_MODE=vulnerable`, sau đó:

```powershell
docker compose up --build -d backend
docker compose logs -f backend
```

Để quay về V2, đổi thành `LAB_MODE=fixed` và chạy lại lệnh trên. Chỉ chạy mode vulnerable khi lab cô lập, có sự cho phép và dùng dữ liệu giả.

`LAB_MODE` chỉ đổi hành vi ứng dụng (brute force, SQLi, IDOR). Hai kịch bản **Recon/Port scan** và **Expose service** cần cấu hình cổng, nên có file override riêng — chỉ bind vào `127.0.0.1`:

```powershell
# V1: publish thêm MySQL (3306) và backend (8081) trên loopback để có thứ để quét
docker compose -f docker-compose.yml -f docker-compose.v1-exposed.yml up -d
docker compose ps

# Quay về V2 (chỉ nginx được publish)
docker compose -f docker-compose.yml up -d --force-recreate db backend
```

## 4. API contract
| Method | Path | Auth | Mô tả |
|---|---|---|---|
| GET | `/api/health` | Public | trạng thái/mode |
| POST | `/api/auth/login` | Public | trả JWT |
| GET | `/api/wallets` | Bearer | ví của user hiện tại |
| GET | `/api/wallets/{id}` | Bearer | chi tiết ví + kiểm tra ownership |
| GET | `/api/transfers` | Bearer | lịch sử của user hiện tại, gồm tiền ra (`direction=OUT`) và tiền vào (`direction=IN`) |
| POST | `/api/transfers` | Bearer | ghi bản ghi chuyển tiền mô phỏng (tối thiểu 1.000 VND, không vượt số dư, không chuyển cho chính mình) |
| GET | `/api/lab/scenarios` | Public | danh mục kịch bản |
| GET | `/api/lab/customer-search?q=...` | Public, lab only | so sánh SQLi V1/V2 |
| GET | `/api/admin/security-events` | ADMIN | xem sự kiện bảo mật |

## 5. Kiểm tra nhanh bằng PowerShell
```powershell
Invoke-RestMethod http://localhost:8080/api/health
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/auth/login -ContentType "application/json" -Body '{"username":"huy","password":"123456"}'
$token = $login.token
Invoke-RestMethod http://localhost:8080/api/wallets -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod http://localhost:8080/api/wallets/2 -Headers @{ Authorization = "Bearer $token" }
```

Trong mode fixed, wallet 2 thuộc Bob nên Huy phải nhận 403. Trong mode vulnerable, `GET /api/wallets/2` trả dữ liệu ví của Bob để minh họa IDOR.

Mọi lỗi API trả JSON `{"status":..., "error":"...", "message":"..."}`; thiếu/hết hạn token trả `401`, sai quyền trả `403`.

Admin events:
```powershell
$admin = Invoke-RestMethod -Method Post http://localhost:8080/api/auth/login -ContentType "application/json" -Body '{"username":"admin","password":"admin123"}'
Invoke-RestMethod http://localhost:8080/api/admin/security-events -Headers @{ Authorization = "Bearer $($admin.token)" }
```

## 6. Chạy test
Docker build chỉ compile (`-DskipTests`). Unit test (JWT, brute-force, IDOR, validate chuyển tiền) chạy tại máy cần JDK 21 + Maven:
```powershell
cd backend
mvn test
```
Hoặc thêm service `test`/CI pipeline nếu nhóm muốn chạy test hoàn toàn trong Docker.

Smoke test end-to-end (cần stack đang chạy):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-tests.ps1
```

## 7. Dọn lab
```powershell
docker compose down
```
Xóa cả dữ liệu MySQL demo:
```powershell
docker compose down -v
```

## 8. Sơ đồ và báo cáo
- `docs/architecture.mmd`: sơ đồ Mermaid kiến trúc
- `docs/REPORT_TEMPLATE.md`: mẫu báo cáo V1/V2, metric, bằng chứng
- `security-lab/scenarios/scenarios.json`: catalog kịch bản

## 9. Ranh giới của prototype
- Mode V1 cố ý có nhánh SQLi/IDOR và bỏ ngưỡng brute force, chỉ dùng localhost.
- TLS chưa bật cho local Nginx; HTTP sniffing chỉ được mô tả là kịch bản lab. Cần terminate HTTPS và redirect trước bất kỳ triển khai nào khác local.
- Brute-force counter là in-memory; restart backend sẽ reset.
- JWT secret trong `.env.example` là secret demo, phải thay bằng secret ngẫu nhiên riêng nếu dùng trong lab nhiều người.
- CSRF không bật do API dùng Bearer token trong header và không dùng cookie auth.
- Khóa brute-force theo username (không theo IP) nên kẻ tấn công có thể cố tình khóa tài khoản người khác trong 60 giây; production cần thêm rate limit theo IP/thiết bị.
- Chuyển tiền không đổi số dư; chưa có nghiệp vụ tài chính thật, transaction ledger, idempotency hay reconciliation.
