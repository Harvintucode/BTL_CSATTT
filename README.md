# PTIT eMB – Mini Web Bank (OWASP A01:2025 Broken Access Control)

Web ngân hàng số mini dùng để **minh họa cách phòng chống** lỗi kiểm soát truy cập (Broken Access Control) theo 5 case CWE, kèm nghiệp vụ ngân hàng cơ bản, bộ test tự động, rule SAST và hướng dẫn deploy online.

## Giao diện và nghiệp vụ

- **Trang công khai:** top bar phân khúc (Cá nhân / Doanh nghiệp / Cao cấp), khung đăng nhập nổi trên banner, thanh dịch vụ nhanh (bấm vào hiện thông báo "Hệ thống đang hoàn thiện tính năng này"), bảng lãi suất và tỷ giá (số liệu minh họa).
- **Cổng eBanking:** sidebar dọc theo vai trò, màu theo vai trò (khách hàng: xanh dương nhạt; giao dịch viên: xanh đậm; admin: xám – đen).
- **Khách hàng (USER):** xem số dư, chuyển tiền 24/7 (có bước xác nhận và biên lai), lịch sử giao dịch, xuất sao kê `.csv`, đăng ký vay, cập nhật hồ sơ, kiểm tra webhook.
- **Giao dịch viên (TELLER):** tra cứu khách hàng (chỉ đọc), duyệt/từ chối khoản vay **≤ 100.000.000 ₫**. Không chuyển tiền hộ khách (tách nhiệm vụ), không xem nhật ký kiểm toán.
- **Admin (Giám đốc chi nhánh):** duyệt mọi khoản vay (kể cả VIP), xem nhật ký kiểm toán, phân quyền người dùng. Không có chức năng sửa số dư trực tiếp.

## 5 case CWE được xử lý

| Case | CWE | Nội dung | Biện pháp trong code |
|---|---|---|---|
| 1 | CWE-639 | IDOR / BOLA + HTTP Parameter Pollution | Kiểm tra quyền sở hữu tài khoản, ép `accountId` là chuỗi 4 số (chặn mảng HPP) |
| 2 | CWE-285 / 862 | BFLA, Verb Tampering, header giả vai trò | `onlyMethods('POST')` + `requireRole`, role lấy từ DB, bỏ qua `X-Forwarded-Role`, Teller bị giới hạn hạn mức duyệt |
| 3 | CWE-915 | Mass Assignment / BOPLA | Allowlist DTO: chỉ nhận `fullName`, `phone`, `email` (có kiểm tra định dạng), ghi nhật ký khi gửi trường cấm |
| 4 | CWE-22 | Path Traversal | Không dùng input làm đường dẫn; tra file theo chủ sở hữu, `path.basename`, kiểm tra tiền tố thư mục |
| 5 | CWE-918 | SSRF | Chỉ http/https, phân giải DNS, chặn loopback/RFC1918/link-local/IPv6 (kể cả dạng IPv4-mapped); chỉ xác thực URL, không gọi ra ngoài |

Bảo mật bổ sung: chuyển tiền chỉ trích từ tài khoản của phiên đăng nhập, kiểm tra số tiền nguyên dương và hạn mức, sao kê CSV chống formula injection, giao diện escape toàn bộ dữ liệu động (chống XSS), mật khẩu băm `scrypt`, JWT HS256 cố định thuật toán (chặn `alg=none`), giới hạn đăng nhập sai, security headers, nhật ký các truy cập bị từ chối.

## Phân quyền (RBAC)

Hệ thống có 3 vai trò. Mọi quyết định phân quyền được thực hiện **ở máy chủ**, dựa trên vai trò lưu trong CSDL của phiên đăng nhập, không tin vào `role` trong token, header (`X-Forwarded-Role`) hay body do client gửi.

| Chức năng (API) | Chưa đăng nhập | USER | TELLER | ADMIN |
|---|:-:|:-:|:-:|:-:|
| Xem số dư và lịch sử giao dịch (`GET /api/accounts/detail`) | 401 | Chỉ TK của mình | Mọi TK (chỉ đọc) | Mọi TK (chỉ đọc) |
| Tra cứu danh sách khách hàng (`GET /api/staff/customers`) | 401 | 403 | Có | Có |
| Chuyển tiền (`POST /api/transactions/transfer`) | 401 | Có, chỉ từ TK của mình | 403 (tách nhiệm vụ) | 403 (tách nhiệm vụ) |
| Xuất sao kê CSV (`GET /api/statements/download`) | 401 | Chỉ sao kê của mình | Không áp dụng | Không áp dụng |
| Xem khoản vay (`GET /api/loans`) | 401 | Chỉ khoản vay của mình | Tất cả | Tất cả |
| Đăng ký vay (`POST /api/loans/apply`) | 401 | Có | 403 | 403 |
| Duyệt / từ chối vay (`POST /api/admin/approve-loan`) | 401 | 403 | Khoản vay ≤ 100.000.000 ₫ | Mọi khoản vay, gồm VIP |
| Cập nhật hồ sơ: họ tên, SĐT, email (`PUT /api/profile/update`) | 401 | Có | Có | Có |
| Kiểm tra webhook (`POST /api/webhooks/test`) | 401 | Có | Có | Có |
| Nhật ký kiểm toán (`GET /api/admin/audit`) | 401 | 403 | 403 | Có |
| Danh sách người dùng, đổi vai trò (`/api/admin/users`) | 401 | 403 | 403 | Có (không tự đổi quyền của mình) |
| Sửa trực tiếp số dư, vai trò, hạn mức qua hồ sơ | Không có chức năng này ở bất kỳ vai trò nào | | | |

Nguyên tắc áp dụng:

1. **Từ chối theo mặc định:** mọi route nghiệp vụ đều qua `authenticate`, route nhạy cảm qua thêm `requireRole(...)`.
2. **Kiểm tra quyền sở hữu (ownership):** USER chỉ truy cập dữ liệu có `accountId` trùng với tài khoản của phiên.
3. **Tách nhiệm vụ (SoD):** nhân viên ngân hàng không được lập lệnh chuyển tiền hộ khách.
4. **Phân cấp thẩm quyền:** Teller bị giới hạn hạn mức duyệt vay, vượt hạn mức trả về 403 và ghi nhật ký `DENY_LIMIT`.
5. **Khóa phương thức HTTP:** `approve-loan` chỉ nhận `POST`, các method khác trả 405.
6. **Allowlist đầu vào:** hồ sơ chỉ nhận 3 trường cho phép, các trường như `role`, `balance`, `creditLimit`, `tier` bị bỏ qua và ghi nhật ký.

Mã trả về khi bị từ chối: `401` chưa đăng nhập hoặc token sai, `403` không đủ quyền, `405` sai method, `400` dữ liệu không hợp lệ.

## 1. Cấu trúc thư mục

```
mini-web-bank/
├── package.json
├── server.js                  # Backend API + CSDL in-memory + toàn bộ biện pháp phòng thủ
├── public/index.html          # Trang công khai + cổng eBanking 3 vai trò (không chứa công cụ kiểm thử)
├── test/access-control.test.js# Test tự động (node:test), tự bật server, không cần chạy riêng
├── security-lab/run.js        # Security Lab: kiểm thử phân quyền từ bên ngoài qua HTTP
├── semgrep-bac.yaml           # Rule SAST phát hiện thiếu phân quyền
├── render.yaml                # Cấu hình deploy Render
├── .env.example
└── README.md
```

## 2. Chạy local

Yêu cầu Node.js >= 18.

```bash
cd mini-web-bank
npm install
npm start            # mở http://localhost:3000
```

### Tài khoản demo

Trang chủ không hiển thị tài khoản mẫu. Dùng các tài khoản sau để đăng nhập (mật khẩu chung `Bank@2025`):

| Tên đăng nhập | Vai trò | Số tài khoản | Ghi chú | Màu giao diện |
|---|---|---|---|---|
| `userA` | Khách hàng (USER) | 1001 | Cá nhân tiêu chuẩn, có hồ sơ vay #101 (45 triệu) | Xanh dương nhạt |
| `userB` | Khách hàng (USER) | 1002 | Khách VIP, có hồ sơ vay #102 (350 triệu) | Xanh dương nhạt |
| `teller1` | Giao dịch viên (TELLER) | 9001 | Duyệt vay đến 100 triệu | Xanh đậm |
| `admin` | Giám đốc chi nhánh (ADMIN) | 9999 | Toàn quyền quản trị, không sửa được số dư | Xám – đen |

Dữ liệu nằm trong bộ nhớ và được khởi tạo lại mỗi lần chạy `npm start`. Đây là tài khoản giả lập cho mục đích học tập, hãy đổi mật khẩu hoặc bỏ chúng nếu đưa vào môi trường thật.

## 3. Chạy kiểm thử

### 3.1 Test tự động
```bash
npm test
```
Kết quả mong đợi: **22 test pass**, gồm xác thực/JWT giả, IDOR, HPP, BFLA (POST/PUT/GET/DELETE/PATCH + header giả), Mass Assignment, Path Traversal, SSRF (13 biến thể URL), chuyển tiền (SoD, trích tiền từ TK người khác, dữ liệu xấu), hạn mức duyệt của Teller, sao kê CSV, nhật ký an ninh. Mỗi test khẳng định hành vi trái phép bị chặn **và** hành vi hợp lệ vẫn chạy.

### 3.2 Kiểm thử trên giao diện
1. `userA` → **Chuyển tiền 24/7**: chuyển 500.000 ₫ sang TK `1002`, xác nhận, nhận biên lai; vào **Lịch sử & Sao kê** thấy giao dịch mới và tải được file `.csv`.
2. Chạy **Security Lab** (mục 3.2b) và đối chiếu kết quả với giao diện, ví dụ sau khi lab chạy, đăng nhập `admin` → **Nhật ký kiểm toán** sẽ thấy các sự kiện bị chặn.
3. `teller1` → **Phê duyệt tín dụng**: duyệt hồ sơ #101 (45 triệu) thành công; duyệt #102 (350 triệu, VIP) bị chặn "Vượt thẩm quyền".
4. `admin` → duyệt #102 thành công; **Nhật ký kiểm toán** thấy các sự kiện bị chặn của `userA` và `teller1`; **Phân quyền người dùng** đổi được vai trò người khác.
5. `teller1` thử gọi API chuyển tiền (Burp/DevTools) nhận 403 do tách nhiệm vụ.

### 3.2b Security Lab (chạy ngoài, không tích hợp vào web)

Security Lab là một script độc lập, kiểm thử kiểu black-box qua HTTP nên không nằm trong giao diện web và có thể chạy với bản local hoặc bản đã deploy. Script tự đăng nhập 4 tài khoản demo, gửi các request trái phép và kỳ vọng máy chủ **chặn hoặc vô hiệu hóa** chúng.

```bash
npm start                                   # cửa sổ 1: bật server
npm run seclab                              # cửa sổ 2: chạy lab (mặc định http://localhost:3000)

# Nhắm vào bản đã deploy
BASE_URL=https://ten-ban.onrender.com npm run seclab

# Chỉ chạy một nhóm ca (lọc theo từ khóa trong tên/CWE)
ONLY=ssrf,path npm run seclab

# Đổi mật khẩu demo nếu bạn đã đổi, tắt màu khi ghi log/CI
LAB_PASSWORD=... NO_COLOR=1 npm run seclab
```

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `BASE_URL` | `http://localhost:3000` | Địa chỉ hệ thống cần kiểm thử |
| `LAB_PASSWORD` | `Bank@2025` | Mật khẩu của các tài khoản demo |
| `ONLY` | (tất cả) | Danh sách từ khóa, phân tách bằng dấu phẩy |
| `NO_COLOR` | (bật màu) | Đặt bất kỳ giá trị nào để tắt màu |

Các ca kiểm thử (15 ca): IDOR, HPP, trích tiền từ tài khoản người khác, BFLA (PUT/GET/DELETE/PATCH và header `X-Forwarded-Role` giả), khách hàng gọi API quản trị/nhân viên, tự đổi vai trò, tách nhiệm vụ (Teller/Admin chuyển tiền), Teller duyệt vay vượt hạn mức, Mass Assignment, Path Traversal, SSRF (13 biến thể), token giả/không token, dữ liệu chuyển tiền bất thường.

Kết quả mỗi ca là `PASS` (đã chặn), `FAIL` (bị rò rỉ) hoặc `SKIP` (không đủ điều kiện, ví dụ khoản vay VIP đã được duyệt trước đó). Mã thoát: `0` mọi ca đạt, `1` có ca rò rỉ, `2` không kết nối được hoặc không đăng nhập được. Nhờ mã thoát này có thể đưa vào CI.

Lưu ý: ca "Teller duyệt khoản vay > 100 triệu" cần khoản vay #102 còn ở trạng thái chờ duyệt. Sau khi Admin duyệt #102, ca này sẽ `SKIP` cho đến khi khởi động lại server (dữ liệu in-memory được khởi tạo lại).

Phân biệt hai bộ kiểm thử: `npm test` kiểm thử mã nguồn trong tiến trình (nhanh, chạy được khi chưa deploy); `npm run seclab` kiểm thử hệ thống đang chạy từ bên ngoài, phù hợp để chứng minh trên bản đã deploy.

### 3.3 Quét SAST bằng Semgrep
```bash
pip install semgrep
semgrep --config semgrep-bac.yaml server.js
```
Rule phát hiện: `Object.assign(x, req.body)`, đường dẫn dựng từ `req.query`, gọi URL từ `req.body`, phân quyền dựa trên dữ liệu client, route `/api/admin` thiếu middleware.

### 3.4 Kiểm thử thủ công với Burp Suite / Autorize
1. Bắt traffic của trình duyệt qua Burp (proxy 8080).
2. Cài extension **Autorize**, dán JWT của `userA` vào ô Cookie/Header thấp quyền.
3. Duyệt web bằng tài khoản `admin`/`teller1`; Autorize tự phát lại request bằng quyền `userA`.
4. Mọi endpoint quản trị phải hiện **Enforced** (403/405).

## 4. Deploy online

### Render (miễn phí)
1. Đẩy thư mục lên GitHub.
2. Render → **New + → Blueprint** → chọn repo. File `render.yaml` tự tạo service và sinh `JWT_SECRET`.
3. Sau khi build, truy cập URL `https://<tên>.onrender.com`.

### Railway / Fly / VPS
- Build: `npm install`, Start: `npm start`.
- Đặt biến môi trường `JWT_SECRET` (chuỗi ngẫu nhiên dài). Ứng dụng đọc `PORT` từ môi trường.

Lưu ý khi host công khai:
- CSDL là **in-memory**, dữ liệu reset mỗi lần khởi động lại, phù hợp demo.
- Tài khoản demo trong README dùng mật khẩu công khai; chỉ đưa dữ liệu giả lên bản demo.
- Gói miễn phí có thể "ngủ" sau một thời gian không truy cập, lần mở đầu tiên sẽ chậm.

## 5. Gợi ý trình bày với thầy
1. Giới thiệu A01:2025 và 5 case CWE (bảng ở đầu file).
2. Chạy `npm run seclab` ở cửa sổ riêng: từng request trái phép bị chặn, kèm mã HTTP.
3. Mở **Nhật ký an ninh** (admin) để cho thấy khả năng phát hiện và truy vết.
4. Chạy `npm test` và `semgrep` để chứng minh kiểm thử tự động và SAST.
5. Giải thích phần sửa lỗi bắt được trong lúc làm: biến thể SSRF `::ffff:7f00:1` (Node chuẩn hóa IPv4-mapped sang dạng hex) từng lọt qua bộ lọc, đã được test phát hiện và vá.

## 6. Tương đương Java Spring Boot (cho báo cáo)

```java
@GetMapping("/accounts/{accountId}")
@PreAuthorize("@ownershipService.isOwner(authentication, #accountId) or hasAnyRole('TELLER','ADMIN')")
public ResponseEntity<Account> getAccount(@PathVariable String accountId) { ... }

@PostMapping("/admin/approve-loan")                    // khóa method
@PreAuthorize("hasAnyRole('ADMIN','TELLER')")          // khóa role
public ResponseEntity<String> approveLoan(@RequestParam Long loanId) { ... }

public record UpdateProfileDTO(String fullName) {}     // DTO không có role/balance
@PutMapping("/profile/update")
public ResponseEntity<User> update(@RequestBody UpdateProfileDTO dto, Authentication auth) { ... }
```
