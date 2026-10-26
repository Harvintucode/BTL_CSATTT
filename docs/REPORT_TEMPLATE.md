# Báo cáo kỹ thuật — NovaBank Mini Cyber Range

## 1. Mục tiêu và phạm vi
Xây dựng ví điện tử giả lập để thực hành chu trình V1 (vulnerable) → attack → defense → V2 (fixed) → re-test. Chỉ dùng localhost/Docker network được nhóm sở hữu; dữ liệu và tài khoản là giả lập. Không tích hợp ngân hàng thật.

## 2. Kiến trúc
Browser HTML/CSS/JS → Nginx reverse proxy → Spring Boot REST API (Controller/Service/Repository) → MySQL trong Docker internal network. JWT xác thực stateless; BCrypt băm mật khẩu; endpoint admin dùng role ADMIN; các truy vấn dữ liệu ràng buộc user ID lấy từ JWT.

Sơ đồ: xem `architecture.mmd`.

## 3. Kịch bản kiểm thử
Mỗi kịch bản cần lưu: ngày giờ, commit V1/V2, lệnh/request, HTTP status, ảnh chụp bằng chứng, kết quả kỳ vọng/thực tế, biện pháp khắc phục.

### 3.1 Recon + Port Scan
- V1: chạy thêm `docker-compose.v1-exposed.yml` để publish MySQL/backend trên loopback.
- V2: chỉ publish Nginx trên loopback; backend và DB không publish port.
- Đo: số cổng host được công bố; kiểm tra cấu hình Docker network.
- Lưu ý: chỉ scan IP/port của lab được phép.

### 3.2 Expose port/service
- V1: `docker-compose.v1-exposed.yml` publish `127.0.0.1:3306` (DB) và `127.0.0.1:8081` (backend).
- V2: loại bỏ `ports` khỏi DB/backend và dùng `private` internal network.
- Đo: cổng DB/backend truy cập được từ host; kỳ vọng không có mapping.

### 3.3 Brute-force login
- V1 (`LAB_MODE=vulnerable`): không áp ngưỡng chặn theo username.
- V2 (`LAB_MODE=fixed`): sau 5 lần sai trả 429 và ghi `BRUTE_FORCE_BLOCK`.
- Đo: số request sai trước khi bị chặn; status code; sự kiện bảo mật.
- Hạn chế: counter trong bộ nhớ, reset khi container restart; production cần rate limit phân tán và IP/device controls.

### 3.4 SQL Injection
- V1: endpoint lab nối chuỗi input vào SQL.
- V2: prepared statement với placeholder.
- Chỉ gửi payload kiểm thử vô hại tới localhost lab, không dùng với hệ thống bên ngoài.
- Đo: kết quả truy vấn và event log; xác nhận V2 không thay đổi cấu trúc truy vấn.

### 3.5 IDOR / Broken Access Control
- V1: đọc wallet theo ID không kiểm tra owner.
- V2: truy vấn yêu cầu cả wallet ID và owner ID lấy từ JWT; truy cập chéo trả 403.
- Đo: token người dùng A yêu cầu wallet B; kết quả kỳ vọng V2 là 403.
- Không dùng header tự khai để thay thế danh tính đã xác thực.

### 3.6 HTTP sniffing
- V1: HTTP plaintext chỉ trong loopback lab, dùng dữ liệu giả.
- V2: bật TLS ở reverse proxy trước mọi môi trường không phải local; kiểm tra certificate và redirect HTTPS.
- Đo: so sánh payload capture trong lab; không thu thập traffic của người khác.
- Ghi rõ trong bản hiện tại reverse proxy local vẫn dùng HTTP; đây là phần mô phỏng/thiết kế phòng thủ, chưa phải HTTPS production.

## 4. Phân tích kết quả V1/V2
| Chỉ số | V1 | V2 | Bằng chứng |
|---|---|---|---|
| Port/service publish | Ghi số đo thực tế | Chỉ Nginx loopback | docker compose ps |
| Login sai | Không giới hạn trong lab | 429 sau ngưỡng | HTTP response |
| SQLi | Kiểm tra hành vi lab | Tham số hóa | response + source |
| IDOR | Có thể đọc chéo | 403 | response |
| Plaintext | HTTP local demo | TLS cần triển khai trước public | capture lab |
| Detection | Log sự kiện cơ bản | Login failure / access violation | admin events |

Không điền số liệu chưa đo; chạy kiểm thử và điền kết quả thực tế.

## 5. Hạn chế và hướng phát triển
- Ví và chuyển tiền là mô phỏng: endpoint chỉ tạo bản ghi, không thay đổi số dư và không kết nối payment rail.
- Brute-force counter hiện trong bộ nhớ.
- HTTP sniffing chưa được bảo vệ bằng TLS trong cấu hình local.
- Bổ sung rate limiting theo IP, audit log tập trung, test tích hợp, HTTPS, quản lý secret, idempotency và transaction trước khi mở rộng.
- Không triển khai mode vulnerable ngoài lab.
