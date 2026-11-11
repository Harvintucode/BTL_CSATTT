# 🔴 Attack Demo & Mô hình Kiểm thử

Thư mục này chứa **bản demo tấn công** và **mô hình kiểm thử** để so sánh giữa hệ thống có lỗi và hệ thống đã phòng thủ.

## Cấu trúc

```
attack-demo/
├── server-vulnerable.js   # Server CÓ LỖI (cổng 3001) – 5 lỗ hổng CWE
├── attack-scenarios.js    # Kịch bản tấn công: khai thác từng lỗ hổng
├── test-model.js          # Mô hình kiểm thử: so sánh hai bản side-by-side
└── README.md              # Hướng dẫn này
```

## ⚠️ Cảnh báo

> **`server-vulnerable.js` CỐ Ý chứa lỗi bảo mật để phục vụ mục đích học tập.**
> KHÔNG triển khai ra môi trường thật hoặc mạng công khai.

## 5 lỗ hổng CWE được cài vào bản vulnerable

| Case | CWE | Lỗ hổng | Cách khai thác |
|---|---|---|---|
| 1 | CWE-639 | IDOR / BOLA | Đổi `accountId` trong URL → xem tài khoản người khác, trích tiền từ TK người khác |
| 2 | CWE-285/862 | BFLA | Gọi API admin bằng tài khoản thường, dùng sai method (PUT/GET/DELETE), giả header `X-Forwarded-Role` |
| 3 | CWE-915 | Mass Assignment | Gửi `role`, `balance`, `creditLimit` trong body cập nhật hồ sơ → tự nâng quyền ADMIN |
| 4 | CWE-22 | Path Traversal | Dùng `../` trong tham số `file` → đọc mã nguồn server, file cấu hình |
| 5 | CWE-918 | SSRF | Gửi URL trỏ về 127.0.0.1, IP nội bộ → server gọi request thay |

## Hướng dẫn chạy

### 1. Demo tấn công (attack scenarios)

```bash
# Cửa sổ 1: khởi động server có lỗi
node attack-demo/server-vulnerable.js

# Cửa sổ 2: chạy kịch bản tấn công
node attack-demo/attack-scenarios.js
```

Hoặc dùng script tích hợp:
```bash
npm run attack-demo
```

### 2. Mô hình kiểm thử so sánh (test model)

```bash
# Cửa sổ 1: server phòng thủ (cổng 3000)
npm start

# Cửa sổ 2: server có lỗi (cổng 3001)
node attack-demo/server-vulnerable.js

# Cửa sổ 3: chạy mô hình kiểm thử
node attack-demo/test-model.js
```

Hoặc dùng script tích hợp:
```bash
npm run test-model
```

### 3. Trình tự báo cáo đề xuất

1. **Bước 1:** Chạy `npm run attack-demo` → cho thấy 5 lỗ hổng bị khai thác thành công
2. **Bước 2:** Chạy `npm run test-model` → so sánh bản có lỗi vs bản phòng thủ
3. **Bước 3:** Chạy `npm test` → chứng minh bộ test tự động phát hiện lỗi
4. **Bước 4:** Chạy `npm run seclab` → kiểm thử black-box trên bản phòng thủ
5. **Bước 5:** Mở giao diện web → demo trực quan trên trình duyệt

## Mô hình kiểm thử 3 giai đoạn

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  PHÁT HIỆN  │ ──▶ │    XÁC NHẬN      │ ──▶ │    ĐỐI CHIẾU     │
│ (Detection) │     │ (Verification)   │     │   (Comparison)    │
│             │     │                  │     │                   │
│ Gửi payload │     │ Kiểm tra dữ liệu│     │ Vuln vs Defended  │
│ tấn công    │     │ có bị thay đổi?  │     │ → đánh giá biện   │
│ HTTP 2xx?   │     │ role? balance?   │     │   pháp phòng thủ  │
└─────────────┘     └──────────────────┘     └───────────────────┘
```
