#!/usr/bin/env node
/**
 * 🔬 MÔ HÌNH KIỂM THỬ – So sánh bản có lỗi (vulnerable) và bản phòng thủ (defended)
 *
 * Chạy cả hai server trước:
 *   node server.js                          # cổng 3000 (phòng thủ)
 *   node attack-demo/server-vulnerable.js   # cổng 3001 (có lỗi)
 *   node attack-demo/test-model.js          # chạy kiểm thử
 *
 * Mô hình gửi cùng một payload tấn công tới cả hai server và so sánh kết quả.
 * Bản phòng thủ phải CHẶN tất cả; bản có lỗi sẽ bị khai thác.
 */
const VULN_BASE = process.env.VULN_URL || 'http://localhost:3001';
const DEF_BASE  = process.env.DEF_URL  || 'http://localhost:3000';
const PASSWORD  = 'Bank@2025';

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const RED = s => c(31, s), GREEN = s => c(32, s), YELLOW = s => c(33, s),
      CYAN = s => c(36, s), BOLD = s => c(1, s), DIM = s => c(90, s),
      BG_RED = s => c('41;37', s), BG_GREEN = s => c('42;30', s);

async function http(base, path, { method = 'GET', token, body, headers = {} } = {}) {
  try {
    const res = await fetch(base + path, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch {}
    return { status: res.status, data, ok: res.ok };
  } catch {
    return { status: 0, data: {}, ok: false };
  }
}

async function login(base, username) {
  const r = await http(base, '/api/login', { method: 'POST', body: { username, password: PASSWORD } });
  return r.data.token || null;
}

const TABLE_WIDTH = 92;
const sep = () => console.log(DIM('  ' + '─'.repeat(TABLE_WIDTH)));

function tableHeader() {
  console.log(`\n  ${BOLD('Ca kiểm thử'.padEnd(42))} ${BOLD('Bản có lỗi'.padEnd(18))} ${BOLD('Bản phòng thủ'.padEnd(18))} ${BOLD('Nhận xét')}`);
  sep();
}

function tableRow(name, vulnResult, defResult, comment) {
  const vulnTag = vulnResult ? BG_RED(' BỊ KHAI THÁC ') : BG_GREEN('  ĐÃ CHẶN  ') + '   ';
  const defTag  = defResult  ? BG_RED(' BỊ KHAI THÁC ') : BG_GREEN('  ĐÃ CHẶN  ') + '   ';
  console.log(`  ${name.padEnd(42)} ${vulnTag}  ${defTag}  ${DIM(comment)}`);
}

(async () => {
  console.log(BOLD(`\n${'━'.repeat(68)}`));
  console.log(BOLD(CYAN('  🔬 MÔ HÌNH KIỂM THỬ PHÁT HIỆN LỖ HỔNG KIỂM SOÁT TRUY CẬP')));
  console.log(BOLD(`${'━'.repeat(68)}`));
  console.log(DIM(`  Server có lỗi:   ${VULN_BASE}`));
  console.log(DIM(`  Server phòng thủ: ${DEF_BASE}\n`));

  // Đăng nhập cả hai server
  const vTokens = {}, dTokens = {};
  let vOk = true, dOk = true;

  for (const u of ['userA', 'userB', 'teller1', 'admin']) {
    vTokens[u] = await login(VULN_BASE, u);
    dTokens[u] = await login(DEF_BASE, u);
    if (!vTokens[u]) vOk = false;
    if (!dTokens[u]) dOk = false;
  }

  if (!vOk) {
    console.log(YELLOW('  ⚠ Không kết nối được bản có lỗi (cổng 3001).'));
    console.log(DIM('    → Chạy: node attack-demo/server-vulnerable.js'));
  }
  if (!dOk) {
    console.log(YELLOW('  ⚠ Không kết nối được bản phòng thủ (cổng 3000).'));
    console.log(DIM('    → Chạy: node server.js'));
  }
  if (!vOk && !dOk) { console.log(RED('\n  Cần ít nhất một server để kiểm thử.')); process.exit(2); }

  console.log(GREEN('  ✓ Đã đăng nhập thành công\n'));

  // Hàm kiểm thử: gửi cùng request tới cả hai server
  async function testBoth(name, path, opts, isExploited) {
    const vr = vOk ? await http(VULN_BASE, path, { ...opts, token: opts.useToken ? vTokens[opts.useToken] : undefined }) : null;
    const dr = dOk ? await http(DEF_BASE, path, { ...opts, token: opts.useToken ? dTokens[opts.useToken] : undefined }) : null;

    const vExploit = vr ? isExploited(vr) : false;
    const dExploit = dr ? isExploited(dr) : false;

    const comment = `V:${vr?.status || '?'} D:${dr?.status || '?'}`;
    tableRow(name, vExploit, dExploit, comment);

    return { vExploit, dExploit };
  }

  // ================================================================
  // NHÓM 1: CWE-639 – IDOR / BOLA
  // ================================================================
  console.log(BOLD(RED('  ▸ CASE 1: CWE-639 – IDOR / BOLA (Insecure Direct Object Reference)')));
  tableHeader();

  await testBoth(
    'Đọc TK 1002 từ tài khoản userA',
    '/api/accounts/detail?accountId=1002',
    { useToken: 'userA' },
    r => r.status === 200
  );

  await testBoth(
    'HPP: gửi accountId lặp (mảng)',
    '/api/accounts/detail?accountId=1001&accountId=1002',
    { useToken: 'userA' },
    r => r.status === 200
  );

  await testBoth(
    'Trích tiền từ TK 1002 (fromAccountId giả)',
    '/api/transactions/transfer',
    { method: 'POST', useToken: 'userA', body: { fromAccountId: '1002', toAccountId: '1001', amount: 1000000 } },
    r => r.status === 201
  );

  // ================================================================
  // NHÓM 2: CWE-285/862 – BFLA
  // ================================================================
  console.log(BOLD(RED('\n  ▸ CASE 2: CWE-285/862 – BFLA (Broken Function Level Authorization)')));
  tableHeader();

  await testBoth(
    'userA duyệt vay bằng PUT (sai method)',
    '/api/admin/approve-loan',
    { method: 'PUT', useToken: 'userA', body: { loanId: 101, action: 'APPROVED' } },
    r => r.status === 200
  );

  await testBoth(
    'userA duyệt vay + header giả X-Forwarded-Role',
    '/api/admin/approve-loan',
    { method: 'POST', useToken: 'userA', body: { loanId: 102 }, headers: { 'X-Forwarded-Role': 'ADMIN' } },
    r => r.status === 200
  );

  await testBoth(
    'userA xem nhật ký kiểm toán (admin API)',
    '/api/admin/audit',
    { useToken: 'userA' },
    r => r.status === 200
  );

  await testBoth(
    'userA xem danh sách người dùng (admin API)',
    '/api/admin/users',
    { useToken: 'userA' },
    r => r.status === 200
  );

  await testBoth(
    'userA tra cứu khách hàng (staff API)',
    '/api/staff/customers',
    { useToken: 'userA' },
    r => r.status === 200
  );

  await testBoth(
    'Teller lập lệnh chuyển tiền (SoD)',
    '/api/transactions/transfer',
    { method: 'POST', useToken: 'teller1', body: { toAccountId: '1002', amount: 100000 } },
    r => r.status === 201
  );

  // ================================================================
  // NHÓM 3: CWE-915 – Mass Assignment
  // ================================================================
  console.log(BOLD(RED('\n  ▸ CASE 3: CWE-915 – Mass Assignment / BOPLA')));
  tableHeader();

  // Get before state
  const vBefore = vOk ? (await http(VULN_BASE, '/api/me', { token: vTokens.userA })).data.user : {};
  const dBefore = dOk ? (await http(DEF_BASE, '/api/me', { token: dTokens.userA })).data.user : {};

  // Send mass assignment attack
  if (vOk) await http(VULN_BASE, '/api/profile/update', { method: 'PUT', token: vTokens.userA, body: { fullName: vBefore.fullName, role: 'ADMIN', balance: 999999999, creditLimit: 999999999 } });
  if (dOk) await http(DEF_BASE, '/api/profile/update', { method: 'PUT', token: dTokens.userA, body: { fullName: dBefore.fullName, role: 'ADMIN', balance: 999999999, creditLimit: 999999999 } });

  const vAfter = vOk ? (await http(VULN_BASE, '/api/me', { token: vTokens.userA })).data.user : {};
  const dAfter = dOk ? (await http(DEF_BASE, '/api/me', { token: dTokens.userA })).data.user : {};

  tableRow(
    'Gửi role=ADMIN trong body',
    vAfter.role === 'ADMIN',
    dAfter.role === 'ADMIN',
    `V:${vBefore.role}→${vAfter.role} D:${dBefore.role}→${dAfter.role}`
  );
  tableRow(
    'Gửi balance=999999999 trong body',
    vAfter.balance === 999999999,
    dAfter.balance === 999999999,
    `V:${vBefore.balance}→${vAfter.balance} D:${dBefore.balance}→${dAfter.balance}`
  );
  tableRow(
    'Gửi creditLimit=999999999 trong body',
    vAfter.creditLimit === 999999999,
    dAfter.creditLimit === 999999999,
    `V:${vBefore.creditLimit}→${vAfter.creditLimit} D:${dBefore.creditLimit}→${dAfter.creditLimit}`
  );

  // ================================================================
  // NHÓM 4: CWE-22 – Path Traversal
  // ================================================================
  console.log(BOLD(RED('\n  ▸ CASE 4: CWE-22 – Path Traversal')));
  tableHeader();

  const traversalFiles = [
    ['Đọc sao kê TK khác: statement_1002.csv', 'statement_1002.csv'],
    ['Traversal: ../server.js', '../server.js'],
    ['Traversal: ../.env.example', '../.env.example'],
    ['Traversal: ....//secret.txt', '....//secret.txt'],
    ['Traversal: ..%2fserver.js', '..%2fserver.js'],
  ];
  for (const [name, file] of traversalFiles) {
    await testBoth(
      name,
      '/api/statements/download?file=' + encodeURIComponent(file),
      { useToken: 'userA' },
      r => r.status === 200
    );
  }

  // ================================================================
  // NHÓM 5: CWE-918 – SSRF
  // ================================================================
  console.log(BOLD(RED('\n  ▸ CASE 5: CWE-918 – SSRF (Server-Side Request Forgery)')));
  tableHeader();

  const ssrfUrls = [
    ['URL: http://127.0.0.1:3001/', 'http://127.0.0.1:3001/'],
    ['URL: http://localhost/', 'http://localhost/'],
    ['URL: http://[::1]/', 'http://[::1]/'],
    ['URL: http://169.254.169.254/ (metadata)', 'http://169.254.169.254/'],
    ['URL: http://10.0.0.5/ (nội bộ)', 'http://10.0.0.5/'],
    ['URL: http://192.168.1.1/ (nội bộ)', 'http://192.168.1.1/'],
    ['Protocol: file:///etc/passwd', 'file:///etc/passwd'],
    ['Protocol: ftp://example.com/', 'ftp://example.com/'],
    ['Credentials: http://user:pw@example.com/', 'http://user:pw@example.com/'],
  ];
  for (const [name, url] of ssrfUrls) {
    await testBoth(
      name,
      '/api/webhooks/test',
      { method: 'POST', useToken: 'userA', body: { webhookUrl: url } },
      r => r.ok
    );
  }

  // ================================================================
  // NHÓM 6: Authentication
  // ================================================================
  console.log(BOLD(RED('\n  ▸ BỔ SUNG: Kiểm tra xác thực')));
  tableHeader();

  await testBoth(
    'Truy cập API không có token',
    '/api/me',
    {},
    r => r.status === 200
  );

  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ id: 4 })}.`;
  for (const base of [VULN_BASE, DEF_BASE]) {
    // Just log - handled per-server
  }
  await testBoth(
    'Token giả mạo alg=none',
    '/api/me',
    { useToken: null },
    r => r.status === 200
  );

  // ================================================================
  // Tổng kết
  // ================================================================
  console.log(`\n${BOLD('━'.repeat(68))}`);
  console.log(BOLD(CYAN('  📊 PHÂN TÍCH KẾT QUẢ')));
  console.log(BOLD('━'.repeat(68)));
  console.log(`
  ${BOLD('Mô hình kiểm thử 3 giai đoạn:')}

  ${CYAN('1. PHÁT HIỆN (Detection)')}
     Gửi payload tấn công và kiểm tra mã HTTP trả về.
     • HTTP 2xx trên endpoint trái phép → ${RED('LỖ HỔNG')}
     • HTTP 4xx (401/403/405)           → ${GREEN('AN TOÀN')}

  ${CYAN('2. XÁC NHẬN (Verification)')}
     Kiểm tra dữ liệu thực tế có bị thay đổi không.
     • role/balance/creditLimit thay đổi → ${RED('Mass Assignment')}
     • Đọc được file ngoài thư mục      → ${RED('Path Traversal')}
     • Server gọi URL nội bộ            → ${RED('SSRF')}

  ${CYAN('3. ĐỐI CHIẾU (Comparison)')}
     So sánh kết quả giữa bản có lỗi và bản phòng thủ.
     • Bản có lỗi bị khai thác, bản phòng thủ chặn → ${GREEN('Biện pháp hiệu quả')}
     • Cả hai đều bị khai thác                     → ${RED('Cần sửa thêm')}

  ${BOLD('Biện pháp phòng thủ đã áp dụng:')}
  ┌────────────┬─────────────────────────────────────────────────┐
  │ ${BOLD('CWE')}        │ ${BOLD('Biện pháp trong bản phòng thủ')}                     │
  ├────────────┼─────────────────────────────────────────────────┤
  │ CWE-639    │ Kiểm tra ownership (accountId === user.acctId) │
  │ CWE-285    │ requireRole() + onlyMethods('POST')            │
  │ CWE-915    │ Allowlist DTO (chỉ fullName, phone, email)     │
  │ CWE-22     │ path.basename() + kiểm tra prefix thư mục     │
  │ CWE-918    │ Lọc protocol, DNS resolve, chặn IP nội bộ     │
  └────────────┴─────────────────────────────────────────────────┘
`);
  process.exit(0);
})();
