#!/usr/bin/env node
/**
 * Security Lab - kiểm thử kiểm soát truy cập từ bên ngoài (black-box qua HTTP).
 * Không phụ thuộc vào giao diện web, chạy được với server local hoặc bản đã deploy.
 *
 *   node security-lab/run.js
 *   BASE_URL=https://ten-ban.onrender.com node security-lab/run.js
 *   LAB_PASSWORD=... node security-lab/run.js
 *
 * Mỗi ca gửi một request trái phép và kỳ vọng máy chủ CHẶN hoặc VÔ HIỆU HÓA nó.
 * Mã thoát: 0 = mọi ca đạt, 1 = có ca không đạt (rò rỉ), 2 = không chạy được.
 */
const BASE = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
const PASSWORD = process.env.LAB_PASSWORD || 'Bank@2025';
const ONLY = process.env.ONLY ? process.env.ONLY.split(',').map(s => s.trim().toLowerCase()) : null;
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);

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
  if (!r.data.token) throw new Error(`Không đăng nhập được ${username} (HTTP ${r.status}). Kiểm tra BASE_URL / LAB_PASSWORD.`);
  return r.data.token;
}

const blocked = r => r.status >= 400;
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');

(async () => {
  let t;
  try {
    t = { A: await login('userA'), B: await login('userB'), T: await login('teller1'), AD: await login('admin') };
  } catch (e) {
    console.error(c(31, 'Không chạy được: ' + e.message));
    process.exit(2);
  }

  // Mỗi ca trả về { ok, detail, skip? }
  const cases = [
    ['CWE-639', 'IDOR: userA đọc TK 1002', async () => {
      const r = await http('/api/accounts/detail?accountId=1002', { token: t.A });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['CWE-639', 'HPP: accountId lặp', async () => {
      const r = await http('/api/accounts/detail?accountId=1001&accountId=1002', { token: t.A });
      return { ok: blocked(r), detail: `HTTP ${r.status}` };
    }],
    ['CWE-639', 'Trích tiền từ TK 1002 (fromAccountId giả)', async () => {
      const r = await http('/api/transactions/transfer', { method: 'POST', token: t.A, body: { fromAccountId: '1002', toAccountId: '1001', amount: 1000000 } });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['CWE-285', 'BFLA: khách hàng gọi API duyệt vay bằng PUT/GET/DELETE/PATCH', async () => {
      const codes = [];
      for (const method of ['PUT', 'GET', 'DELETE', 'PATCH']) {
        const r = await http('/api/admin/approve-loan', { method, token: t.A, body: method === 'GET' ? undefined : { loanId: 101, action: 'APPROVED' } });
        codes.push(r.status);
        if (!blocked(r)) return { ok: false, detail: `${method} -> ${r.status}` };
      }
      return { ok: true, detail: `HTTP ${codes.join('/')}` };
    }],
    ['CWE-285', 'BFLA: POST kèm header giả X-Forwarded-Role: ADMIN', async () => {
      const r = await http('/api/admin/approve-loan', { method: 'POST', token: t.A, body: { loanId: 101 }, headers: { 'X-Forwarded-Role': 'ADMIN' } });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['CWE-285', 'Khách hàng gọi API quản trị/nhân viên', async () => {
      const paths = ['/api/admin/audit', '/api/admin/users', '/api/staff/customers'];
      const codes = [];
      for (const p of paths) { const r = await http(p, { token: t.A }); codes.push(r.status); if (!blocked(r)) return { ok: false, detail: `${p} -> ${r.status}` }; }
      return { ok: true, detail: `HTTP ${codes.join('/')}` };
    }],
    ['CWE-285', 'Khách hàng tự đổi vai trò người khác', async () => {
      const r = await http('/api/admin/users/2/role', { method: 'PUT', token: t.A, body: { role: 'ADMIN' } });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['SoD', 'Teller lập lệnh chuyển tiền', async () => {
      const r = await http('/api/transactions/transfer', { method: 'POST', token: t.T, body: { toAccountId: '1002', amount: 100000 } });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['SoD', 'Admin lập lệnh chuyển tiền', async () => {
      const r = await http('/api/transactions/transfer', { method: 'POST', token: t.AD, body: { toAccountId: '1002', amount: 100000 } });
      return { ok: r.status === 403, detail: `HTTP ${r.status}` };
    }],
    ['Hạn mức', 'Teller duyệt khoản vay > 100 triệu', async () => {
      const loans = (await http('/api/loans', { token: t.T })).data.data || [];
      const vip = loans.find(l => l.status === 'PENDING' && l.amount > 100000000);
      if (!vip) return { skip: true, detail: 'không có khoản vay VIP đang chờ (đã được xử lý)' };
      const r = await http('/api/admin/approve-loan', { method: 'POST', token: t.T, body: { loanId: vip.loanId } });
      return { ok: r.status === 403, detail: `loan #${vip.loanId} -> HTTP ${r.status}` };
    }],
    ['CWE-915', 'Mass assignment: role=ADMIN, creditLimit, balance', async () => {
      const before = (await http('/api/me', { token: t.A })).data.user;
      await http('/api/profile/update', { method: 'PUT', token: t.A, body: { fullName: before.fullName, role: 'ADMIN', creditLimit: 999999999, balance: 999999999, tier: 'VIP' } });
      const after = (await http('/api/me', { token: t.A })).data.user;
      const ok = after.role === before.role && after.creditLimit === before.creditLimit && after.balance === before.balance && after.tier === before.tier;
      return { ok, detail: `role=${after.role}, creditLimit=${after.creditLimit}` };
    }],
    ['CWE-22', 'Path traversal / đọc sao kê người khác', async () => {
      const files = ['....//secret_config.txt', '../server.js', '..%2fserver.js', '..\\server.js', '/etc/passwd', 'statement_1002.csv'];
      for (const f of files) {
        const r = await http('/api/statements/download?file=' + encodeURIComponent(f), { token: t.A });
        if (!blocked(r)) return { ok: false, detail: `${f} -> ${r.status}` };
      }
      return { ok: true, detail: `${files.length} biến thể đều bị chặn` };
    }],
    ['CWE-918', 'SSRF: URL trỏ về mạng nội bộ', async () => {
      const urls = ['http://127.0.0.1:4000/', 'http://localhost/', 'http://[::1]/', 'http://0.0.0.0/', 'http://2130706433/', 'http://127.1/',
        'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/', 'http://192.168.1.1/', 'http://[::ffff:127.0.0.1]/',
        'file:///etc/passwd', 'ftp://example.com/', 'http://user:pw@example.com/'];
      for (const webhookUrl of urls) {
        const r = await http('/api/webhooks/test', { method: 'POST', token: t.A, body: { webhookUrl } });
        if (!blocked(r)) return { ok: false, detail: `${webhookUrl} -> ${r.status}` };
      }
      return { ok: true, detail: `${urls.length} biến thể đều bị chặn` };
    }],
    ['Auth', 'Không token / token giả (alg=none) / token rác', async () => {
      const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ id: 4 })}.`;
      const codes = [];
      for (const tok of [undefined, forged, 'abc.def.ghi']) { const r = await http('/api/me', { token: tok }); codes.push(r.status); if (r.status !== 401) return { ok: false, detail: `-> ${r.status}` }; }
      return { ok: true, detail: `HTTP ${codes.join('/')}` };
    }],
    ['Validate', 'Chuyển tiền với số tiền/tài khoản bất thường', async () => {
      const bad = [{ amount: -5 }, { amount: 0 }, { amount: 1.5 }, { amount: 'abc' }, { amount: 99999999999 }, { toAccountId: '9999' }, { toAccountId: '1001' }, { toAccountId: ['1002'] }];
      for (const patch of bad) {
        const r = await http('/api/transactions/transfer', { method: 'POST', token: t.A, body: { toAccountId: '1002', amount: 1000, ...patch } });
        if (!blocked(r)) return { ok: false, detail: `${JSON.stringify(patch)} -> ${r.status}` };
      }
      return { ok: true, detail: `${bad.length} dữ liệu xấu đều bị từ chối` };
    }],
  ];

  console.log(c(1, `\nSecurity Lab · ${BASE}`));
  console.log('Kỳ vọng: mọi request trái phép bị chặn hoặc vô hiệu hóa.\n');
  let pass = 0, fail = 0, skip = 0;
  for (const [cwe, name, fn] of cases) {
    if (ONLY && !ONLY.some(k => (cwe + ' ' + name).toLowerCase().includes(k))) continue;
    let r;
    try { r = await fn(); } catch (e) { r = { ok: false, detail: 'lỗi: ' + e.message }; }
    const tag = r.skip ? c(33, 'SKIP') : r.ok ? c(32, 'PASS') : c(31, 'FAIL');
    r.skip ? skip++ : r.ok ? pass++ : fail++;
    console.log(`${tag}  ${cwe.padEnd(8)} ${name}  ${c(90, '· ' + r.detail)}`);
  }
  console.log(`\nKết quả: ${c(32, pass + ' pass')}, ${fail ? c(31, fail + ' fail') : '0 fail'}, ${skip} skip`);
  if (fail) console.log(c(31, 'Có ca bị rò rỉ: kiểm tra lại phân quyền trên máy chủ.'));
  process.exit(fail ? 1 : 0);
})();
