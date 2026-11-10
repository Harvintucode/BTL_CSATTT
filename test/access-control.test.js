/**
 * Kiểm thử kiểm soát truy cập tự động.  Chạy: npm test
 * Test tự khởi động server ở cổng ngẫu nhiên, không cần bật server riêng.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp, db, DEMO_PASSWORD, isPrivateIP } = require('../server');

let server, base;
const tokens = {};

const call = (path, { method = 'GET', token, body } = {}) =>
  fetch(base + path, {
    method,
    headers: { ...(token && { Authorization: `Bearer ${token}` }), 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });

before(async () => {
  server = createApp().listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  for (const u of ['userA', 'userB', 'teller1', 'admin']) {
    const r = await call('/api/login', { method: 'POST', body: { username: u, password: DEMO_PASSWORD } });
    tokens[u] = (await r.json()).token;
  }
});
after(() => server.close());

test('Xác thực: không token -> 401, sai mật khẩu -> 401', async () => {
  assert.equal((await call('/api/me')).status, 401);
  const r = await call('/api/login', { method: 'POST', body: { username: 'userA', password: 'sai' } });
  assert.equal(r.status, 401);
});

test('Xác thực: token giả mạo (alg none / sai chữ ký) bị từ chối', async () => {
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ id: 4 })}.`;
  assert.equal((await call('/api/me', { token: forged })).status, 401);
});

test('CWE-639: user đọc tài khoản của mình được, của người khác bị chặn', async () => {
  assert.equal((await call('/api/accounts/detail?accountId=1001', { token: tokens.userA })).status, 200);
  assert.equal((await call('/api/accounts/detail?accountId=1002', { token: tokens.userA })).status, 403);
});

test('CWE-639/HPP: accountId trùng lặp bị chặn 400', async () => {
  const r = await call('/api/accounts/detail?accountId=1001&accountId=1002', { token: tokens.userA });
  assert.equal(r.status, 400);
});

test('CWE-639: teller xem được mọi tài khoản khách', async () => {
  assert.equal((await call('/api/accounts/detail?accountId=1002', { token: tokens.teller1 })).status, 200);
});

test('CWE-285: user không duyệt vay được bằng POST/PUT/GET/DELETE hay header giả', async () => {
  for (const method of ['POST', 'PUT', 'GET', 'DELETE', 'PATCH']) {
    const r = await call('/api/admin/approve-loan', {
      method, token: tokens.userA, body: method === 'GET' ? undefined : { loanId: 101 },
    });
    assert.ok([403, 405].includes(r.status), `${method} trả ${r.status}`);
  }
  const r = await fetch(base + '/api/admin/approve-loan', {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokens.userA}`, 'Content-Type': 'application/json', 'X-Forwarded-Role': 'ADMIN' },
    body: JSON.stringify({ loanId: 101 }),
  });
  assert.equal(r.status, 403);
  assert.equal(db.loans.find(l => l.loanId === 101).status, 'PENDING');
});

test('CWE-285: teller duyệt vay hợp lệ bằng POST', async () => {
  const r = await call('/api/admin/approve-loan', { method: 'POST', token: tokens.teller1, body: { loanId: 101 } });
  assert.equal(r.status, 200);
  assert.match(db.loans.find(l => l.loanId === 101).approvedBy, /TELLER/);
});

test('CWE-285: user không vào được API quản trị', async () => {
  for (const p of ['/api/admin/users', '/api/admin/audit', '/api/staff/customers']) {
    assert.equal((await call(p, { token: tokens.userA })).status, 403, p);
  }
  const r = await call('/api/admin/users/2/role', { method: 'PUT', token: tokens.userA, body: { role: 'ADMIN' } });
  assert.equal(r.status, 403);
});

test('CWE-915: mass assignment bị bỏ qua, role/balance không đổi', async () => {
  const before = { ...db.users.find(u => u.id === 1) };
  const r = await call('/api/profile/update', {
    method: 'PUT', token: tokens.userA,
    body: { fullName: 'User A Moi', role: 'ADMIN', creditLimit: 999999999, balance: 1 },
  });
  const data = await r.json();
  assert.equal(r.status, 200);
  assert.equal(data.updatedUser.fullName, 'User A Moi');
  assert.equal(data.updatedUser.role, 'USER');
  assert.equal(data.updatedUser.creditLimit, before.creditLimit);
  assert.equal(data.updatedUser.balance, before.balance);
  assert.deepEqual(data.ignoredFields.sort(), ['balance', 'creditLimit', 'role']);
  assert.equal((await call('/api/admin/users', { token: tokens.userA })).status, 403);
});

test('CWE-22: path traversal và đọc sao kê người khác bị chặn', async () => {
  const bad = ['....//secret_config.txt', '../server.js', '..%2fserver.js', '/etc/passwd', 'statement_1002.csv'];
  for (const f of bad) {
    const r = await call(`/api/statements/download?file=${f}`, { token: tokens.userA });
    assert.ok(r.status >= 400, `${f} -> ${r.status}`);
  }
  const ok = await call('/api/statements/download?file=statement_1001.csv', { token: tokens.userA });
  assert.equal(ok.status, 200);
});

test('CWE-918: SSRF vào IP nội bộ bị chặn (nhiều biến thể)', async () => {
  const urls = [
    'http://127.0.0.1:4000/', 'http://localhost/', 'http://[::1]/', 'http://0.0.0.0/',
    'http://2130706433/', 'http://127.1/', 'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.5/', 'http://192.168.1.1/', 'http://[::ffff:127.0.0.1]/',
    'file:///etc/passwd', 'ftp://example.com/', 'http://user:pw@example.com/',
  ];
  for (const webhookUrl of urls) {
    const r = await call('/api/webhooks/test', { method: 'POST', token: tokens.userA, body: { webhookUrl } });
    assert.ok(r.status >= 400, `${webhookUrl} -> ${r.status}`);
  }
});

test('CWE-918: hàm isPrivateIP nhận diện đúng dải nội bộ', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.1.1', '::1', 'fd00::1', '::ffff:10.0.0.1', '::ffff:7f00:1', '::ffff:a00:1'])
    assert.equal(isPrivateIP(ip), true, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '93.184.216.34'])
    assert.equal(isPrivateIP(ip), false, ip);
});

test('SoD: teller/admin không được lập lệnh chuyển tiền', async () => {
  for (const t of [tokens.teller1, tokens.admin]) {
    const r = await call('/api/transactions/transfer', { method: 'POST', token: t, body: { toAccountId: '1002', amount: 100000 } });
    assert.equal(r.status, 403);
  }
});

test('CWE-639: không trích tiền từ tài khoản người khác', async () => {
  const b1 = db.users[1].balance;
  const r = await call('/api/transactions/transfer', { method: 'POST', token: tokens.userA, body: { fromAccountId: '1002', toAccountId: '1001', amount: 5000000 } });
  assert.equal(r.status, 403);
  assert.equal(db.users[1].balance, b1);
});

test('Chuyển tiền: hợp lệ cập nhật số dư hai phía và ghi sổ', async () => {
  const [a0, b0] = [db.users[0].balance, db.users[1].balance];
  const r = await call('/api/transactions/transfer', { method: 'POST', token: tokens.userA, body: { fromAccountId: '1001', toAccountId: '1002', amount: 500000, memo: '=HYPERLINK("x")' } });
  assert.equal(r.status, 201);
  assert.equal(db.users[0].balance, a0 - 500000);
  assert.equal(db.users[1].balance, b0 + 500000);
});

test('Chuyển tiền: dữ liệu xấu bị từ chối, số dư không đổi', async () => {
  const a0 = db.users[0].balance;
  const bad = [{ amount: -5 }, { amount: 0 }, { amount: 1.5 }, { amount: 'abc' }, { amount: 1e12 }, { amount: 999999999999 },
    { toAccountId: '9999' }, { toAccountId: '1001' }, { toAccountId: ['1002'] }, { toAccountId: '0000' }];
  for (const patch of bad) {
    const r = await call('/api/transactions/transfer', { method: 'POST', token: tokens.userA, body: { toAccountId: '1002', amount: 1000, ...patch } });
    assert.ok(r.status >= 400, JSON.stringify(patch) + ' -> ' + r.status);
  }
  assert.equal(db.users[0].balance, a0);
});

test('Sao kê CSV: chống formula injection và chỉ chứa giao dịch của chủ tài khoản', async () => {
  const r = await call('/api/statements/download?file=statement_1001.csv', { token: tokens.userA });
  const { content } = await r.json();
  assert.ok(content.startsWith('Ma GD,'));
  assert.ok(!/(^|,)=HYPERLINK/m.test(content));
  assert.ok(!content.includes('TX882'));
});

test('Phân cấp: Teller không duyệt khoản vay > 100 triệu, Admin duyệt được', async () => {
  const t = await call('/api/admin/approve-loan', { method: 'POST', token: tokens.teller1, body: { loanId: 102 } });
  assert.equal(t.status, 403);
  assert.equal(db.loans.find(l => l.loanId === 102).status, 'PENDING');
  const a = await call('/api/admin/approve-loan', { method: 'POST', token: tokens.admin, body: { loanId: 102 } });
  assert.equal(a.status, 200);
  assert.equal((await call('/api/admin/approve-loan', { method: 'POST', token: tokens.admin, body: { loanId: 102 } })).status, 409);
});

test('Vay vốn: chỉ khách hàng nộp hồ sơ, dữ liệu được kiểm tra', async () => {
  assert.equal((await call('/api/loans/apply', { method: 'POST', token: tokens.teller1, body: { amount: 5000000, term: '12 tháng' } })).status, 403);
  assert.equal((await call('/api/loans/apply', { method: 'POST', token: tokens.userA, body: { amount: -1, term: '12 tháng' } })).status, 400);
  assert.equal((await call('/api/loans/apply', { method: 'POST', token: tokens.userA, body: { amount: 5000000, term: '99 năm' } })).status, 400);
  assert.equal((await call('/api/loans/apply', { method: 'POST', token: tokens.userA, body: { amount: 5000000, term: '12 tháng' } })).status, 201);
});

test('Khách hàng chỉ thấy khoản vay của mình', async () => {
  const { data } = await (await call('/api/loans', { token: tokens.userB })).json();
  assert.ok(data.every(l => l.accountId === '1002'));
});

test('Hồ sơ: phone/email hợp lệ được lưu, giá trị xấu bị từ chối', async () => {
  assert.equal((await call('/api/profile/update', { method: 'PUT', token: tokens.userB, body: { phone: '0977000111', email: 'b@example.com' } })).status, 200);
  assert.equal((await call('/api/profile/update', { method: 'PUT', token: tokens.userB, body: { phone: 'abc' } })).status, 400);
  assert.equal((await call('/api/profile/update', { method: 'PUT', token: tokens.userB, body: { email: '<script>' } })).status, 400);
});

test('Nhật ký: admin thấy các lần bị từ chối', async () => {
  const r = await call('/api/admin/audit', { token: tokens.admin });
  const { data } = await r.json();
  const events = new Set(data.map(e => e.event));
  for (const e of ['LOGIN', 'TRANSFER', 'DENY_LIMIT', 'DENY_IDOR', 'DENY_HPP', 'DENY_ROLE', 'DENY_METHOD', 'DENY_MASS_ASSIGN', 'DENY_PATH', 'DENY_SSRF'])
    assert.ok(events.has(e), `thiếu ${e}`);
});
