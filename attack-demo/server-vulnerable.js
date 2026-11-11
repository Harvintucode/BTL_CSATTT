/**
 * Mini Web Bank – BẢN CÓ LỖI (Vulnerable Demo)
 * ⚠️ File này CỐ Ý chứa lỗi bảo mật để phục vụ demo tấn công.
 * KHÔNG triển khai ra môi trường thật.
 *
 * 5 lỗ hổng CWE được cài:
 *   CASE 1: CWE-639  – IDOR / BOLA: không kiểm tra quyền sở hữu tài khoản
 *   CASE 2: CWE-285  – BFLA: không kiểm tra role, không khóa method
 *   CASE 3: CWE-915  – Mass Assignment: Object.assign(user, req.body) trực tiếp
 *   CASE 4: CWE-22   – Path Traversal: dùng req.query.file trực tiếp vào đường dẫn
 *   CASE 5: CWE-918  – SSRF: gọi fetch tới URL người dùng cung cấp không qua lọc
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const JWT_SECRET = 'demo-secret-key-insecure';
const STATEMENT_DIR = path.resolve(__dirname, '..', 'statements');

// ---------------------------------------------------------------- Dữ liệu giả lập
const DEMO_PASSWORD = 'Bank@2025';
const hashPw = (pw) => crypto.createHash('md5').update(pw).digest('hex'); // Weak hash for demo
const db = {
  users: [
    { id: 1, username: 'userA', role: 'USER', tier: 'Cá nhân Tiêu chuẩn', accountId: '1001', fullName: 'Nguyễn Văn A', phone: '0912345678', email: 'nguyenvana@ptit.edu.vn', balance: 50000000, creditLimit: 20000000, stmtFile: 'statement_1001.csv', passwordHash: hashPw(DEMO_PASSWORD) },
    { id: 2, username: 'userB', role: 'USER', tier: 'Khách hàng Cao cấp (Priority)', accountId: '1002', fullName: 'Trần Thị B', phone: '0988888888', email: 'tranthib@example.com', balance: 950000000, creditLimit: 200000000, stmtFile: 'statement_1002.csv', passwordHash: hashPw(DEMO_PASSWORD) },
    { id: 3, username: 'teller1', role: 'TELLER', tier: 'Chuyên viên Giao dịch (Bậc 1)', accountId: '9001', fullName: 'Lê Hoàng', phone: '0901112222', email: 'teller1@ptit-emb.example', balance: 0, creditLimit: 0, stmtFile: '', passwordHash: hashPw(DEMO_PASSWORD) },
    { id: 4, username: 'admin', role: 'ADMIN', tier: 'Giám đốc Chi nhánh', accountId: '9999', fullName: 'Phạm Quản Trị', phone: '0909999999', email: 'admin@ptit-emb.example', balance: 0, creditLimit: 0, stmtFile: '', passwordHash: hashPw(DEMO_PASSWORD) },
  ],
  transactions: [
    { id: 'TX901', date: '2026-11-01T08:30:00+07:00', fromAcct: '1001', toAcct: '1002', amount: 2000000, memo: 'Chuyen tien mua hang', status: 'SUCCESS' },
    { id: 'TX902', date: '2026-11-03T14:15:00+07:00', fromAcct: 'CTY_PTIT', toAcct: '1001', amount: 15000000, memo: 'Luong thang 11', status: 'SUCCESS' },
    { id: 'TX882', date: '2026-11-05T09:00:00+07:00', fromAcct: '1002', toAcct: 'BDS_VIN', amount: 150000000, memo: 'Dat coc can ho', status: 'SUCCESS' },
  ],
  loans: [
    { loanId: 101, accountId: '1001', borrower: 'Nguyễn Văn A', amount: 45000000, term: '12 tháng', rate: '7.5%/năm', purpose: 'Vay tiêu dùng mua thiết bị', status: 'PENDING', approvedBy: null },
    { loanId: 102, accountId: '1002', borrower: 'Trần Thị B', amount: 350000000, term: '36 tháng', rate: '6.8%/năm', purpose: 'Bổ sung vốn kinh doanh (hồ sơ VIP)', status: 'PENDING', approvedBy: null },
  ],
  audit: [],
};
let txSeq = 1000, loanSeq = 102;

const publicUser = ({ passwordHash, ...rest }) => rest;

// ---------------------------------------------------------------- Middleware
function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try {
    // ⚠️ LỖI: không chỉ định algorithms → chấp nhận alg=none
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: 'Phiên không hợp lệ' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
  }
}

// ⚠️ LỖI: KHÔNG CÓ requireRole middleware → mọi user đã đăng nhập đều truy cập được

// ---------------------------------------------------------------- App
function createApp() {
  const app = express();
  app.use(express.json());
  // Phục vụ giao diện web (dùng chung thư mục public của project gốc)
  app.use(express.static(path.join(__dirname, '..', 'public')));
  // ⚠️ LỖI: không thiết lập security headers

  // ---- Đăng nhập
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    const user = db.users.find(u => u.username === username);
    if (!user || hashPw(password) !== user.passwordHash) {
      return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    }
    // ⚠️ LỖI: đưa role vào token, sau dùng role từ token thay vì DB
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, user: publicUser(user) });
  });

  app.get('/api/me', authenticate, (req, res) => res.json({ user: publicUser(req.user) }));

  // ---- CASE 1: CWE-639 IDOR / BOLA
  // ⚠️ LỖI: không kiểm tra quyền sở hữu – ai cũng đọc được bất kỳ tài khoản nào
  app.get('/api/accounts/detail', authenticate, (req, res) => {
    const acct = req.query.accountId || req.user.accountId;
    // ⚠️ LỖI: không kiểm tra acct === req.user.accountId
    const target = db.users.find(u => u.accountId === acct);
    if (!target) return res.status(404).json({ error: 'Không tìm thấy tài khoản' });
    const transactions = db.transactions.filter(t => t.fromAcct === acct || t.toAcct === acct);
    res.json({ data: publicUser(target), transactions });
  });

  app.get('/api/staff/customers', authenticate, (req, res) =>
    // ⚠️ LỖI: không kiểm tra role – user thường cũng truy cập được
    res.json({
      data: db.users.filter(u => u.role === 'USER').map(({ accountId, fullName, tier, phone, balance, creditLimit }) =>
        ({ accountId, fullName, tier, phone, balance, creditLimit })),
    }));

  // ---- Chuyển tiền
  // ⚠️ LỖI: chấp nhận fromAccountId từ client → trích tiền từ tài khoản người khác
  app.post('/api/transactions/transfer', authenticate, (req, res) => {
    const { fromAccountId, toAccountId, amount, memo } = req.body || {};
    const sourceAcct = fromAccountId || req.user.accountId;
    // ⚠️ LỖI: không kiểm tra sourceAcct === req.user.accountId
    const source = db.users.find(u => u.accountId === sourceAcct);
    if (!source) return res.status(404).json({ error: 'Tài khoản nguồn không tồn tại' });
    const value = Number(amount);
    if (!value || value <= 0) return res.status(400).json({ error: 'Số tiền không hợp lệ' });
    const receiver = db.users.find(u => u.accountId === toAccountId);
    if (!receiver) return res.status(404).json({ error: 'Tài khoản thụ hưởng không tồn tại' });
    if (source.balance < value) return res.status(400).json({ error: 'Số dư không đủ' });
    source.balance -= value;
    receiver.balance += value;
    const tx = { id: `TX${++txSeq}`, date: new Date().toISOString(), fromAcct: sourceAcct, toAcct: toAccountId, amount: value, memo: memo || '', status: 'SUCCESS' };
    db.transactions.unshift(tx);
    res.status(201).json({ message: 'Chuyển tiền thành công', transaction: tx, newBalance: source.balance });
  });

  // ---- Khoản vay
  app.get('/api/loans', authenticate, (req, res) => {
    // ⚠️ LỖI: trả toàn bộ khoản vay cho mọi người, không lọc theo role
    res.json({ data: db.loans });
  });

  app.post('/api/loans/apply', authenticate, (req, res) => {
    const { amount, term, purpose } = req.body || {};
    const loan = {
      loanId: ++loanSeq, accountId: req.user.accountId, borrower: req.user.fullName,
      amount: Number(amount), term: term || '12 tháng',
      rate: '7.5%/năm', purpose: purpose || 'Vay tiêu dùng',
      status: 'PENDING', approvedBy: null,
    };
    db.loans.unshift(loan);
    res.status(201).json({ message: 'Đã gửi hồ sơ vay vốn', loan });
  });

  // ---- CASE 2: CWE-285/862 BFLA – không khóa method, không kiểm tra role
  // ⚠️ LỖI: dùng app.all → chấp nhận GET/PUT/DELETE/PATCH
  // ⚠️ LỖI: không requireRole → user thường cũng duyệt vay được
  // ⚠️ LỖI: kiểm tra role từ header X-Forwarded-Role thay vì DB
  app.all('/api/admin/approve-loan', authenticate, (req, res) => {
    // ⚠️ LỖI: tin vào header do client gửi
    const clientRole = req.headers['x-forwarded-role'] || req.user.role;
    // Không kiểm tra role thực tế, không giới hạn hạn mức
    const { loanId, action = 'APPROVED' } = req.body || {};
    const loan = db.loans.find(l => l.loanId === Number(loanId));
    if (!loan) return res.status(404).json({ error: 'Không tìm thấy khoản vay' });
    if (loan.status !== 'PENDING') return res.status(409).json({ error: 'Khoản vay đã được xử lý' });
    loan.status = action || 'APPROVED';
    loan.approvedBy = `${req.user.fullName} (${clientRole})`;
    res.json({ message: 'Đã xử lý khoản vay', loan });
  });

  // ---- CASE 3: CWE-915 Mass Assignment
  // ⚠️ LỖI: Object.assign trực tiếp từ req.body → thay đổi được role, balance, creditLimit
  app.put('/api/profile/update', authenticate, (req, res) => {
    const body = req.body || {};
    Object.assign(req.user, body);
    res.json({ message: 'Đã cập nhật hồ sơ', updatedUser: publicUser(req.user) });
  });

  // ---- CASE 4: CWE-22 Path Traversal
  // ⚠️ LỖI: nối trực tiếp req.query.file vào đường dẫn, không kiểm tra quyền sở hữu
  app.get('/api/statements/download', authenticate, (req, res) => {
    const file = req.query.file || req.user.stmtFile;
    if (!file) return res.status(400).json({ error: 'Thiếu tên file' });
    // ⚠️ LỖI: path.join cho phép traversal (../server.js, ../../etc/passwd...)
    const filePath = path.join(STATEMENT_DIR, file);
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      res.json({ fileName: file, content });
    } catch {
      res.status(404).json({ error: 'Không tìm thấy file' });
    }
  });

  // ---- CASE 5: CWE-918 SSRF
  // ⚠️ LỖI: gọi fetch trực tiếp tới URL do người dùng cung cấp, không kiểm tra IP/protocol
  app.post('/api/webhooks/test', authenticate, async (req, res) => {
    const { webhookUrl } = req.body || {};
    if (!webhookUrl) return res.status(400).json({ error: 'Thiếu webhookUrl' });
    try {
      // ⚠️ LỖI: không lọc protocol, không kiểm tra IP nội bộ, gọi fetch thật
      const resp = await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ test: true, time: new Date().toISOString() }), signal: AbortSignal.timeout(5000) });
      const text = await resp.text();
      res.json({ message: `Webhook trả về HTTP ${resp.status}`, preview: text.slice(0, 500) });
    } catch (e) {
      res.json({ message: `Webhook gặp lỗi: ${e.message}` });
    }
  });

  // ---- Quản trị
  // ⚠️ LỖI: không requireRole('ADMIN')
  app.get('/api/admin/users', authenticate, (req, res) => res.json({ data: db.users.map(publicUser) }));
  app.put('/api/admin/users/:id/role', authenticate, (req, res) => {
    const target = db.users.find(u => u.id === Number(req.params.id));
    if (!target) return res.status(404).json({ error: 'Không tìm thấy user' });
    target.role = req.body?.role || target.role;
    res.json({ data: publicUser(target) });
  });
  app.get('/api/admin/audit', authenticate, (req, res) => res.json({ data: db.audit }));

  app.use('/api', (req, res) => res.status(404).json({ error: 'Không tìm thấy endpoint' }));
  return app;
}

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  createApp().listen(PORT, () => console.log(`⚠️  Vulnerable Mini Web Bank: http://localhost:${PORT}`));
}

module.exports = { createApp, db, DEMO_PASSWORD };
