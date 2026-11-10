/**
 * Mini Web Bank - OWASP A01:2025 Broken Access Control (bản phòng thủ)
 * Chạy: npm start   |   Test: npm test
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const net = require('net');
const dns = require('dns').promises;

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const STATEMENT_DIR = path.resolve(__dirname, 'statements');

// ---------------------------------------------------------------- Dữ liệu
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  `${salt}:${crypto.scryptSync(pw, salt, 32).toString('hex')}`;
const checkPw = (pw, stored) => {
  const [salt, hash] = stored.split(':');
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(pw, salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const DEMO_PASSWORD = 'Bank@2025';
const db = {
  users: [
    { id: 1, username: 'userA', role: 'USER', tier: 'Cá nhân Tiêu chuẩn', accountId: '1001', fullName: 'Nguyễn Văn A', phone: '0912345678', email: 'nguyenvana@ptit.edu.vn', balance: 50000000, creditLimit: 20000000, stmtFile: 'statement_1001.csv' },
    { id: 2, username: 'userB', role: 'USER', tier: 'Khách hàng Cao cấp (Priority)', accountId: '1002', fullName: 'Trần Thị B', phone: '0988888888', email: 'tranthib@example.com', balance: 950000000, creditLimit: 200000000, stmtFile: 'statement_1002.csv' },
    { id: 3, username: 'teller1', role: 'TELLER', tier: 'Chuyên viên Giao dịch (Bậc 1)', accountId: '9001', fullName: 'Lê Hoàng', phone: '0901112222', email: 'teller1@ptit-emb.example', balance: 0, creditLimit: 0, stmtFile: '' },
    { id: 4, username: 'admin', role: 'ADMIN', tier: 'Giám đốc Chi nhánh', accountId: '9999', fullName: 'Phạm Quản Trị', phone: '0909999999', email: 'admin@ptit-emb.example', balance: 0, creditLimit: 0, stmtFile: '' },
  ].map(u => ({ ...u, passwordHash: hashPw(DEMO_PASSWORD) })),
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
const TELLER_LOAN_LIMIT = 100000000;
const LOAN_TERMS = ['6 tháng', '12 tháng', '24 tháng', '36 tháng'];
let txSeq = 1000, loanSeq = 102;

// Sao kê CSV được sinh từ sổ giao dịch; tên file do server quyết định, không lấy từ client.
const csvCell = v => {
  let t = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; // chống CSV/Formula injection
  return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
};
function buildStatement(user) {
  const rows = db.transactions.filter(t => t.fromAcct === user.accountId || t.toAcct === user.accountId)
    .map(t => [t.id, t.date, t.fromAcct, t.toAcct, (t.fromAcct === user.accountId ? '-' : '+') + t.amount, t.memo].map(csvCell).join(','));
  return ['Ma GD,Thoi gian,TK nguon,TK dich,So tien (VND),Noi dung', ...rows].join('\n') + '\n';
}
function seedStatements() {
  fs.mkdirSync(STATEMENT_DIR, { recursive: true });
  for (const u of db.users.filter(x => x.stmtFile)) fs.writeFileSync(path.join(STATEMENT_DIR, u.stmtFile), buildStatement(u));
}

const publicUser = ({ passwordHash, ...rest }) => rest;
const audit = (req, event, detail = '') => {
  db.audit.unshift({ time: new Date().toISOString(), user: req.user?.username || 'anonymous', ip: req.ip, event, detail });
  db.audit.length = Math.min(db.audit.length, 200);
};

// ---------------------------------------------------------------- Middleware
function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    // Quyền luôn lấy từ DB phía server, không tin role trong token.
    const user = db.users.find(u => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: 'Phiên không hợp lệ' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    audit(req, 'DENY_ROLE', `${req.method} ${req.path} yêu cầu ${roles.join('/')}`);
    return res.status(403).json({ error: `Từ chối truy cập (CWE-285). Yêu cầu quyền: ${roles.join(', ')}` });
  }
  next();
};

const onlyMethods = (...methods) => (req, res, next) => {
  if (!methods.includes(req.method)) {
    res.set('Allow', methods.join(', '));
    audit(req, 'DENY_METHOD', `${req.method} ${req.path}`);
    return res.status(405).json({ error: `Method Not Allowed. Chỉ chấp nhận: ${methods.join(', ')}` });
  }
  next();
};

// Giới hạn đăng nhập sai (chống dò mật khẩu)
const attempts = new Map();
function loginLimiter(req, res, next) {
  const key = req.ip;
  const rec = attempts.get(key) || { n: 0, until: 0 };
  if (rec.until > Date.now()) return res.status(429).json({ error: 'Thử lại sau ít phút' });
  req.loginRec = rec; req.loginKey = key;
  next();
}

// ---------------------------------------------------------------- SSRF helper
function isPrivateIP(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80')) return true;
    // IPv4-mapped: dạng thập phân (::ffff:1.2.3.4) hoặc hex đã chuẩn hóa (::ffff:7f00:1)
    const dec = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (dec) return isPrivateIP(dec[1]);
    const hex = v.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16), lo = parseInt(hex[2], 16);
      return isPrivateIP(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return false;
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

// ---------------------------------------------------------------- App
function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '10kb' }));
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
    });
    next();
  });
  app.use(express.static(path.join(__dirname, 'public')));

  // ---- Đăng nhập
  app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body || {};
    const user = typeof username === 'string' && typeof password === 'string' &&
      db.users.find(u => u.username === username);
    if (!user || !checkPw(password, user.passwordHash)) {
      req.loginRec.n += 1;
      if (req.loginRec.n >= 8) { req.loginRec.until = Date.now() + 5 * 60 * 1000; req.loginRec.n = 0; }
      attempts.set(req.loginKey, req.loginRec);
      return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    }
    attempts.delete(req.loginKey);
    audit({ user, ip: req.ip }, 'LOGIN', user.role);
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '2h' });
    res.json({ token, user: publicUser(user) });
  });

  app.get('/api/me', authenticate, (req, res) => res.json({ user: publicUser(req.user) }));

  // ---- CASE 1: CWE-639 IDOR / HPP
  app.get('/api/accounts/detail', authenticate, (req, res) => {
    const acct = req.query.accountId === undefined ? req.user.accountId : req.query.accountId;
    if (typeof acct !== 'string' || !/^\d{4}$/.test(acct)) {
      audit(req, 'DENY_HPP', 'accountId không phải chuỗi 4 số');
      return res.status(400).json({ error: 'accountId không hợp lệ (CWE-639/HPP)' });
    }
    if (req.user.role === 'USER' && acct !== req.user.accountId) {
      audit(req, 'DENY_IDOR', `đọc tài khoản ${acct}`);
      return res.status(403).json({ error: 'Bạn không có quyền xem tài khoản của người khác (CWE-639)' });
    }
    const target = db.users.find(u => u.accountId === acct);
    if (!target) return res.status(404).json({ error: 'Không tìm thấy tài khoản' });
    const transactions = db.transactions.filter(t => t.fromAcct === acct || t.toAcct === acct);
    res.json({ data: publicUser(target), transactions });
  });

  // Tra cứu khách hàng: chỉ đọc, không có API sửa số dư trực tiếp cho bất kỳ vai trò nào
  app.get('/api/staff/customers', authenticate, requireRole('TELLER', 'ADMIN'), (req, res) =>
    res.json({
      data: db.users.filter(u => u.role === 'USER').map(({ accountId, fullName, tier, phone, balance, creditLimit }) =>
        ({ accountId, fullName, tier, phone, balance, creditLimit })),
    }));

  // ---- Chuyển tiền: chỉ USER, nguồn tiền luôn là tài khoản của phiên đăng nhập (SoD + CWE-639)
  app.post('/api/transactions/transfer', authenticate, requireRole('USER'), (req, res) => {
    const { fromAccountId, toAccountId, amount, memo } = req.body || {};
    if (fromAccountId !== undefined && fromAccountId !== req.user.accountId) {
      audit(req, 'DENY_IDOR', `trích tiền từ TK ${String(fromAccountId).slice(0, 20)}`);
      return res.status(403).json({ error: 'Chỉ được trích tiền từ tài khoản của chính mình (CWE-639)' });
    }
    const value = Number(amount);
    if (typeof toAccountId !== 'string' || !/^\d{4}$/.test(toAccountId)) return res.status(400).json({ error: 'Tài khoản thụ hưởng không hợp lệ' });
    if (!Number.isInteger(value) || value < 1000 || value > 500000000) return res.status(400).json({ error: 'Số tiền phải là số nguyên từ 1.000 đến 500.000.000 VNĐ' });
    const receiver = db.users.find(u => u.accountId === toAccountId && u.role === 'USER');
    if (!receiver) return res.status(404).json({ error: 'Tài khoản thụ hưởng không tồn tại' });
    if (receiver.id === req.user.id) return res.status(400).json({ error: 'Không thể chuyển tiền cho chính mình' });
    if (req.user.balance < value) return res.status(400).json({ error: 'Số dư khả dụng không đủ' });
    req.user.balance -= value;
    receiver.balance += value;
    const cleanMemo = (typeof memo === 'string' ? memo : '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 100) || `${req.user.fullName} chuyển tiền`;
    const tx = { id: `TX${++txSeq}`, date: new Date().toISOString(), fromAcct: req.user.accountId, toAcct: receiver.accountId, amount: value, memo: cleanMemo, status: 'SUCCESS' };
    db.transactions.unshift(tx);
    audit(req, 'TRANSFER', `${value} VND: ${tx.fromAcct} -> ${tx.toAcct} (${tx.id})`);
    res.status(201).json({ message: 'Chuyển tiền thành công', transaction: tx, newBalance: req.user.balance });
  });

  // ---- Khoản vay
  app.get('/api/loans', authenticate, (req, res) => {
    const list = req.user.role === 'USER' ? db.loans.filter(l => l.accountId === req.user.accountId) : db.loans;
    res.json({ data: list });
  });

  app.post('/api/loans/apply', authenticate, requireRole('USER'), (req, res) => {
    const { amount, term, purpose } = req.body || {};
    const value = Number(amount);
    if (!Number.isInteger(value) || value < 1000000 || value > 5000000000) return res.status(400).json({ error: 'Số tiền vay phải từ 1.000.000 đến 5.000.000.000 VNĐ' });
    if (!LOAN_TERMS.includes(term)) return res.status(400).json({ error: 'Kỳ hạn không hợp lệ' });
    const loan = {
      loanId: ++loanSeq, accountId: req.user.accountId, borrower: req.user.fullName, amount: value, term,
      rate: value > TELLER_LOAN_LIMIT ? '6.8%/năm' : '7.5%/năm',
      purpose: (typeof purpose === 'string' ? purpose : '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 120) || 'Vay tiêu dùng tín chấp',
      status: 'PENDING', approvedBy: null,
    };
    db.loans.unshift(loan);
    audit(req, 'LOAN_APPLY', `#${loan.loanId} ${value} VND`);
    res.status(201).json({ message: 'Đã gửi hồ sơ vay vốn', loan });
  });

  // ---- CASE 2: CWE-285/862 BFLA - khóa method + role + hạn mức phê duyệt theo cấp
  app.all('/api/admin/approve-loan', authenticate, onlyMethods('POST'), requireRole('TELLER', 'ADMIN'), (req, res) => {
    const { loanId, action = 'APPROVED' } = req.body || {};
    if (!['APPROVED', 'REJECTED'].includes(action)) return res.status(400).json({ error: 'action không hợp lệ' });
    const loan = db.loans.find(l => l.loanId === Number(loanId));
    if (!loan) return res.status(404).json({ error: 'Không tìm thấy khoản vay' });
    if (loan.status !== 'PENDING') return res.status(409).json({ error: 'Khoản vay đã được xử lý' });
    if (req.user.role === 'TELLER' && loan.amount > TELLER_LOAN_LIMIT) {
      audit(req, 'DENY_LIMIT', `loan #${loan.loanId} ${loan.amount} VND vượt hạn mức Teller`);
      return res.status(403).json({ error: 'Vượt thẩm quyền: Giao dịch viên chỉ duyệt khoản vay ≤ 100.000.000 VNĐ. Cần Giám đốc Chi nhánh phê duyệt.' });
    }
    loan.status = action;
    loan.approvedBy = `${req.user.fullName} (${req.user.role})`;
    audit(req, 'LOAN_' + action, `#${loan.loanId}`);
    res.json({ message: action === 'APPROVED' ? 'Phê duyệt đúng thẩm quyền' : 'Đã từ chối hồ sơ', loan });
  });

  // ---- CASE 3: CWE-915 Mass Assignment - allowlist DTO (fullName, phone, email)
  app.put('/api/profile/update', authenticate, (req, res) => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const { fullName, phone, email } = body;
    if (fullName !== undefined && !(typeof fullName === 'string' && fullName.trim() && fullName.length <= 80)) return res.status(400).json({ error: 'Họ tên không hợp lệ' });
    if (phone !== undefined && !(typeof phone === 'string' && /^0\d{9}$/.test(phone))) return res.status(400).json({ error: 'Số điện thoại phải gồm 10 chữ số, bắt đầu bằng 0' });
    if (email !== undefined && !(typeof email === 'string' && email.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'Email không hợp lệ' });
    if (fullName !== undefined) req.user.fullName = fullName.trim();
    if (phone !== undefined) req.user.phone = phone;
    if (email !== undefined) req.user.email = email;
    const forbidden = ['role', 'balance', 'creditLimit', 'accountId', 'tier', 'id', 'passwordHash', 'username', 'stmtFile'];
    const ignored = Object.keys(body).filter(k => forbidden.includes(k));
    if (ignored.length) audit(req, 'DENY_MASS_ASSIGN', `bỏ qua: ${ignored.join(',')}`);
    res.json({ message: 'Đã cập nhật hồ sơ (allowlist: họ tên, số điện thoại, email)', ignoredFields: ignored, updatedUser: publicUser(req.user) });
  });

  // ---- CASE 4: CWE-22 Path Traversal
  app.get('/api/statements/download', authenticate, (req, res) => {
    const file = req.query.file === undefined ? req.user.stmtFile : req.query.file;
    if (typeof file !== 'string') return res.status(400).json({ error: 'Tham số file không hợp lệ' });
    // Chỉ cho tải file gắn với chính user (tra theo DB, không dùng input làm đường dẫn)
    if (!req.user.stmtFile || file !== req.user.stmtFile) {
      audit(req, 'DENY_PATH', `file=${file.slice(0, 80)}`);
      return res.status(403).json({ error: 'Chỉ được xuất sao kê của chính mình (CWE-22)' });
    }
    const resolved = path.resolve(STATEMENT_DIR, path.basename(req.user.stmtFile));
    if (!resolved.startsWith(STATEMENT_DIR + path.sep)) return res.status(403).json({ error: 'Đường dẫn không hợp lệ' });
    const content = buildStatement(req.user);
    fs.writeFileSync(resolved, content);
    audit(req, 'STATEMENT', req.user.stmtFile);
    res.json({ fileName: req.user.stmtFile, content });
  });

  // ---- CASE 5: CWE-918 SSRF (chỉ xác thực URL, không gửi request đi)
  app.post('/api/webhooks/test', authenticate, async (req, res) => {
    const raw = req.body?.webhookUrl;
    if (typeof raw !== 'string' || raw.length > 2048) return res.status(400).json({ error: 'Thiếu hoặc sai webhookUrl' });
    let u;
    try { u = new URL(raw); } catch { return res.status(400).json({ error: 'URL không hợp lệ' }); }
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) {
      audit(req, 'DENY_SSRF', raw);
      return res.status(400).json({ error: 'Chỉ chấp nhận http/https, không kèm thông tin đăng nhập (CWE-918)' });
    }
    try {
      const host = u.hostname.replace(/^\[|\]$/g, '');
      const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
      const bad = addrs.find(a => isPrivateIP(a.address));
      if (bad) {
        audit(req, 'DENY_SSRF', `${raw} -> ${bad.address}`);
        return res.status(403).json({ error: `Chặn SSRF (CWE-918): '${u.hostname}' phân giải ra IP nội bộ ${bad.address}` });
      }
      res.json({ message: `URL hợp lệ (IP public: ${addrs.map(a => a.address).join(', ')})` });
    } catch {
      res.status(400).json({ error: 'Không phân giải được tên miền' });
    }
  });

  // ---- Quản trị
  app.get('/api/admin/users', authenticate, requireRole('ADMIN'), (req, res) => res.json({ data: db.users.map(publicUser) }));

  app.put('/api/admin/users/:id/role', authenticate, requireRole('ADMIN'), (req, res) => {
    const target = db.users.find(u => u.id === Number(req.params.id));
    const role = req.body?.role;
    if (!target) return res.status(404).json({ error: 'Không tìm thấy user' });
    if (!['USER', 'TELLER', 'ADMIN'].includes(role)) return res.status(400).json({ error: 'Role không hợp lệ' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'Không thể tự đổi quyền của chính mình' });
    target.role = role;
    res.json({ data: publicUser(target) });
  });

  app.get('/api/admin/audit', authenticate, requireRole('ADMIN'), (req, res) => res.json({ data: db.audit }));

  app.use('/api', (req, res) => res.status(404).json({ error: 'Không tìm thấy endpoint' }));
  return app;
}

seedStatements();

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  createApp().listen(PORT, () => console.log(`Mini Web Bank: http://localhost:${PORT}`));
}

module.exports = { createApp, db, DEMO_PASSWORD, isPrivateIP };
