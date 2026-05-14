/**
 * AttendX — Secure QR Attendance System
 * Backend: Node.js + Express + Supabase PostgreSQL
 *
 * Run:
 *   npm install
 *   npm start
 *
 * Required Vercel Environment Variables:
 *   SUPABASE_DB_URL = postgresql://postgres.xxxxx:[PASSWORD]@aws-xxx.pooler.supabase.com:6543/postgres
 *   HMAC_SECRET = any long random secret string
 */

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.use(express.json({ limit: '2mb' }));

// Serve your HTML/CSS files. If your files are in /public, keep /public.
// If your files are in the project root, this also allows them to load.
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

const db = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET_KEY = process.env.HMAC_SECRET || 'SUPER_SECRET_KEY_PROTOTYPE_CHANGE_ME';
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function id(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function toDateString(value) {
  if (!value) return '';
  if (typeof value === 'string') return value.slice(0, 10);
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function toTimeString(value) {
  if (!value) return '';
  return String(value).slice(0, 5);
}

function normalizeTimestamp(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return value;
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    studentId: user.student_id,
    email: user.email,
    role: user.role
  };
}

async function queryOne(sql, params = []) {
  const result = await db.query(sql, params);
  return result.rows[0];
}

async function queryAll(sql, params = []) {
  const result = await db.query(sql, params);
  return result.rows;
}

async function safeLogAudit(userId, subjectId, sessionId, action, details) {
  try {
    await db.query(
      `INSERT INTO audit_logs (id, user_id, subject_id, session_id, action, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id('log'), userId || 'system', subjectId || null, sessionId || null, action, details || '']
    );
  } catch (err) {
    console.error('Audit log failed:', err.message);
  }
}

function generateQRToken(sessionId, subjectId) {
  const payload = {
    sid: sessionId,
    sub: subjectId,
    iat: Date.now(),
    n: crypto.randomBytes(5).toString('hex')
  };

  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payloadStr)
    .digest('base64url')
    .slice(0, 32);

  return `${payloadStr}.${signature}`;
}

function verifyQRToken(token) {
  try {
    const [payloadStr, signature] = String(token || '').split('.');
    if (!payloadStr || !signature) return null;

    const expectedShort = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(payloadStr)
      .digest('base64url')
      .slice(0, 32);

    const expectedOldHex = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(payloadStr)
      .digest('hex');

    const ok = signature === expectedShort || signature === expectedOldHex;
    if (!ok) return null;

    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));

    return {
      sessionId: payload.sessionId || payload.sid,
      subjectId: payload.subjectId || payload.sub,
      created: payload.created || payload.iat,
      nonce: payload.nonce || payload.n
    };
  } catch {
    return null;
  }
}

function getDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function seedUsersIfEmpty() {
  const row = await queryOne('SELECT COUNT(*)::int AS n FROM users');
  if (row && row.n > 0) {
    console.log('✅ Supabase already has users. Seed skipped.');
    return;
  }

  const users = [
    ['u_teacher', 'Professor Minerva McGonagall', null, 'teacher@example.com', 'teacher123', 'teacher'],
    ['u_harry', 'Harry Potter', '6622701845', '6622701845@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_hermione', 'Hermione Granger', '6622703928', '6622703928@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_ron', 'Ron Weasley', '6622707461', '6622707461@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_draco', 'Draco Malfoy', '6622705139', '6622705139@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_luna', 'Luna Lovegood', '6622708256', '6622708256@g.siit.tu.ac.th', 'student123', 'student']
  ];

  for (const [userId, name, studentId, email, password, role] of users) {
    await db.query(
      `INSERT INTO users (id, name, student_id, email, password, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO NOTHING`,
      [userId, name, studentId, email, bcrypt.hashSync(password, 10), role]
    );
  }

  console.log('✅ Seeded demo teacher and student accounts into Supabase.');
}

async function createSafeIndexes() {
  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS attendance_records_session_student_unique
    ON attendance_records (session_id, student_id)
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS subjects_teacher_name_section_unique
    ON subjects (teacher_id, subject_name, section)
  `);

  await db.query('CREATE INDEX IF NOT EXISTS idx_tokens_user ON auth_tokens(user_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_subjects_teacher ON subjects(teacher_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_sessions_teacher ON sessions(teacher_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_records_session ON attendance_records(session_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_records_student ON attendance_records(student_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_logs_user ON audit_logs(user_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_logs_subject ON audit_logs(subject_id)');
  await db.query('CREATE INDEX IF NOT EXISTS idx_logs_session ON audit_logs(session_id)');
}

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const row = await queryOne(
      `SELECT u.*, t.created_at AS token_created_at
       FROM auth_tokens t
       JOIN users u ON u.id = t.user_id
       WHERE t.token = $1`,
      [token]
    );

    if (!row) return res.status(401).json({ error: 'Unauthorized' });

    if (Date.now() - Number(row.token_created_at) > TOKEN_TTL_MS) {
      await db.query('DELETE FROM auth_tokens WHERE token = $1', [token]);
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    req.user = row;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Authentication failed.' });
  }
};

const requireRole = (role) => async (req, res, next) => {
  if (req.user.role !== role) {
    await safeLogAudit(req.user.id, null, null, 'Unauthorized Access', `Tried to access ${role} route`);
    return res.status(403).json({ error: 'Access denied.' });
  }
  next();
};

async function requireTeacherSubject(req, res, next) {
  try {
    const subjectId = req.params.subjectId || req.body.subjectId;
    const subject = await queryOne(
      'SELECT * FROM subjects WHERE id = $1 AND teacher_id = $2',
      [subjectId, req.user.id]
    );
    if (!subject) return res.status(404).json({ error: 'Subject not found or access denied.' });
    req.subject = subject;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not check subject permission.' });
  }
}

async function requireTeacherSession(req, res, next) {
  try {
    const sessionId = req.params.sessionId || req.body.sessionId;
    const session = await queryOne(
      `SELECT se.*, su.subject_name, su.section
       FROM sessions se
       JOIN subjects su ON su.id = se.subject_id
       WHERE se.id = $1 AND se.teacher_id = $2`,
      [sessionId, req.user.id]
    );
    if (!session) return res.status(404).json({ error: 'Session not found or access denied.' });
    req.sessionRow = session;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not check session permission.' });
  }
}

app.get('/api/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ ok: true, database: 'supabase-postgres' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Database connection failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await queryOne('SELECT * FROM users WHERE email = $1', [String(email || '').trim()]);

    if (!user || !bcrypt.compareSync(password || '', user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = crypto.randomBytes(24).toString('hex');

    await db.query(
      'INSERT INTO auth_tokens (token, user_id, created_at) VALUES ($1, $2, $3)',
      [token, user.id, Date.now()]
    );

    await safeLogAudit(user.id, null, null, 'Login', `${user.name} logged in as ${user.role}`);

    res.json({ token, role: user.role, name: user.name, user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  try {
    await db.query('DELETE FROM auth_tokens WHERE token = $1', [req.headers.authorization]);
    await safeLogAudit(req.user.id, null, null, 'Logout', `${req.user.name} logged out`);
    res.json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Logout failed.' });
  }
});

app.get('/api/me', authenticate, (req, res) => res.json(publicUser(req.user)));
app.get('/api/teacher/profile', authenticate, requireRole('teacher'), (req, res) => res.json(publicUser(req.user)));
app.get('/api/student/profile', authenticate, requireRole('student'), (req, res) => res.json(publicUser(req.user)));

// Self-registration is intentionally disabled for this prototype.
app.post('/api/register', (req, res) => {
  res.status(403).json({ error: 'Student self-registration is disabled. Accounts are created by the institution.' });
});

app.get('/api/teacher/subjects', authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const subjects = await queryAll(
      `SELECT s.*,
        (SELECT COUNT(*)::int FROM sessions WHERE subject_id = s.id) AS session_count
       FROM subjects s
       WHERE s.teacher_id = $1
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    res.json({ subjects });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load subjects.' });
  }
});

app.post('/api/teacher/subjects', authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const subjectName = String(req.body.subjectName || '').trim();
    const section = String(req.body.section || '').trim();

    if (!subjectName || !section) {
      return res.status(400).json({ error: 'Subject name and section are required.' });
    }

    const existing = await queryOne(
      'SELECT id FROM subjects WHERE teacher_id = $1 AND subject_name = $2 AND section = $3',
      [req.user.id, subjectName, section]
    );

    if (existing) {
      return res.status(409).json({ error: 'This subject and section already exists.' });
    }

    const subjectId = id('subj');

    const subject = await queryOne(
      `INSERT INTO subjects (id, teacher_id, subject_name, section)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [subjectId, req.user.id, subjectName, section]
    );

    await safeLogAudit(req.user.id, subjectId, null, 'Create Subject', `Created ${subjectName} Section ${section}`);
    res.status(201).json(subject);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not create subject.' });
  }
});

app.get('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, async (req, res) => {
  try {
    const sessions = await queryAll(
      `SELECT *
       FROM sessions
       WHERE subject_id = $1 AND teacher_id = $2
       ORDER BY session_date DESC, start_time DESC`,
      [req.subject.id, req.user.id]
    );

    res.json({ subject: req.subject, sessions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load sessions.' });
  }
});

app.post('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, async (req, res) => {
  try {
    const { sessionDate, startTime, endTime, classroomLat, classroomLng, allowedRadius } = req.body;

    if (!sessionDate || !startTime || !endTime || classroomLat == null || classroomLng == null || !allowedRadius) {
      return res.status(400).json({ error: 'Date, start time, end time, location, and allowed radius are required.' });
    }

    const start = new Date(`${sessionDate}T${startTime}`);
    const end = new Date(`${sessionDate}T${endTime}`);

    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
      return res.status(400).json({ error: 'Invalid date/time. End time must be after start time.' });
    }

    const radius = parseInt(allowedRadius, 10);
    if (!Number.isFinite(radius) || radius <= 0) {
      return res.status(400).json({ error: 'Allowed radius must be a positive number.' });
    }

    const lat = parseFloat(classroomLat);
    const lng = parseFloat(classroomLng);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ error: 'Valid classroom latitude and longitude are required.' });
    }

    const sessionId = id('sess');
    const qrToken = generateQRToken(sessionId, req.subject.id);

    const session = await queryOne(
      `INSERT INTO sessions
        (id, subject_id, teacher_id, session_date, start_time, end_time, qr_token, classroom_lat, classroom_lng, allowed_radius)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [sessionId, req.subject.id, req.user.id, sessionDate, startTime, endTime, qrToken, lat, lng, radius]
    );

    await safeLogAudit(
      req.user.id,
      req.subject.id,
      sessionId,
      'Create QR Session',
      `Created QR session for ${req.subject.subject_name} Section ${req.subject.section} on ${sessionDate}`
    );

    res.status(201).json({
      id: session.id,
      subjectId: req.subject.id,
      qrToken: session.qr_token,
      sessionDate: toDateString(session.session_date),
      startTime: toTimeString(session.start_time),
      endTime: toTimeString(session.end_time)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not create session.' });
  }
});

app.get('/api/teacher/sessions/:sessionId/attendance', authenticate, requireRole('teacher'), requireTeacherSession, async (req, res) => {
  try {
    const rows = await queryAll(
      `SELECT
        u.id AS user_id,
        u.student_id,
        u.name,
        u.email,
        ar.submit_time,
        ar.distance_meters,
        ar.status,
        ar.warning_message
       FROM users u
       LEFT JOIN attendance_records ar
         ON ar.student_id = u.id AND ar.session_id = $1
       WHERE u.role = 'student'
       ORDER BY u.student_id ASC`,
      [req.sessionRow.id]
    );

    const attendance = rows.map((r) => ({
      userId: r.user_id,
      studentId: r.student_id,
      name: r.name,
      email: r.email,
      status: r.submit_time ? 'Checked' : 'Not Checked',
      submitTime: normalizeTimestamp(r.submit_time),
      distanceMeters: r.distance_meters,
      warning: r.warning_message || 'No'
    }));

    res.json({ session: req.sessionRow, attendance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load attendance.' });
  }
});

app.get('/api/teacher/audit-logs', authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const logs = await queryAll(
      `SELECT l.*, u.name AS user_name, u.role, su.subject_name, su.section
       FROM audit_logs l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN subjects su ON su.id = l.subject_id
       WHERE
         l.user_id = $1
         OR l.subject_id IN (SELECT id FROM subjects WHERE teacher_id = $2)
         OR l.session_id IN (SELECT id FROM sessions WHERE teacher_id = $3)
       ORDER BY l.created_at DESC
       LIMIT 200`,
      [req.user.id, req.user.id, req.user.id]
    );

    res.json({ logs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load audit logs.' });
  }
});

app.post('/api/student/submit-attendance', authenticate, requireRole('student'), async (req, res) => {
  try {
    const { qrToken, latitude, longitude } = req.body;
    const payload = verifyQRToken(qrToken);

    if (!payload) {
      await safeLogAudit(req.user.id, null, null, 'Submit Attendance Rejected', 'Invalid or fake QR token');
      return res.status(400).json({ status: 'Rejected', message: 'Invalid QR token.' });
    }

    const session = await queryOne(
      `SELECT se.*, su.subject_name, su.section
       FROM sessions se
       JOIN subjects su ON su.id = se.subject_id
       WHERE se.id = $1 AND se.subject_id = $2`,
      [payload.sessionId, payload.subjectId]
    );

    if (!session) {
      return res.status(400).json({ status: 'Rejected', message: 'Session not found.' });
    }

    const sessionDate = toDateString(session.session_date);
    const startTime = toTimeString(session.start_time);
    const endTime = toTimeString(session.end_time);

    const now = new Date();
    const start = new Date(`${sessionDate}T${startTime}`);
    const end = new Date(`${sessionDate}T${endTime}`);

    if (now < start || now > end) {
      await safeLogAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance Rejected', 'Attendance session is closed or expired');
      return res.status(400).json({ status: 'Rejected', message: 'Attendance session is not open now.' });
    }

    const duplicate = await queryOne(
      'SELECT id FROM attendance_records WHERE session_id = $1 AND student_id = $2',
      [session.id, req.user.id]
    );

    if (duplicate) {
      await safeLogAudit(req.user.id, session.subject_id, session.id, 'Duplicate Attendance Attempt', `${req.user.name} tried to submit again`);
      return res.status(400).json({ status: 'Rejected', message: 'You already checked attendance for this session.' });
    }

    const lat = parseFloat(latitude);
    const lng = parseFloat(longitude);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ status: 'Rejected', message: 'Location permission is required for attendance verification.' });
    }

    const distance = getDistance(session.classroom_lat, session.classroom_lng, lat, lng);

    let status = 'Checked';
    let warning = 'No';

    if (distance > session.allowed_radius) {
      status = 'Checked with Warning';
      warning = `Far location (${Math.round(distance)}m away)`;
      await safeLogAudit(req.user.id, session.subject_id, session.id, 'Far Location Warning', `${req.user.name} checked in ${Math.round(distance)}m away`);
    } else {
      await safeLogAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance', `${req.user.name} checked in successfully`);
    }

    const recordId = id('rec');

    await db.query(
      `INSERT INTO attendance_records
        (id, session_id, student_id, submit_time, latitude, longitude, distance_meters, status, warning_message)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [recordId, session.id, req.user.id, new Date().toISOString(), lat, lng, Math.round(distance), status, warning]
    );

    res.json({
      id: recordId,
      subjectName: session.subject_name,
      section: session.section,
      status,
      warningMessage: warning,
      distanceMeters: Math.round(distance)
    });
  } catch (err) {
    console.error(err);

    if (err.code === '23505') {
      return res.status(400).json({ status: 'Rejected', message: 'You already checked attendance for this session.' });
    }

    res.status(500).json({ status: 'Rejected', message: 'Could not submit attendance.' });
  }
});

app.get('/api/student/my-attendance', authenticate, requireRole('student'), async (req, res) => {
  try {
    const records = await queryAll(
      `SELECT ar.*, se.session_date, se.start_time, se.end_time, su.subject_name, su.section
       FROM attendance_records ar
       JOIN sessions se ON se.id = ar.session_id
       JOIN subjects su ON su.id = se.subject_id
       WHERE ar.student_id = $1
       ORDER BY ar.submit_time DESC`,
      [req.user.id]
    );

    res.json({ records });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load attendance history.' });
  }
});

// Backward compatible alias for old pages/tools.
app.get('/api/student/dashboard', authenticate, requireRole('student'), async (req, res) => {
  try {
    const records = await queryAll(
      `SELECT ar.*, su.subject_name, su.section
       FROM attendance_records ar
       JOIN sessions se ON se.id = ar.session_id
       JOIN subjects su ON su.id = se.subject_id
       WHERE ar.student_id = $1
       ORDER BY ar.submit_time DESC`,
      [req.user.id]
    );

    res.json({ records });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load dashboard.' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    if (!process.env.SUPABASE_DB_URL) {
      console.warn('⚠️ SUPABASE_DB_URL is missing. Add it in Vercel Environment Variables.');
    }

    await db.query('SELECT 1');
    console.log('✅ Connected to Supabase PostgreSQL.');

    await createSafeIndexes();
    await seedUsersIfEmpty();

    app.listen(PORT, () => {
      console.log(`\n🎓 AttendX server running → http://localhost:${PORT}`);
      console.log('🔐 Demo teacher: teacher@example.com / teacher123');
      console.log('🧑‍🎓 Demo student: 6622701845@g.siit.tu.ac.th / student123\n');
    });
  } catch (err) {
    console.error('❌ Server startup failed:', err);
    process.exit(1);
  }
}

startServer();
