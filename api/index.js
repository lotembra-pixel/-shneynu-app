'use strict';
const express = require('express');
const admin   = require('firebase-admin');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json({ limit: '512kb' }));

// ── Firebase Admin init ──────────────────────────────────────────────────────
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    }),
  });
}
const db   = admin.firestore();
const auth = admin.auth();

// ── Rate limiting ────────────────────────────────────────────────────────────
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));

// ── CORS (same-origin on Vercel, needed for local dev) ──────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Input validation helper ──────────────────────────────────────────────────
function validate(body, rules) {
  for (const [field, rule] of Object.entries(rules)) {
    const val = body[field];
    if (rule.required && (val === undefined || val === null || String(val).trim() === ''))
      return `שדה חסר: ${field}`;
    if (val !== undefined) {
      if (rule.type && typeof val !== rule.type) return `שדה ${field} לא תקין`;
      if (rule.maxLength && typeof val === 'string' && val.length > rule.maxLength)
        return `שדה ${field} ארוך מדי (מקסימום ${rule.maxLength})`;
      if (field === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val))
        return 'כתובת אימייל לא תקינה';
      if (field === 'week' && (val < 1 || val > 42)) return 'מספר שבוע לא תקין';
    }
  }
  return null;
}

// ── Auth middleware ──────────────────────────────────────────────────────────
async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'נדרשת התחברות' });
  try {
    req.user = await auth.verifyIdToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'אסימון לא תקף — אנא התחברי מחדש' });
  }
}

// ── Firestore sign-in helper (REST) — gets an idToken server-side ────────────
async function signInWithPassword(email, password) {
  const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, returnSecureToken: true }),
  });
  const data = await r.json();
  if (!r.ok) {
    const msgs = {
      WRONG_PASSWORD:                'הסיסמה שגויה',
      EMAIL_NOT_FOUND:               'המשתמשת לא נמצאה',
      INVALID_EMAIL:                 'כתובת האימייל אינה תקינה',
      INVALID_LOGIN_CREDENTIALS:     'אימייל או סיסמה שגויים',
      USER_DISABLED:                 'החשבון הושהה',
      TOO_MANY_ATTEMPTS_TRY_LATER:   'יותר מדי ניסיונות — נסי שוב מאוחר יותר',
    };
    const code = (data.error?.message || '').split(' : ')[0];
    throw new Error(msgs[code] || 'אימייל או סיסמה שגויים');
  }
  return data; // { idToken, localId, email, displayName, ... }
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  const err = validate(req.body, {
    name:     { required: true,  type: 'string', maxLength: 100 },
    email:    { required: true,  type: 'string', maxLength: 200 },
    password: { required: true,  type: 'string', maxLength: 128 },
  });
  if (err) return res.status(400).json({ error: err });
  if (password.length < 6) return res.status(400).json({ error: 'הסיסמה חלשה מדי (לפחות 6 תווים)' });

  try {
    const userRecord = await auth.createUser({ email, password, displayName: name });
    await db.collection('users').doc(userRecord.uid).set({
      fullName: name, email,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    const tokenData = await signInWithPassword(email, password);
    res.json({ token: tokenData.idToken, uid: userRecord.uid, fullName: name, email });
  } catch (e) {
    const msgs = {
      'auth/email-already-exists': 'האימייל כבר רשום — נסי להתחבר',
      'auth/invalid-email':        'כתובת האימייל אינה תקינה',
      'auth/weak-password':        'הסיסמה חלשה מדי',
    };
    res.status(400).json({ error: msgs[e.code] || e.message || 'שגיאה ביצירת החשבון' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const err = validate(req.body, {
    email:    { required: true, type: 'string', maxLength: 200 },
    password: { required: true, type: 'string', maxLength: 128 },
  });
  if (err) return res.status(400).json({ error: err });

  try {
    const tokenData = await signInWithPassword(email, password);
    const docSnap   = await db.collection('users').doc(tokenData.localId).get();
    const profile   = docSnap.exists ? docSnap.data() : {};
    res.json({
      token:    tokenData.idToken,
      uid:      tokenData.localId,
      fullName: profile.fullName || tokenData.displayName || email.split('@')[0],
      email,
      ...profile,
    });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PROFILE ROUTES
// ════════════════════════════════════════════════════════════════════════════

const ALLOWED_PROFILE_FIELDS = [
  'fullName','fund','doctor','clinic','dueDate','babies','firstPreg',
  'partner','pName','pContact','diet','reminder','weight','height',
  'partnerEmail','partnerName','partnerUid','currentWeek',
  'idnum','phone','bloodtype','allergies','prevpreg',
  'ecname','ecphone','birthpref',
];

app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.user.uid).get();
    if (!doc.exists) return res.json({});
    const data = doc.data();
    try {
      const med = await db.collection('users').doc(req.user.uid)
        .collection('medical').doc('private').get();
      if (med.exists) Object.assign(data, med.data());
    } catch {}
    res.json(data);
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת הפרופיל' });
  }
});

app.put('/api/profile', authenticate, async (req, res) => {
  const publicData = {};
  for (const k of ALLOWED_PROFILE_FIELDS) {
    if (req.body[k] !== undefined) publicData[k] = req.body[k];
  }
  const { conds, meds } = req.body;
  try {
    await db.collection('users').doc(req.user.uid).set(
      { ...publicData, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true }
    );
    if (conds !== undefined || meds !== undefined) {
      await db.collection('users').doc(req.user.uid)
        .collection('medical').doc('private')
        .set({ conds, meds }, { merge: true });
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירת הפרופיל' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// METRICS ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/metrics', authenticate, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const doc   = await db.collection('users').doc(req.user.uid)
      .collection('metrics').doc(today).get();
    res.json(doc.exists ? doc.data() : {});
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת מדדים' });
  }
});

app.put('/api/metrics', authenticate, async (req, res) => {
  const { w, b, k, d, medDone, week } = req.body;
  const data = {};
  if (typeof w      === 'string')  data.w       = w.slice(0, 20);
  if (typeof b      === 'string')  data.b       = b.slice(0, 20);
  if (typeof k      === 'string')  data.k       = k.slice(0, 10);
  if (typeof d      === 'string')  data.d       = d.slice(0, 10);
  if (typeof medDone === 'boolean') data.medDone = medDone;
  if (typeof week    === 'number' && week >= 1 && week <= 42) data.week = week;

  try {
    const today = new Date().toISOString().split('T')[0];
    await db.collection('users').doc(req.user.uid)
      .collection('metrics').doc(today)
      .set(data, { merge: true });
    // Mirror current week to profile for partner visibility
    if (data.week) {
      await db.collection('users').doc(req.user.uid)
        .set({ currentWeek: data.week }, { merge: true });
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירת מדדים' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// JOURNAL ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/journal', authenticate, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.user.uid)
      .collection('journal').orderBy('id', 'desc').limit(20).get();
    res.json(snap.docs.map(d => d.data()));
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת יומן' });
  }
});

app.post('/api/journal', authenticate, async (req, res) => {
  const err = validate(req.body, {
    text: { required: true, type: 'string', maxLength: 5000 },
    time: { required: true, type: 'string', maxLength: 10  },
    week: { required: true, type: 'number'                 },
  });
  if (err) return res.status(400).json({ error: err });

  const { text, time, week } = req.body;
  const id = Date.now();
  try {
    await db.collection('users').doc(req.user.uid)
      .collection('journal').doc(String(id))
      .set({ id, text, time, week });
    res.json({ ok: true, id });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירת יומן' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PARTNER ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/partner/invite', authenticate, async (req, res) => {
  const err = validate(req.body, {
    toContact: { required: true, type: 'string', maxLength: 200 },
    toName:    {               type: 'string', maxLength: 100 },
  });
  if (err) return res.status(400).json({ error: err });

  const { toContact, toName } = req.body;
  const key = toContact.replace(/[.@+]/g, '_');

  try {
    const userDoc  = await db.collection('users').doc(req.user.uid).get();
    const fromName = userDoc.exists ? (userDoc.data().fullName || '') : '';

    await db.collection('partnerInvites').doc(key).set({
      fromUid:   req.user.uid,
      fromName,
      fromEmail: req.user.email || '',
      toContact,
      toName:    toName || '',
      week:      (typeof req.body.week === 'number') ? req.body.week : 0,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    await db.collection('users').doc(req.user.uid).set(
      { partnerEmail: toContact, partnerName: toName || toContact },
      { merge: true }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'שגיאה בשליחת הזמנה' });
  }
});

app.get('/api/partner/check', authenticate, async (req, res) => {
  const email = req.user.email || '';
  const key   = email.replace(/[.@+]/g, '_');
  try {
    const invDoc = await db.collection('partnerInvites').doc(key).get();
    if (invDoc.exists) {
      const inv = invDoc.data();
      // Bi-directional link
      await db.collection('users').doc(req.user.uid).set(
        { partnerUid: inv.fromUid, partnerName: inv.fromName, partnerEmail: inv.fromEmail },
        { merge: true }
      );
      if (inv.fromUid) {
        const myDoc  = await db.collection('users').doc(req.user.uid).get();
        const myName = myDoc.exists ? (myDoc.data().fullName || '') : '';
        await db.collection('users').doc(inv.fromUid).set(
          { partnerUid: req.user.uid, partnerName: myName, partnerEmail: email },
          { merge: true }
        );
      }
      return res.json({ partner: { fullName: inv.fromName, email: inv.fromEmail, uid: inv.fromUid } });
    }
    // Check existing link on profile
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (userDoc.exists && userDoc.data().partnerName) {
      const d = userDoc.data();
      return res.json({ partner: { fullName: d.partnerName, email: d.partnerEmail || '', uid: d.partnerUid || '' } });
    }
    res.json({ partner: null });
  } catch {
    res.status(500).json({ error: 'שגיאה בבדיקת שותף' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// SCAN ROUTES
// ════════════════════════════════════════════════════════════════════════════

function generateMockResults(week, filename) {
  const w = Math.min(Math.max(parseInt(week) || 14, 1), 42);
  const tri = w <= 13 ? 1 : w <= 26 ? 2 : 3;

  const rand = (base, spread) =>
    Math.round((base + (Math.random() - 0.5) * spread * 2) * 10) / 10;

  // Values drift slightly per trimester to feel realistic
  const hgb       = rand(tri === 1 ? 11.9 : tri === 2 ? 11.3 : 10.9, 0.8);
  const ferritin  = rand(tri === 1 ? 26   : tri === 2 ? 19   : 15,   5);
  const vitD      = rand(tri === 1 ? 36   : 32,                       6);
  const glucose   = rand(4.6,                                          0.4);
  const platelets = rand(225,                                          25);
  const tsh       = rand(tri === 1 ? 1.8  : 2.1,                      0.5);

  const rows = [
    { label:'המוגלובין',   val:`${hgb} g/dL`,       range:'11–16',     ok: hgb >= 11,                              icon:'🩸' },
    { label:'פריטין',      val:`${ferritin} µg/L`,   range:'15–200',    ok: ferritin >= 15,                         icon: ferritin < 15 ? '⚠️' : '✅' },
    { label:'ויטמין D',    val:`${vitD} ng/mL`,      range:'30–100',    ok: vitD >= 30,                             icon:'☀️' },
    { label:'גלוקוז',      val:`${glucose} mmol/L`,  range:'3.9–5.5',   ok: glucose >= 3.9 && glucose <= 5.5,       icon:'💙' },
    { label:'טסיות דם',    val:`${platelets} K/µL`,  range:'150–400',   ok: platelets >= 150 && platelets <= 400,   icon:'🔬' },
    { label:'TSH (בלוטה)', val:`${tsh} mIU/L`,       range:'0.1–2.5',   ok: tsh >= 0.1 && tsh <= 2.5,              icon:'🦋' },
    { label:'מדד התבלינים',val:'תקין 100%',          range:'תקין',      ok: true,                                   icon:'🧂' },
  ];

  const warnings = rows.filter(r => !r.ok).map(r => r.label);
  const summary  = ['רוב הערכים תקינים ומאוזנים 🌟'];
  if (warnings.includes('פריטין'))   summary.push('הפריטין (ברזל) מעט בגבול התחתון — שוחחי עם הרופאה');
  if (warnings.includes('ויטמין D')) summary.push('ויטמין D מעט נמוך — שקלי תוסף לאחר התייעצות');
  if (warnings.includes('TSH (בלוטה)')) summary.push('TSH מחוץ לטווח — חשוב לעדכן את הרופאה');
  summary.push('מדד התבלינים מצוין לשלב ההריון ✨');

  return { rows, summary, warnings, week: w, filename: filename || 'בדיקת דם' };
}

app.post('/api/scan', authenticate, async (req, res) => {
  const err = validate(req.body, {
    week:     { required: true, type: 'number' },
    filename: { type: 'string', maxLength: 200 },
  });
  if (err) return res.status(400).json({ error: err });

  const { week, filename } = req.body;
  const results  = generateMockResults(week, filename);
  const scanId   = Date.now();

  try {
    await db.collection('users').doc(req.user.uid)
      .collection('scans').doc(String(scanId))
      .set({
        id: scanId,
        filename:  results.filename,
        week,
        rows:      results.rows,
        summary:   results.summary,
        warnings:  results.warnings,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
  } catch { /* non-fatal */ }

  res.json({ ok: true, id: scanId, ...results });
});

app.get('/api/scan/history', authenticate, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.user.uid)
      .collection('scans').orderBy('id', 'desc').limit(10).get();
    res.json(snap.docs.map(d => d.data()));
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת היסטוריית סריקות' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// CHAT ROUTE
// ════════════════════════════════════════════════════════════════════════════

const CHAT_KB = [
  { kw:['בחילה','בחילות'],          ans:'כשיש בחילות — קחי את הרכיב הסודי עם אוכל קל 🥐 שתי כוס מים קרים לפני הנטילה עוזרת לספיגה. אם הבחילה חזקה — שוחחי עם הרופאה על שינוי שעת הנטילה 💛' },
  { kw:['אכ','לאכ','אוכ','מאכ'],   ans:'שליש שני הוא הזמן הכי טוב ✨ מומלץ: אגוזים, טחינה (ברזל ❤️), סלמון (אומגה 3), ירקות כתומים, לחם מחיטה מלאה. הגוף צריך ברזל, סידן וחומצה פולית.' },
  { kw:['ויטמין'],                  ans:'ויטמינים חשובים 💊 חומצה פולית (עלים ירוקים), ברזל (עדשים, בשר), סידן (מוצרי חלב), ויטמין D (שמש וסלמון), אומגה 3. שוחחי עם הרופאה על ויטמינים מותאמים.' },
  { kw:['נשימ','הרגע','רגוע'],      ans:'תרגיל 4-7-8: שאפי 4 שניות 🌬️, החזיקי 7, נשפי לאט 8 שניות. חזרי 4 פעמים. מרגיע את מערכת העצבים ועוזר גם לתינוקת/ון 💛' },
  { kw:['חרד','לחץ','מתח','פחד'],   ans:'חרדה בהריון היא נורמלית לגמרי 💛 נסי: נשימות עמוקות, הליכה קצרה, שיחה עם מישהי קרובה, יוגה להריון. אם מרגישה מוצפת — שוחחי עם הרופאה.' },
  { kw:['שינה','לישון','עייפ'],     ans:'שינה טובה חיונית 🌙 ישני על הצד השמאלי (עוזר לזרימת דם), השתמשי בכרית הריון, שמרי על שגרת שינה קבועה. הימנעי מקפאין אחרי 14:00.' },
  { kw:['כאב'],                     ans:'כאבים קלים הם לרוב נורמליים ✨ לכאבים חזקים, חדים, מלווים בדימום, או כאב ראש עז — פני לרופאה מיד ⚕️' },
  { kw:['משקל','עלייה'],            ans:'עלייה במשקל היא תהליך טבעי 💛 בשליש שני-שלישי: 0.4-0.5 ק"ג לשבוע. שוחחי עם הרופאה על היעד האישי שלך.' },
  { kw:['ברזל','אנמי'],             ans:'ברזל חשוב מאוד 🩸 מזונות עשירים: עדשים, תרד, בשר בקר, טחינה, אגוזי קשיו. לספיגה טובה — אכלי עם ויטמין C (לימון, תפוז). הימנעי מקפה/תה בסמוך.' },
  { kw:['פעיל','ספורט','תרגיל'],   ans:'פעילות מתונה מומלצת 🏃‍♀️ הליכה, שחייה, יוגה להריון — מצוינות. הימנעי מפעילות עצימה אחרי שבוע 20. הקשיבי לגוף שלך.' },
  { kw:['בעיט','תנוע','תינוק זז'],  ans:'בעיטות התינוק הן סימן מצוין 🥰 מרגישים אותן משבוע 18-25. מומלץ לספור 10 תנועות תוך שעתיים. פחות מהרגיל — ספרי לרופאה.' },
  { kw:['שליש'],                    ans:'כל שליש עולם בפני עצמו ✨ שליש ראשון (1-13): גיבוש האיברים. שליש שני (14-26): "הזהב" — הכי נוח. שליש שלישי (27-40): הכנה ללידה.' },
  { kw:['לידה','לחייה'],            ans:'כדאי להתכונן ללידה 🏥 שקלי לרשום לקורס לידה, הכיני תיק לידה (משבוע 35), שוחחי עם הרופאה על תוכנית הלידה שלך.' },
  { kw:['הנקה','שדה'],              ans:'הנקה היא חוויה מיוחדת 🍼 כדאי ללמוד עליה מראש — קורס הכנה להנקה יכול לעזור מאוד. יש יועצות הנקה שזמינות גם לאחר הלידה.' },
  { kw:['סוכרת','גלוקוז','סוכר'],   ans:'בדיקת סוכרת הריון (GDH) מתבצעת בשבוע 24-28 🩸 אם אובחנה סוכרת הריון — דיאטה מותאמת, ניטור עצמי ומעקב רפואי הדוק הם המפתח.' },
  { kw:['לחץ דם'],                  ans:'לחץ דם תקין בהריון הוא 120/80 או פחות 💊 לחץ דם גבוה (מעל 140/90) יש לדווח לרופאה מיד — יכול להיות סימן לפרה-אקלמפסיה.' },
  { kw:['בחוק','חוקת','עצירות'],    ans:'עצירות שכיחה בהריון 🌿 נסי: שתיית הרבה מים, סיבים תזונתיים (פירות, ירקות, קטניות), הליכות קצרות. שוחחי עם הרופאה לפני כל תרופה.' },
];

function chatAnswer(question) {
  const q = question.toLowerCase();
  for (const { kw, ans } of CHAT_KB) {
    if (kw.some(k => q.includes(k))) return ans;
  }
  return 'שאלה מצוינת 💛 כדי לתת לך תשובה מדויקת ואישית — שוחחי עם הרופאה המטפלת שלך שמכירה את הפרטים האישיים שלך.';
}

app.post('/api/chat', authenticate, async (req, res) => {
  const err = validate(req.body, {
    question: { required: true, type: 'string', maxLength: 500 },
  });
  if (err) return res.status(400).json({ error: err });

  const answer = chatAnswer(req.body.question);

  // Save to chat history (fire-and-forget)
  db.collection('users').doc(req.user.uid).collection('chat').add({
    question: req.body.question,
    answer,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  }).catch(() => {});

  res.json({ answer });
});

// ── Partner data ──────────────────────────────────────────────────────────────
app.get('/api/partner/data', authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists) return res.json({ partner: null });
    const { partnerUid } = userDoc.data();
    if (!partnerUid) return res.json({ partner: null });

    const partnerDoc = await db.collection('users').doc(partnerUid).get();
    if (!partnerDoc.exists) return res.json({ partner: null });
    const d = partnerDoc.data();

    // Load medications
    let meds = '';
    try {
      const medDoc = await db.collection('users').doc(partnerUid)
        .collection('medical').doc('private').get();
      if (medDoc.exists) meds = medDoc.data().meds || '';
    } catch {}

    // Load latest scan results
    let latestScan = null;
    try {
      const scanSnap = await db.collection('users').doc(partnerUid)
        .collection('scans').orderBy('id', 'desc').limit(1).get();
      if (!scanSnap.empty) latestScan = scanSnap.docs[0].data();
    } catch {}

    res.json({
      partner: {
        fullName:    d.fullName     || '',
        currentWeek: d.currentWeek || 14,
        fund:        d.fund         || '',
        doctor:      d.doctor       || '',
        dueDate:     d.dueDate      || '',
        babies:      d.babies       || '',
        meds:        meds,
        latestScan:  latestScan,
      },
    });
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת נתוני שותף' });
  }
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use('/api', (_req, res) => res.status(404).json({ error: 'נתיב לא נמצא' }));

// Export for Vercel (serverless) and local dev
module.exports = app;
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
}
