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
  { kw:['בחילה','בחילות','בחיל'],   ans:'כשיש בחילות — קחי את הרכיב הסודי עם אוכל קל 🥐 שתי כוס מים קרים לפני הנטילה עוזרת לספיגה. ג\'ינג\'ר (תה, סוכריות) ידועה כמסייעת. אכלי ארוחות קטנות ותכופות ולא על בטן ריקה.' },
  { kw:['אכ','לאכ','אוכ','מאכ','תזונה','דיאטה'], ans:'תזונה מצוינת בהריון ✨ מומלץ: אגוזים, טחינה (ברזל ❤️), סלמון (אומגה 3), ירקות כתומים, לחם מחיטה מלאה, קטניות, ביצים. הגוף צריך ברזל, סידן, חומצה פולית ואומגה 3. הימנעי מגבינות רכות לא מפוסטרות ודגים גדולים (טונה גדולה, חרב).' },
  { kw:['ויטמין','תוסף'],           ans:'ויטמינים חשובים 💊 חומצה פולית מונעת מומים (חיונית בשליש ראשון), ברזל (עדשים, בשר, תרד), סידן (מוצרי חלב, טחינה), ויטמין D (שמש 15 דק\' ביום, סלמון), אומגה 3 (דגים, אגוזי מלך). ויטמין B12 חשוב לצמחוניות.' },
  { kw:['נשימ','הרגע','רגוע','מדיטציה'], ans:'תרגיל נשימה 4-7-8 🌬️ שאפי 4 שניות, החזיקי 7, נשפי לאט 8 שניות. חזרי 4 פעמים. מרגיע את מערכת העצבים. אפשר גם: מדיטציית מיינדפולנס 10 דקות, יוגה להריון, או הליכה בטבע.' },
  { kw:['חרד','לחץ','מתח','פחד','דכאון'], ans:'רגשות מעורבים בהריון — נורמלי לגמרי 💛 נסי: נשימות עמוקות, הליכה קצרה, שיחה עם מישהי קרובה, יוגה להריון, כתיבת יומן. תמיכה רגשית חשובה לא פחות מהפיזית. אם מרגישה מוצפת לאורך זמן — יש מי שיכולה לעזור.' },
  { kw:['שינה','לישון','עייפ','עייפות'], ans:'שינה טובה חיונית 🌙 ישני על הצד השמאלי (עוזר לזרימת דם לתינוק), השתמשי בכרית הריון בין הברכיים, שמרי על שגרת שינה קבועה. הימנעי מקפאין אחרי 14:00. עייפות קיצונית בשליש ראשון ושלישי היא נורמלית לחלוטין.' },
  { kw:['גב','עמוד שדרה','כאב גב'], ans:'כאבי גב שכיחים מאוד בהריון 💛 נסי: כרית גב בישיבה, שכיבה על הצד השמאלי עם כרית בין הברכיים, הליכות קצרות, יוגה להריון. חממי עם שקית מים חמים. אם הכאב חזק מאוד או קורן לרגל — שוחח עם הרופאה.' },
  { kw:['ראש','כאב ראש','מיגרנה'], ans:'כאבי ראש בהריון נפוצים 💛 שתי מים רבים (8+ כוסות ביום), מנוחה בחדר חשוך, קומפרס קר על המצח. ניתן לקחת פרמול — לא אספירין ולא איבופרופן. לכאב ראש חזק פתאומי עם נפיחות בפנים — פני לרופאה.' },
  { kw:['נפיח','בצקת','רגל','קרסול'], ans:'נפיחות ברגליים שכיחה בשליש שני ושלישי 💛 העלי את הרגליים, הימנעי מישיבה ממושכת (קום כל שעה), לבשי גרביים תומכות, שתי מים מרובה. קירור עם מים קרים עוזר. נפיחות פתאומית בפנים — פני לרופאה.' },
  { kw:['שתן','שלפוחית','דלקת','צריבה'], ans:'דלקת שתן שכיחה בהריון ⚕️ שתי הרבה מים, הימנעי מחזקות. אם יש כאב/צריבה בשתן, חום, או כאב גב תחתון — פני לרופאה לטיפול אנטיביוטי מתאים להריון. לא לחכות — עלולה להסתבך.' },
  { kw:['כאב'],                     ans:'כאבים קלים ומשיכות קלות הם לרוב נורמליים בהריון ✨ הרחם גדל ורצועות מתמתחות. כאבים חזקים, חדים, מלווים בדימום, חום, או כאב ראש עז — פני לרופאה מיד ⚕️' },
  { kw:['משקל','עלייה במשקל'],       ans:'עלייה במשקל בהריון — תהליך טבעי ובריא 💛 שליש ראשון: 1-2 ק"ג. שליש שני-שלישי: 0.4-0.5 ק"ג לשבוע. סה"כ: 11-16 ק"ג (תלוי במשקל ההתחלתי). אל תצמצמי קלוריות — הגוף שלך עובד קשה!' },
  { kw:['ברזל','אנמי','פריטין','המוגלובין'], ans:'ברזל חשוב מאוד בהריון 🩸 מזונות עשירים: עדשים, תרד, בשר בקר, טחינה, אגוזי קשיו. לספיגה טובה — אכלי עם ויטמין C (לימון, פלפל, תפוז). הימנעי מקפה/תה שעה לפני ואחרי נטילת ברזל. אנמיה — שכיחה ומטופלת בקלות.' },
  { kw:['פעיל','ספורט','תרגיל','כושר'], ans:'פעילות גופנית מומלצת 🏃‍♀️ הליכה (30 דקות), שחייה, יוגה להריון, פילאטיס להריון — מצוינות! מסייעות לגב, מצב הרוח, הכנה ללידה. הימנעי מספורט עצים עם סיכון נפילה. הקשיבי לגוף שלך.' },
  { kw:['בעיט','תנוע','תינוק זז','עיטות'], ans:'בעיטות התינוק הן סימן מצוין 🥰 מרגישים אותן משבוע 18-25. משבוע 28 — מומלץ לספור 10 תנועות תוך שעתיים פעם ביום. פחות תנועה מהרגיל — שכבי על הצד ושתי מים קרים, ואם עדיין פחות — פני לרופאה.' },
  { kw:['שליש','טרימסטר'],          ans:'כל שליש עולם בפני עצמו ✨ שליש ראשון (1-13): גיבוש האיברים, בחילות נורמליות. שליש שני (14-26): "הזהב" — הכי נוח, אנרגיה חוזרת. שליש שלישי (27-40): הכנה ללידה, הכבדה, קוצר נשימה.' },
  { kw:['לידה','לחייה','צירים'],     ans:'הכנה ללידה 🏥 שקלי קורס לידה מחודש 7. הכיני תיק לידה משבוע 34-35. דבדי עם הרופאה על תוכנית הלידה שלך (אפידורל, לידה טבעית). צירים סדירים כל 5 דקות — פני לבית חולים.' },
  { kw:['הנקה','שד','חלב'],         ans:'הנקה היא חוויה מיוחדת 🍼 הגוף מתחיל להתכונן כבר בהריון. כדאי: קורס הנקה, לחות ועיסוי עדין. יש יועצות הנקה זמינות אחרי הלידה — אל תהססי לפנות. הנקה היא כישרון נלמד.' },
  { kw:['סוכרת','גלוקוז','סוכר','GDH'], ans:'בדיקת סוכרת הריון (GDH) — שבוע 24-28 🩸 צום 8 שעות לפני. אם אובחנה סוכרת הריון — דיאטה מותאמת (פחות קמח לבן וסוכר), הליכות אחרי ארוחות, ניטור עצמי. הרוב מנהלות אותה היטב ובלי סיבוכים.' },
  { kw:['לחץ דם','לחץ עורקי'],      ans:'לחץ דם תקין בהריון: 120/80 או פחות 💊 לחץ גבוה (מעל 140/90) — חשוב לדווח לרופאה. תסמינים מדאיגים: כאב ראש עז, ראייה מטושטשת, נפיחות פתאומית בפנים — פני מיד.' },
  { kw:['בחוק','חוקת','עצירות'],    ans:'עצירות שכיחה בהריון 🌿 נסי: 8-10 כוסות מים ביום, סיבים תזונתיים (שזיפים, תמרים, פירות, קטניות), הליכות בוקר. תרגול יוגה עוזר מאוד. יש תרופות בטוחות להריון אם מסי מאוד.' },
  { kw:['מגנזיום'],                  ans:'מגנזיום חשוב בהריון 💊 עוזר למניעת התכווצויות, שיפור שינה, ולחץ דם. מקורות: שקדים, בננות, שוקולד מריר 🍫, ירקות ירוקים, גרעיני דלעת. מחסור שכיח — שאלי את הרופאה על תוסף.' },
  { kw:['קפה','קפאין','תה','אספרסו'], ans:'קפאין בהריון 🍵 עד 200 מ"ג ביום — בסדר (כוס קפה אחת). תה ירוק מכיל קפאין גם כן. קפה נטול קפאין — מצוין כתחליף. הימנעי ממשקאות אנרגיה. אחרי 14:00 — עדיף להימנע לשינה טובה.' },
  { kw:['אלכוהול','יין','בירה'],    ans:'אלכוהול בהריון — עדיף להימנע לחלוטין 🚫 אין כמות בטוחה ידועה. אם שתית לפני שידעת — זה קורה לרבות, ולרוב הכל בסדר.' },
  { kw:['חום','טמפרטורה','קדחת'],   ans:'חום בהריון 🌡️ מעל 38°C — קחי פרמול (לא אספירין/איבופרופן) ושתי מים. חום מעל 38.5° שלא יורד — פני לרופאה. נגבי עם ספוג ומים פושרים לקירור מהיר.' },
  { kw:['הקאה','הקיא','הקיות','בחיל קשה'], ans:'הקאות קשות בהריון 💛 נסי: ג\'ינג\'ר, קרקרים לפני קימה, ויטמין B6. אם לא מצליחה לשמור נוזלים בכלל — פני לרופאה — יש טיפול. לאחר שבוע 12-14 הבחילות בדרך כלל פוחתות.' },
  { kw:['תנוחה','שכיבה','כרית הריון'], ans:'תנוחת שינה בהריון 🌙 מהשבוע ה-20 — עדיף הצד השמאלי (זרימת דם טובה יותר). כרית הריון בין הברכיים מורידה לחץ על הגב. אל תדאגי אם התהפכת בלילה — הגוף יזיז אותך.' },
  { kw:['שחייה','בריכה','ג\'קוזי'], ans:'שחייה מומלצת מאוד 🏊‍♀️ מפחיתה לחץ על הגב, עוזרת לנפיחות, מצוינת לנשימה ומצב הרוח. בריכה עם כלור — בטוחה. ג\'קוזי חם מאוד — הימנעי.' },
  { kw:['קרם','מתיחה','פסי','גרד'], ans:'פסי מתיחה וגרד בעור 🧴 לחות עוזרת — שמן שקדים, חמאת קוקו, קרם קקאו — עסי פעמיים ביום מהשבוע ה-16. לא ניתן למנוע לחלוטין (גנטיקה), אבל גרד מופחת. הופעים לרוב שבוע 20-26.' },
  { kw:['אולטרסאונד','אולטרה','US','סקירה'], ans:'אולטרסאונד בהריון 📷 לו"ז: שבוע 8-10 (אישור הריון), שבוע 12-14 (שקיפות עורפית), שבוע 20-22 (סקירת מערכות — מביאים את השותף! 💛), שבוע 32-34 (שליש שלישי). בטוח לחלוטין.' },
  { kw:['נסיע','טיסה','טיול'],       ans:'נסיעות בהריון 🚗 עד שבוע 36 — בדרך כלל בסדר. בטיסה: קום כל שעה-שעתיים, שתי מים, לבשי גרביים תומכות. נסיעה ארוכה ברכב — עצרי כל שעתיים לתנועה ומתיחות.' },
  { kw:['עבוד','עבודה','עמידה ממושכת'], ans:'עבודה בהריון 💼 עמידה ממושכת — קחי הפסקות לישיבה כל 30 דקות. עבודה עם כימיקלים או הרמת משאות — שוחח עם הרופאה. מגיע לך חופשת לידה — תכנני מראש (בדרך כלל מ-34 שבוע).' },
  { kw:['סידן','עצמות','שיניים'],   ans:'סידן חיוני לעצמות ושיניים התינוק 🦷 מקורות: גבינה, יוגורט, חלב, טחינה, שקדים, ברוקולי. תינוק ישאב סידן מעצמותיך אם אין מספיק — חשוב לאכול מספיק. הקפידי לבקר אצל שיניים בהריון — מוגן וחשוב.' },
  { kw:['דגים','סלמון','טונה','כספית'], ans:'דגים בהריון 🐟 מצוין: סלמון, פורל, בורי, קרפיון. הימנעי מ: חרב, כריש, מקרל מלך (הרבה כספית). טונה בקופסה — מוגבל לפחה אחת בשבוע. 2-3 מנות דגים בשבוע — מומלץ לאומגה 3 ולחלבון.' },
  { kw:['גבינה','קממבר','ברי','גורגונזול'], ans:'גבינות בהריון 🧀 מותר: גבינות קשות (מותק, צהובה, פרמז\'ן, קוטג\', לבנה 9%). הימנעי מ: גבינות רכות לא מפוסטרות (קממבר, ברי, גורגונזולה) — סיכון לליסטריה. כל גבינה מפוסטרת — בסדר.' },
  { kw:['חומצה פולית','פולית','פולאט'], ans:'חומצה פולית — חיונית ✨ מונעת מומי נפש. מקורות: עלים ירוקים (תרד, ברוקולי), קטניות, הדרים. תוסף מומלץ 3 חודשים לפני ועד סוף שבוע 12. לרוב — 400-800 מק"ג ביום.' },
  { kw:['אומגה','DHA','אומגה 3'],   ans:'אומגה 3 / DHA חיוני להתפתחות מוח ועיניים התינוק 🧠 מקורות: סלמון, פורל, אגוזי מלך, זרעי פשתן. תוסף DHA מומלץ אם לא אוכלת דגים באופן קבוע.' },
];

function chatAnswerLocal(question) {
  const q = question.toLowerCase();
  for (const { kw, ans } of CHAT_KB) {
    if (kw.some(k => q.includes(k))) return ans;
  }
  return 'שאלה טובה 💛 בהריון הגוף עובר שינויים מדהימים! הבסיס לתחושה טובה: מנוחה, תזונה מאוזנת (ירקות, חלבונים, ברזל, סידן), שתיית מים מרובה (8+ כוסות), ותוספי הריון. אם תפרטי את שאלתך — אוכל לעזור יותר 🌸';
}

async function chatAnswerGemini(question) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;

  const systemPrompt = `את "שפית ההריון" — עוזרת חכמה ואמפתית לנשים בהריון.
ענִי תמיד בעברית בלבד, בשפה חמה, תומכת ומקצועית.
תני תשובות מועילות ומבוססות על מידע רפואי מוכר.
לשאלות על תסמינים חמורים (דימום חזק, כאב חד מאוד, חום גבוה מאוד, אובדן הכרה) — ציינִי שיש לפנות לרופאה או לחדר מיון.
אל תגידי "התייעצי עם הרופאה" כתשובה יחידה — תמיד תני מידע מועיל תחילה.
השתמשי באמוג'ים בצורה מתונה (2-3 לכל תשובה).
תשובות קצרות וברורות — עד 5 משפטים.`;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
  const body = {
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents: [{ parts: [{ text: question }] }],
    generationConfig: { temperature: 0.7, maxOutputTokens: 400 },
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) return null;
  const data = await r.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
}

app.post('/api/chat', authenticate, async (req, res) => {
  const err = validate(req.body, {
    question: { required: true, type: 'string', maxLength: 500 },
  });
  if (err) return res.status(400).json({ error: err });

  let answer;
  try {
    answer = await chatAnswerGemini(req.body.question);
  } catch {}
  if (!answer) answer = chatAnswerLocal(req.body.question);

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
