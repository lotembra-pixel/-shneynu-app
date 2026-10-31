'use strict';
// ════════════════════════════════════════════════════════════════════════════
// שנינו — שרת API (Express + Firebase Admin) · לטם מחוליה, 2026
// ════════════════════════════════════════════════════════════════════════════
const express   = require('express');
const admin     = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');

const app = express();
app.set('trust proxy', 1);                       // Vercel עובד מאחורי proxy
app.use(express.json({ limit: '1.5mb' }));       // תמונות מסמכים מכווצות

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
const TS   = () => admin.firestore.FieldValue.serverTimestamp();
const userRef = uid => db.collection('users').doc(uid);

// ── Rate limiting ────────────────────────────────────────────────────────────
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }));
app.use('/api/partner/join', rateLimit({ windowMs: 15 * 60 * 1000, max: 15 }));

// ── CORS (same-origin on Vercel; needed only for local dev) ─────────────────
app.use((req, res, next) => {
  if (process.env.ALLOWED_ORIGIN) res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Helpers ──────────────────────────────────────────────────────────────────
const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : undefined);
const isDate = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);

async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'נדרשת התחברות' });
  try {
    req.user = await auth.verifyIdToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'החיבור פג — מתחברים מחדש' });
  }
}

const AUTH_MSGS = {
  WRONG_PASSWORD:              'הסיסמה שגויה',
  EMAIL_NOT_FOUND:             'לא נמצא חשבון עם האימייל הזה',
  INVALID_EMAIL:               'כתובת האימייל אינה תקינה',
  INVALID_LOGIN_CREDENTIALS:   'אימייל או סיסמה שגויים',
  USER_DISABLED:               'החשבון הושהה',
  TOO_MANY_ATTEMPTS_TRY_LATER: 'יותר מדי ניסיונות — נסי שוב בעוד כמה דקות',
};

async function signInWithPassword(email, password) {
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, returnSecureToken: true }),
  });
  const data = await r.json();
  if (!r.ok) {
    const code = (data.error?.message || '').split(' : ')[0];
    throw new Error(AUTH_MSGS[code] || 'אימייל או סיסמה שגויים');
  }
  return data;
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  const name = str(req.body.name, 100), email = str(req.body.email, 200);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const role = req.body.role === 'partner' ? 'partner' : 'mom';
  if (!name)  return res.status(400).json({ error: 'נא להזין שם' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'כתובת אימייל לא תקינה' });
  if (password.length < 6 || password.length > 128) return res.status(400).json({ error: 'סיסמה של 6 תווים לפחות' });
  try {
    const u = await auth.createUser({ email, password, displayName: name });
    await userRef(u.uid).set({ fullName: name, email, role, createdAt: TS() });
    const t = await signInWithPassword(email, password);
    res.json({ token: t.idToken, refreshToken: t.refreshToken, uid: u.uid });
  } catch (e) {
    const msgs = {
      'auth/email-already-exists': 'האימייל כבר רשום — נסי להתחבר',
      'auth/invalid-email':        'כתובת האימייל אינה תקינה',
      'auth/weak-password':        'הסיסמה חלשה מדי',
    };
    res.status(400).json({ error: msgs[e.code] || 'שגיאה ביצירת החשבון' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = str(req.body.email, 200);
  const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 128) : '';
  if (!email || !password) return res.status(400).json({ error: 'נא למלא אימייל וסיסמה' });
  try {
    const t = await signInWithPassword(email, password);
    res.json({ token: t.idToken, refreshToken: t.refreshToken, uid: t.localId });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// חידוש חיבור — הטוקן של Firebase פג אחרי שעה, כאן מקבלים חדש בלי להתחבר שוב
app.post('/api/auth/refresh', async (req, res) => {
  const rt = str(req.body.refreshToken, 2000);
  if (!rt) return res.status(400).json({ error: 'חסר טוקן' });
  try {
    const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${process.env.FIREBASE_API_KEY}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt }).toString(),
    });
    const d = await r.json();
    if (!r.ok) return res.status(401).json({ error: 'החיבור פג — מתחברים מחדש' });
    res.json({ token: d.id_token, refreshToken: d.refresh_token });
  } catch {
    res.status(500).json({ error: 'שגיאת שרת' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PROFILE
// ════════════════════════════════════════════════════════════════════════════
const PROFILE_FIELDS = {
  fullName: 100, fund: 30, doctor: 100, clinic: 100, babies: 30, firstPreg: 30,
  phone: 30, ecname: 100, ecphone: 30, birthpref: 1000, hospital: 100,
};
const PRIVATE_FIELDS = { idnum: 20, bloodtype: 10, allergies: 500, prevpreg: 300, conds: 500, weight: 10, height: 10 };

app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const [doc, priv] = await Promise.all([
      userRef(req.user.uid).get(),
      userRef(req.user.uid).collection('medical').doc('private').get(),
    ]);
    const data = doc.exists ? doc.data() : {};
    delete data.createdAt; delete data.updatedAt;
    res.json({ ...data, ...(priv.exists ? priv.data() : {}), uid: req.user.uid, email: req.user.email });
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת הפרופיל' });
  }
});

app.put('/api/profile', authenticate, async (req, res) => {
  const pub = {}, priv = {};
  for (const [k, max] of Object.entries(PROFILE_FIELDS)) if (req.body[k] !== undefined) pub[k] = str(String(req.body[k]), max);
  for (const [k, max] of Object.entries(PRIVATE_FIELDS)) if (req.body[k] !== undefined) priv[k] = str(String(req.body[k]), max);
  if (req.body.dueDate !== undefined) {
    if (req.body.dueDate && !isDate(req.body.dueDate)) return res.status(400).json({ error: 'תאריך לא תקין' });
    pub.dueDate = req.body.dueDate || '';
  }
  if (req.body.onboarded === true) pub.onboarded = true;
  if (req.body.share && typeof req.body.share === 'object') {
    pub.share = { meds: !!req.body.share.meds, docs: !!req.body.share.docs, journal: !!req.body.share.journal };
  }
  if (Array.isArray(req.body.meds)) {
    priv.meds = req.body.meds.slice(0, 15).map(m => ({
      name: str(m?.name, 60) || '',
      time: /^\d{2}:\d{2}$/.test(m?.time || '') ? m.time : '08:00',
    })).filter(m => m.name);
  }
  try {
    await userRef(req.user.uid).set({ ...pub, updatedAt: TS() }, { merge: true });
    if (Object.keys(priv).length) await userRef(req.user.uid).collection('medical').doc('private').set(priv, { merge: true });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירה' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// DAILY — בעיטות, מים ותרופות לפי יום
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/daily/:date', authenticate, async (req, res) => {
  if (!isDate(req.params.date)) return res.status(400).json({ error: 'תאריך לא תקין' });
  try {
    const d = await userRef(req.user.uid).collection('daily').doc(req.params.date).get();
    res.json(d.exists ? d.data() : { kicks: 0, water: 0, medsTaken: [] });
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינה' });
  }
});

app.put('/api/daily/:date', authenticate, async (req, res) => {
  if (!isDate(req.params.date)) return res.status(400).json({ error: 'תאריך לא תקין' });
  const n = v => Math.max(0, Math.min(200, parseInt(v) || 0));
  const data = {};
  if (req.body.kicks !== undefined) data.kicks = n(req.body.kicks);
  if (req.body.water !== undefined) data.water = n(req.body.water);
  if (Array.isArray(req.body.medsTaken)) data.medsTaken = req.body.medsTaken.slice(0, 15).map(x => str(String(x), 60));
  try {
    await userRef(req.user.uid).collection('daily').doc(req.params.date).set(data, { merge: true });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירה' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// DOCS — תיק רפואי: תמונה + ערכים שהמשתמשת מקלידה בעצמה (בלי "ניתוח" מומצא)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/docs', authenticate, async (req, res) => {
  try {
    const snap = await userRef(req.user.uid).collection('docs').orderBy('date', 'desc').limit(100).get();
    res.json(snap.docs.map(d => { const x = d.data(); const hasImage = !!x.image; delete x.image; return { ...x, hasImage }; }));
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת התיק' });
  }
});

app.get('/api/docs/:id/image', authenticate, async (req, res) => {
  try {
    const d = await userRef(req.user.uid).collection('docs').doc(String(req.params.id).slice(0, 40)).get();
    if (!d.exists) return res.status(404).json({ error: 'לא נמצא' });
    res.json({ image: d.data().image || null });
  } catch {
    res.status(500).json({ error: 'שגיאה' });
  }
});

app.post('/api/docs', authenticate, async (req, res) => {
  const title = str(req.body.title, 100);
  if (!title) return res.status(400).json({ error: 'נא לתת שם לבדיקה' });
  const image = typeof req.body.image === 'string' && req.body.image.startsWith('data:image/') ? req.body.image : null;
  if (image && image.length > 1_000_000) return res.status(400).json({ error: 'התמונה גדולה מדי' });
  const values = Array.isArray(req.body.values) ? req.body.values.slice(0, 20).map(v => ({
    label: str(v?.label, 60) || '', val: str(v?.val, 40) || '',
  })).filter(v => v.label && v.val) : [];
  const id = String(Date.now());
  try {
    await userRef(req.user.uid).collection('docs').doc(id).set({
      id, title, values, image,
      date: isDate(req.body.date) ? req.body.date : new Date().toISOString().slice(0, 10),
      note: str(req.body.note, 1000) || '',
      createdAt: TS(),
    });
    res.json({ ok: true, id });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירה' });
  }
});

app.delete('/api/docs/:id', authenticate, async (req, res) => {
  try {
    await userRef(req.user.uid).collection('docs').doc(String(req.params.id).slice(0, 40)).delete();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה במחיקה' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// JOURNAL
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/journal', authenticate, async (req, res) => {
  try {
    const snap = await userRef(req.user.uid).collection('journal').orderBy('id', 'desc').limit(100).get();
    res.json(snap.docs.map(d => d.data()));
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת היומן' });
  }
});

app.post('/api/journal', authenticate, async (req, res) => {
  const text = str(req.body.text, 5000);
  if (!text) return res.status(400).json({ error: 'היומן ריק' });
  const id = Date.now();
  const week = parseInt(req.body.week) || 0;
  try {
    await userRef(req.user.uid).collection('journal').doc(String(id)).set({ id, text, week, createdAt: TS() });
    res.json({ ok: true, id });
  } catch {
    res.status(500).json({ error: 'שגיאה בשמירה' });
  }
});

app.delete('/api/journal/:id', authenticate, async (req, res) => {
  try {
    await userRef(req.user.uid).collection('journal').doc(String(req.params.id).slice(0, 40)).delete();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה במחיקה' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PARTNER — קוד הזמנה + אישור של האמא. בלי אישור אין חיבור ואין גישה לנתונים.
// ════════════════════════════════════════════════════════════════════════════
const CODE_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const newCode = () => Array.from(crypto.randomBytes(6), b => CODE_ABC[b % CODE_ABC.length]).join('');

// האמא יוצרת קוד (תקף 7 ימים) ושולחת לשותף בוואטסאפ
app.post('/api/partner/code', authenticate, async (req, res) => {
  try {
    const me = await userRef(req.user.uid).get();
    if (me.data()?.role === 'partner') return res.status(400).json({ error: 'רק חשבון של אמא יכול להזמין' });
    const old = me.data()?.inviteCode;
    if (old) await db.collection('partnerCodes').doc(old).delete().catch(() => {});
    const code = newCode();
    await db.collection('partnerCodes').doc(code).set({
      ownerUid: req.user.uid, ownerName: me.data()?.fullName || '',
      expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
    });
    await userRef(req.user.uid).set({ inviteCode: code }, { merge: true });
    res.json({ code });
  } catch {
    res.status(500).json({ error: 'שגיאה ביצירת קוד' });
  }
});

// השותף מזין קוד → נוצרת בקשה שממתינה לאישור של האמא
app.post('/api/partner/join', authenticate, async (req, res) => {
  const code = str(req.body.code, 10)?.toUpperCase();
  if (!code) return res.status(400).json({ error: 'נא להזין קוד' });
  try {
    const c = await db.collection('partnerCodes').doc(code).get();
    if (!c.exists || c.data().expiresAt < Date.now()) return res.status(400).json({ error: 'הקוד לא תקין או שפג תוקפו' });
    const { ownerUid, ownerName } = c.data();
    if (ownerUid === req.user.uid) return res.status(400).json({ error: 'זה הקוד שלך 🙂' });
    const me = await userRef(req.user.uid).get();
    await userRef(ownerUid).set({
      pendingPartner: { uid: req.user.uid, name: me.data()?.fullName || '', email: req.user.email || '', at: Date.now() },
    }, { merge: true });
    await userRef(req.user.uid).set({ role: 'partner', pendingWith: ownerUid, pendingWithName: ownerName }, { merge: true });
    res.json({ ok: true, ownerName });
  } catch {
    res.status(500).json({ error: 'שגיאה בחיבור' });
  }
});

// האמא מאשרת או דוחה
app.post('/api/partner/respond', authenticate, async (req, res) => {
  try {
    const meRef = userRef(req.user.uid);
    const me = (await meRef.get()).data() || {};
    const p = me.pendingPartner;
    if (!p) return res.status(400).json({ error: 'אין בקשה ממתינה' });
    const del = admin.firestore.FieldValue.delete();
    if (req.body.approve === true) {
      await meRef.set({ partnerUid: p.uid, partnerName: p.name, pendingPartner: del, inviteCode: del,
        share: me.share || { meds: false, docs: false, journal: false } }, { merge: true });
      await userRef(p.uid).set({ partnerUid: req.user.uid, partnerName: me.fullName || '', pendingWith: del, pendingWithName: del }, { merge: true });
      if (me.inviteCode) await db.collection('partnerCodes').doc(me.inviteCode).delete().catch(() => {});
    } else {
      await meRef.set({ pendingPartner: del }, { merge: true });
      await userRef(p.uid).set({ pendingWith: del, pendingWithName: del }, { merge: true });
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה' });
  }
});

// ניתוק — כל אחד מהצדדים יכול
app.post('/api/partner/unlink', authenticate, async (req, res) => {
  try {
    const me = (await userRef(req.user.uid).get()).data() || {};
    const del = admin.firestore.FieldValue.delete();
    await userRef(req.user.uid).set({ partnerUid: del, partnerName: del }, { merge: true });
    if (me.partnerUid) await userRef(me.partnerUid).set({ partnerUid: del, partnerName: del }, { merge: true });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'שגיאה' });
  }
});

// השותף קורא את הנתונים של האמא — רק מה שהיא בחרה לשתף
app.get('/api/partner/data', authenticate, async (req, res) => {
  try {
    const me = (await userRef(req.user.uid).get()).data() || {};
    if (me.role !== 'partner' || !me.partnerUid) return res.json({ mom: null });
    const momRef = userRef(me.partnerUid);
    const mom = (await momRef.get()).data() || {};
    if (mom.partnerUid !== req.user.uid) return res.json({ mom: null });   // החיבור חייב להיות דו-כיווני
    const share = mom.share || {};
    const out = { fullName: mom.fullName || '', dueDate: mom.dueDate || '', babies: mom.babies || '',
      fund: mom.fund || '', doctor: mom.doctor || '', hospital: mom.hospital || '', share };
    if (share.meds) {
      const priv = await momRef.collection('medical').doc('private').get();
      out.meds = priv.exists ? (priv.data().meds || []) : [];
      const today = new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10);
      const d = await momRef.collection('daily').doc(today).get();
      out.today = d.exists ? d.data() : { kicks: 0, water: 0, medsTaken: [] };
    }
    if (share.docs) {
      const snap = await momRef.collection('docs').orderBy('date', 'desc').limit(30).get();
      out.docs = snap.docs.map(d => { const x = d.data(); delete x.image; return x; });
    }
    if (share.journal) {
      const snap = await momRef.collection('journal').orderBy('id', 'desc').limit(30).get();
      out.journal = snap.docs.map(d => d.data());
    }
    res.json({ mom: out });
  } catch {
    res.status(500).json({ error: 'שגיאה בטעינת הנתונים' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// CHAT — Gemini, ואם אין מפתח/תקלה: מאגר תשובות מקומי
// ════════════════════════════════════════════════════════════════════════════
const CHAT_KB = [
  { kw:['בחילה','בחילות','בחיל'],   ans:'כשיש בחילות — אם את נוטלת תוספים — עדיף לקחת אותם עם אוכל קל 🥐. ג\'ינג\'ר (תה, סוכריות) ידועה כמסייעת. אכלי ארוחות קטנות ותכופות ולא על בטן ריקה.' },
  { kw:['אכ','לאכ','אוכ','מאכ','תזונה','דיאטה'], ans:'תזונה מצוינת בהריון ✨ מומלץ: אגוזים, טחינה (ברזל ❤️), סלמון (אומגה 3), ירקות כתומים, לחם מחיטה מלאה, קטניות, ביצים. הגוף צריך ברזל, סידן, חומצה פולית ואומגה 3. הימנעי מגבינות רכות לא מפוסטרות ודגים גדולים (טונה גדולה, חרב).' },
  { kw:['ויטמין','תוסף'],           ans:'ויטמינים חשובים 💊 חומצה פולית מונעת מומים (חיונית בשליש ראשון), ברזל (עדשים, בשר, תרד), סידן (מוצרי חלב, טחינה), ויטמין D (שמש 15 דק\' ביום, סלמון), אומגה 3 (דגים, אגוזי מלך). ויטמין B12 חשוב לצמחוניות.' },
  { kw:['נשימ','הרגע','רגוע','מדיטציה'], ans:'תרגיל נשימה 4-7-8 🌬️ שאפי 4 שניות, החזיקי 7, נשפי לאט 8 שניות. חזרי 4 פעמים. מרגיע את מערכת העצבים. אפשר גם: מדיטציית מיינדפולנס 10 דקות, יוגה להריון, או הליכה בטבע.' },
  { kw:['חרד','לחץ','מתח','פחד','דכאון'], ans:'רגשות מעורבים בהריון — נורמלי לגמרי 💛 נסי: נשימות עמוקות, הליכה קצרה, שיחה עם מישהי קרובה, יוגה להריון, כתיבת יומן. תמיכה רגשית חשובה לא פחות מהפיזית. אם מרגישה מוצפת לאורך זמן — יש מי שיכולה לעזור.' },
  { kw:['שינה','לישון','עייפ','עייפות'], ans:'שינה טובה חיונית 🌙 ישני על הצד השמאלי (עוזר לזרימת דם לתינוק), השתמשי בכרית הריון בין הברכיים, שמרי על שגרת שינה קבועה. הימנעי מקפאין אחרי 14:00. עייפות קיצונית בשליש ראשון ושלישי היא נורמלית לחלוטין.' },
  { kw:['גב','עמוד שדרה','כאב גב'], ans:'כאבי גב שכיחים מאוד בהריון 💛 נסי: כרית גב בישיבה, שכיבה על הצד השמאלי עם כרית בין הברכיים, הליכות קצרות, יוגה להריון. חממי עם שקית מים חמים. אם הכאב חזק מאוד או קורן לרגל — שוחחי עם הרופאה.' },
  { kw:['ראש','כאב ראש','מיגרנה'], ans:'כאבי ראש בהריון נפוצים 💛 שתי מים רבים (8+ כוסות ביום), מנוחה בחדר חשוך, קומפרס קר על המצח. ניתן לקחת פרמול — לא אספירין ולא איבופרופן. לכאב ראש חזק פתאומי עם נפיחות בפנים — פני לרופאה.' },
  { kw:['נפיח','בצקת','רגל','קרסול'], ans:'נפיחות ברגליים שכיחה בשליש שני ושלישי 💛 העלי את הרגליים, הימנעי מישיבה ממושכת (קומי כל שעה), לבשי גרביים תומכות, שתי מים מרובה. קירור עם מים קרים עוזר. נפיחות פתאומית בפנים — פני לרופאה.' },
  { kw:['שתן','שלפוחית','דלקת','צריבה'], ans:'דלקת שתן שכיחה בהריון ⚕️ שתי הרבה מים, הימנעי מחזקות. אם יש כאב/צריבה בשתן, חום, או כאב גב תחתון — פני לרופאה לטיפול אנטיביוטי מתאים להריון. לא לחכות — עלולה להסתבך.' },
  { kw:['כאב'],                     ans:'כאבים קלים ומשיכות קלות הם לרוב נורמליים בהריון ✨ הרחם גדל ורצועות מתמתחות. כאבים חזקים, חדים, מלווים בדימום, חום, או כאב ראש עז — פני לרופאה מיד ⚕️' },
  { kw:['משקל','עלייה במשקל'],       ans:'עלייה במשקל בהריון — תהליך טבעי ובריא 💛 שליש ראשון: 1-2 ק"ג. שליש שני-שלישי: 0.4-0.5 ק"ג לשבוע. סה"כ: 11-16 ק"ג (תלוי במשקל ההתחלתי). אל תצמצמי קלוריות — הגוף שלך עובד קשה!' },
  { kw:['ברזל','אנמי','פריטין','המוגלובין'], ans:'ברזל חשוב מאוד בהריון 🩸 מזונות עשירים: עדשים, תרד, בשר בקר, טחינה, אגוזי קשיו. לספיגה טובה — אכלי עם ויטמין C (לימון, פלפל, תפוז). הימנעי מקפה/תה שעה לפני ואחרי נטילת ברזל. אנמיה — שכיחה ומטופלת בקלות.' },
  { kw:['פעיל','ספורט','תרגיל','כושר'], ans:'פעילות גופנית מומלצת 🏃‍♀️ הליכה (30 דקות), שחייה, יוגה להריון, פילאטיס להריון — מצוינות! מסייעות לגב, מצב הרוח, הכנה ללידה. הימנעי מספורט עצים עם סיכון נפילה. הקשיבי לגוף שלך.' },
  { kw:['בעיט','תנוע','תינוק זז','עיטות'], ans:'בעיטות התינוק הן סימן מצוין 🥰 מרגישים אותן משבוע 18-25. משבוע 28 — מומלץ לספור 10 תנועות תוך שעתיים פעם ביום. פחות תנועה מהרגיל — שכבי על הצד ושתי מים קרים, ואם עדיין פחות — פני לרופאה.' },
  { kw:['שליש','טרימסטר'],          ans:'כל שליש עולם בפני עצמו ✨ שליש ראשון (1-13): גיבוש האיברים, בחילות נורמליות. שליש שני (14-26): "הזהב" — הכי נוח, אנרגיה חוזרת. שליש שלישי (27-40): הכנה ללידה, הכבדה, קוצר נשימה.' },
  { kw:['לידה','לחייה','צירים'],     ans:'הכנה ללידה 🏥 שקלי קורס לידה מחודש 7. הכיני תיק לידה משבוע 34-35. דברי עם הרופאה על תוכנית הלידה שלך (אפידורל, לידה טבעית). צירים סדירים כל 5 דקות — פני לבית חולים.' },
  { kw:['הנקה','שד','חלב'],         ans:'הנקה היא חוויה מיוחדת 🍼 הגוף מתחיל להתכונן כבר בהריון. כדאי: קורס הנקה, לחות ועיסוי עדין. יש יועצות הנקה זמינות אחרי הלידה — אל תהססי לפנות. הנקה היא כישרון נלמד.' },
  { kw:['סוכרת','גלוקוז','סוכר','GDM'], ans:'בדיקת סוכרת הריון (GDM) — שבוע 24-28 🩸 צום 8 שעות לפני. אם אובחנה סוכרת הריון — דיאטה מותאמת (פחות קמח לבן וסוכר), הליכות אחרי ארוחות, ניטור עצמי. הרוב מנהלות אותה היטב ובלי סיבוכים.' },
  { kw:['לחץ דם','לחץ עורקי'],      ans:'לחץ דם תקין בהריון: 120/80 או פחות 💊 לחץ גבוה (מעל 140/90) — חשוב לדווח לרופאה. תסמינים מדאיגים: כאב ראש עז, ראייה מטושטשת, נפיחות פתאומית בפנים — פני מיד.' },
  { kw:['בחוק','חוקת','עצירות'],    ans:'עצירות שכיחה בהריון 🌿 נסי: 8-10 כוסות מים ביום, סיבים תזונתיים (שזיפים, תמרים, פירות, קטניות), הליכות בוקר. תרגול יוגה עוזר מאוד. יש תרופות בטוחות להריון אם מסי מאוד.' },
  { kw:['מגנזיום'],                  ans:'מגנזיום חשוב בהריון 💊 עוזר למניעת התכווצויות, שיפור שינה, ולחץ דם. מקורות: שקדים, בננות, שוקולד מריר 🍫, ירקות ירוקים, גרעיני דלעת. מחסור שכיח — שאלי את הרופאה על תוסף.' },
  { kw:['קפה','קפאין','תה','אספרסו'], ans:'קפאין בהריון 🍵 עד 200 מ"ג ביום — בסדר (כוס קפה אחת). תה ירוק מכיל קפאין גם כן. קפה נטול קפאין — מצוין כתחליף. הימנעי ממשקאות אנרגיה. אחרי 14:00 — עדיף להימנע לשינה טובה.' },
  { kw:['אלכוהול','יין','בירה'],    ans:'אלכוהול בהריון — עדיף להימנע לחלוטין 🚫 אין כמות בטוחה ידועה. אם שתית לפני שידעת — זה קורה לרבות, ולרוב הכל בסדר.' },
  { kw:['חום','טמפרטורה','קדחת'],   ans:'חום בהריון 🌡️ מעל 38°C — קחי פרמול (לא אספירין/איבופרופן) ושתי מים. חום מעל 38.5° שלא יורד — פני לרופאה. נגבי עם ספוג ומים פושרים לקירור מהיר.' },
  { kw:['הקאה','הקיא','הקיות','בחיל קשה'], ans:'הקאות קשות בהריון 💛 נסי: ג\'ינג\'ר, קרקרים לפני קימה, ויטמין B6. אם לא מצליחה לשמור נוזלים בכלל — פני לרופאה — יש טיפול. לאחר שבוע 12-14 הבחילות בדרך כלל פוחתות.' },
  { kw:['תנוחה','שכיבה','כרית הריון'], ans:'תנוחת שינה בהריון 🌙 מהשבוע ה-20 — עדיף הצד השמאלי (זרימת דם טובה יותר). כרית הריון בין הברכיים מורידה לחץ על הגב. אל תדאגי אם התהפכת בלילה — הגוף יזיז אותך.' },
  { kw:['שחייה','בריכה','ג\'קוזי'], ans:'שחייה מומלצת מאוד 🏊‍♀️ מפחיתה לחץ על הגב, עוזרת לנפיחות, מצוינת לנשימה ומצב הרוח. בריכה עם כלור — בטוחה. ג\'קוזי חם מאוד — הימנעי.' },
  { kw:['קרם','מתיחה','פסי','גרד'], ans:'פסי מתיחה וגרד בעור 🧴 לחות עוזרת — שמן שקדים, חמאת קוקו, קרם קקאו — עסי פעמיים ביום מהשבוע ה-16. לא ניתן למנוע לחלוטין (גנטיקה), אבל גרד מופחת. מופיעים לרוב שבוע 20-26.' },
  { kw:['אולטרסאונד','אולטרה','US','סקירה'], ans:'אולטרסאונד בהריון 📷 לו"ז: שבוע 8-10 (אישור הריון), שבוע 12-14 (שקיפות עורפית), שבוע 20-22 (סקירת מערכות — מביאים את השותף! 💛), שבוע 32-34 (שליש שלישי). בטוח לחלוטין.' },
  { kw:['נסיע','טיסה','טיול'],       ans:'נסיעות בהריון 🚗 עד שבוע 36 — בדרך כלל בסדר. בטיסה: קומי כל שעה-שעתיים, שתי מים, לבשי גרביים תומכות. נסיעה ארוכה ברכב — עצרי כל שעתיים לתנועה ומתיחות.' },
  { kw:['עבוד','עבודה','עמידה ממושכת'], ans:'עבודה בהריון 💼 עמידה ממושכת — קחי הפסקות לישיבה כל 30 דקות. עבודה עם כימיקלים או הרמת משאות — שוחחי עם הרופאה. מגיע לך חופשת לידה — תכנני מראש (בדרך כלל מ-34 שבוע).' },
  { kw:['סידן','עצמות','שיניים'],   ans:'סידן חיוני לעצמות ושיניים התינוק 🦷 מקורות: גבינה, יוגורט, חלב, טחינה, שקדים, ברוקולי. תינוק ישאב סידן מעצמותיך אם אין מספיק — חשוב לאכול מספיק. הקפידי לבקר אצל שיניים בהריון — מוגן וחשוב.' },
  { kw:['דגים','סלמון','טונה','כספית'], ans:'דגים בהריון 🐟 מצוין: סלמון, פורל, בורי, קרפיון. הימנעי מ: חרב, כריש, מקרל מלך (הרבה כספית). טונה בקופסה — מוגבל לפחית אחת בשבוע. 2-3 מנות דגים בשבוע — מומלץ לאומגה 3 ולחלבון.' },
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


function chatAnswerLocal(question) {
  const q = question.toLowerCase();
  for (const { kw, ans } of CHAT_KB) if (kw.some(k => q.includes(k))) return ans;
  return 'שאלה טובה 💛 לא מצאתי תשובה מדויקת לשאלה הזו. נסי לנסח אותה אחרת — ולכל דבר שמדאיג אותך, הכי בטוח לשאול את הרופאה או האחות במרפאה.';
}

async function chatAnswerGemini(question, week) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  // GEMINI_MODEL אפשר לשנות ב-Vercel בלי לגעת בקוד. ברירת המחדל מתעדכנת אוטומטית למודל העדכני.
  const model = process.env.GEMINI_MODEL || 'gemini-flash-latest';
  const systemPrompt = `את עוזרת מידע חמה ואמפתית לנשים בהריון ולבני הזוג שלהן, באפליקציה "שנינו".
ענִי תמיד בעברית, בשפה פשוטה, חמה ומקצועית, עד 5 משפטים.
תני מידע כללי ומבוסס בלבד. את לא רופאה: לא לאבחן, לא לפרש תוצאות בדיקה ספציפיות ולא לקבוע מינון תרופות — במקרים כאלה תני רקע כללי והפני לרופאה.
בתסמינים מדאיגים (דימום, ירידה בתנועות העובר, כאב חזק, חום גבוה, כאב ראש עז עם טשטוש ראייה, ירידת מים) — כתבי בתחילת התשובה לפנות מיד לרופאה או למיון יולדות.
${week ? `המשתמשת נמצאת בערך בשבוע ${week} להריון.` : ''}
מותר 1-2 אמוג'י.`;
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: 'user', parts: [{ text: question }] }],
      generationConfig: { temperature: 0.6, maxOutputTokens: 600 },
    }),
  });
  if (!r.ok) { console.error('Gemini error:', r.status, await r.text().catch(() => '')); return null; }
  const data = await r.json();
  return data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim() || null;
}

app.post('/api/chat', authenticate, async (req, res) => {
  const question = str(req.body.question, 500);
  if (!question) return res.status(400).json({ error: 'נא לכתוב שאלה' });
  let answer = null;
  try { answer = await chatAnswerGemini(question, parseInt(req.body.week) || 0); } catch {}
  if (!answer) answer = chatAnswerLocal(question);
  res.json({ answer });
});

// ── Health / 404 ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api', (_req, res) => res.status(404).json({ error: 'נתיב לא נמצא' }));

module.exports = app;
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
}
