const express = require('express');
const http = require('http');
const crypto = require('crypto');
const ShellyOWS = require('./shellyOWS');

// ==========================================
// רשת ביטחון - למנוע קריסת שרת מ-Promise לא מטופל
// (זו הייתה סיבת קריסות ה-502 שראינו!)
// ==========================================
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection (not crashing):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception (not crashing):', err);
});

const app = express();
app.use(express.json());

const server = http.createServer(app);
const ows = new ShellyOWS(server);

// חובה - אין ברירת מחדל! אם לא מוגדר, השרת לא עולה
const API_SECRET = process.env.RELAY_SECRET;
if (!API_SECRET) {
  console.error('FATAL: RELAY_SECRET environment variable is not set!');
  process.exit(1);
}

function isValidSecret(provided, expected) {
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function generateShellyAuth(password, realm, nonce) {
  const username = 'admin';
  const nc = '00000001';
  const cnonce = crypto.randomBytes(4).toString('hex');

  const ha1 = crypto.createHash('sha256').update(`${username}:${realm}:${password}`).digest('hex');
  const ha2 = crypto.createHash('sha256').update('dummy_method:dummy_uri').digest('hex');
  const response = crypto.createHash('sha256').update(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`).digest('hex');

  return {
    realm,
    username,
    nonce,
    cnonce,
    nc,
    response,
    algorithm: 'SHA-256',
  };
}

function callWithTimeout(deviceId, method, params, authObject, timeoutMs = 10000) {
  return Promise.race([
    ows.call(deviceId, method, params, authObject),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Device response timeout')), timeoutMs)
    ),
  ]);
}

// פונקציה חכמה שעוטפת את הבקשה ומטפלת בהזדהות אוטומטית
async function callWithAuth(deviceId, method, params, devicePassword) {
  try {
    return await callWithTimeout(deviceId, method, params, undefined);
  } catch (err) {
    let authChallenge = null;

    // תשובת שגיאת 401 מהמכשיר מגיעה כ- { code: 401, message: "{...json...}" }
    if (err && err.code === 401 && err.message) {
      try {
        authChallenge = JSON.parse(err.message);
      } catch (e) {
        console.error('Failed to parse auth challenge from device error', e);
      }
    }

    if (authChallenge && authChallenge.nonce && devicePassword) {
      console.log(`[Auth] Generating Digest Auth for device ${deviceId}...`);
      const authObject = generateShellyAuth(devicePassword, authChallenge.realm, authChallenge.nonce);
      return await callWithTimeout(deviceId, method, params, authObject);
    }

    // אין challenge שמיש או אין סיסמה - זו שגיאה אחרת (כולל שגיאות RPC לגיטימיות כמו "already exists")
    throw err;
  }
}

/* ==========================================
   דף הבית - בדיקה ויזואלית שהשרת חי
========================================== */
app.get('/', (req, res) => {
  res.send(
    '<h1 dir="rtl" style="text-align: center; margin-top: 50px; font-family: sans-serif; color: #333;">הי, לאן רצית להגיע? 🚦</h1>'
  );
});

/* ==========================================
   בדיקת "דופק" קלה - לניטור/UptimeRobot וכו'
   לא דורש secret בכוונה, כדי שאפשר יהיה לפנג בקלות
========================================== */
app.get('/api/ping', (req, res) => {
  res.json({ status: 'alive', uptime_seconds: Math.floor(process.uptime()) });
});

/* ==========================================
   ENDPOINT 1: קבלת פקודות מ-Lovable
========================================== */
app.post('/api/rpc', async (req, res) => {
  if (!isValidSecret(req.headers['x-api-secret'], API_SECRET)) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  const { deviceId, method, params, devicePassword } = req.body;

  if (!deviceId || !method) {
    return res.status(400).json({ success: false, error: 'Missing deviceId or method in request body' });
  }

  try {
    console.log(`Sending ${method} to device ${deviceId}...`);

    // BTHome.StartDeviceDiscovery itself returns null on success - the actual
    // results arrive later as async NotifyEvent pushes over the same socket
    // (see /api/discovery/:deviceId below). Clear any previous scan's buffer
    // right before sending, so results don't get mixed across scans.
    if (method === 'BTHome.StartDeviceDiscovery') {
      ows.resetDiscovery(deviceId);
    }

    const result = await callWithAuth(deviceId, method, params, devicePassword);
    res.json({ success: true, result });
  } catch (err) {
    console.error(`Error communicating with ${deviceId}:`, err && err.message ? err.message : err);

    // שגיאת RPC לגיטימית מהמכשיר (יש לה code, כמו "already exists", 401 בלי סיסמה וכו')
    // - זה לא כשל של ה-relay עצמו, מחזירים 200 עם success:false כדי להבדיל מ-502 אמיתי
    if (err && typeof err === 'object' && 'code' in err) {
      return res.status(200).json({
        success: false,
        deviceError: true,
        code: err.code,
        error: err.message || JSON.stringify(err),
      });
    }

    // כשל אמיתי של ה-relay/תקשורת (timeout, מכשיר לא מחובר וכו')
    res.status(502).json({
      success: false,
      error: (err && err.message) || 'Device disconnected or internal error',
    });
  }
});

/* ==========================================
   ENDPOINT 2: רשימת המכשירים המחוברים
========================================== */
app.get('/api/clients', (req, res) => {
  if (!isValidSecret(req.headers['x-api-secret'], API_SECRET)) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  // getClients() כבר מחזיר מערך - בלי Object.keys נוסף!
  res.json({ success: true, active_devices: ows.getClients() });
});

/* ==========================================
   ENDPOINT 3: תוצאות סריקת BTHome (BLU) שנאספו עד כה
   מיועד ל-polling אחרי קריאה ל-BTHome.StartDeviceDiscovery דרך /api/rpc,
   כי התוצאות מגיעות אסינכרונית כ-NotifyEvent ולא בתשובת ה-RPC עצמה.
========================================== */
app.get('/api/discovery/:deviceId', (req, res) => {
  if (!isValidSecret(req.headers['x-api-secret'], API_SECRET)) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  res.json({ success: true, ...ows.getDiscovery(req.params.deviceId) });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Shelly API Server is live and listening on port ${PORT}`);
});
