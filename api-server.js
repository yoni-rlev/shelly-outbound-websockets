const express = require('express');
const http = require('http');
const crypto = require('crypto');
const ShellyOWS = require('./shellyOWS');

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

// 1. אבטחת מילת הסוד (נגד Timing Attacks)
function isValidSecret(provided, expected) {
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// 2. פונקציית יצירת המפתח למכשירי Shelly (Digest Auth)
function generateShellyAuth(password, realm, nonce) {
  const username = 'admin'; // משתמש ברירת המחדל של Shelly
  const nc = '00000001';
  const cnonce = crypto.randomBytes(4).toString('hex');

  const ha1 = crypto.createHash('sha256').update(`${username}:${realm}:${password}`).digest('hex');
  const ha2 = crypto.createHash('sha256').update('dummy_method:dummy_uri').digest('hex');
  const response = crypto.createHash('sha256').update(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`).digest('hex');

  return {
    realm: realm,
    username: username,
    nonce: nonce,
    cnonce: cnonce,
    nc: nc,
    response: response,
    algorithm: 'SHA-256'
  };
}

// 3. הגבלת זמן (Timeout) לבקשות
function callWithTimeout(deviceId, method, params, authObject, timeoutMs = 10000) {
  return Promise.race([
    ows.call(deviceId, method, params, authObject),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Device response timeout')), timeoutMs)
    ),
  ]);
}

// 4. פונקציה חכמה שעוטפת את הבקשה ומטפלת בהזדהות אוטומטית
async function callWithAuth(deviceId, method, params, devicePassword) {
  try {
    // ניסיון ראשון (ללא סיסמה)
    return await callWithTimeout(deviceId, method, params, undefined);
  } catch (err) {
    // המכשיר החזיר שגיאה. נבדוק אם זו שגיאת 401 (בקשת סיסמה)
    let authChallenge = null;
    
    if (err && err.code === 401 && err.message) {
      try {
        // מחלצים את ה-nonce וה-realm מתוך הודעת השגיאה של Shelly
        authChallenge = JSON.parse(err.message); 
      } catch (e) {
        console.error("Failed to parse auth challenge from device error", e);
      }
    }

    // המכשיר דרש סיסמה ויש לנו את פרטי האתגר? נחשב ונשלח שוב!
    if (authChallenge && authChallenge.nonce && devicePassword) {
      console.log(`[Auth] Generating Digest Auth for device ${deviceId}...`);
      const authObject = generateShellyAuth(devicePassword, authChallenge.realm, authChallenge.nonce);
      
      // ניסיון שני מאובטח
      return await callWithTimeout(deviceId, method, params, authObject);
    }

    // אם אין סיסמה או שזו שגיאה אחרת, נזרוק אותה החוצה
    throw err;
  }
}

/* ==========================================
   ENDPOINT 1: קבלת פקודות מ-Lovable
========================================== */
app.post('/api/rpc', async (req, res) => {
  if (!isValidSecret(req.headers['x-api-secret'], API_SECRET)) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  // Lovable יכול לשלוח גם את devicePassword אם קיים
  const { deviceId, method, params, devicePassword } = req.body;
  
  if (!deviceId || !method) {
    return res.status(400).json({ success: false, error: 'Missing deviceId or method in request body' });
  }

  try {
    console.log(`Sending ${method} to device ${deviceId}...`);
    const result = await callWithAuth(deviceId, method, params, devicePassword);
    res.json({ success: true, result });
  } catch (err) {
    console.error(`Error communicating with ${deviceId}:`, err && err.message ? err.message : err);
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
  res.json({ success: true, active_devices: ows.getClients() });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Shelly API Server is live and listening on port ${PORT}`);
});
