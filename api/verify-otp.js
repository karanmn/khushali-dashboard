const crypto = require('crypto');

function base32tohex(base32) {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let hex = "";
  base32 = base32.replace(/=+$/, '').toUpperCase();
  for (let i = 0; i < base32.length; i++) {
    const val = base32chars.indexOf(base32.charAt(i));
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 4 <= bits.length; i += 4) {
    const chunk = bits.substr(i, 4);
    hex = hex + parseInt(chunk, 2).toString(16);
  }
  return hex;
}

function getTOTP(secretHex, timeStep) {
  const timeBuffer = Buffer.alloc(8);
  let temp = timeStep;
  for (let i = 7; i >= 0; i--) {
    timeBuffer[i] = temp & 0xff;
    temp = temp >> 8;
  }
  const key = Buffer.from(secretHex, 'hex');
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuffer);
  const digest = hmac.digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = ((digest[offset] & 0x7f) << 24 |
                (digest[offset + 1] & 0xff) << 16 |
                (digest[offset + 2] & 0xff) << 8 |
                (digest[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

export default async function handler(req, res) {
  // CORS & Method Check
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  const { otp } = req.body || {};
  const secret = process.env.TOTP_SECRET;

  if (!secret) {
    return res.status(500).json({ success: false, message: 'Server configuration error: TOTP_SECRET not found' });
  }

  if (!otp || typeof otp !== 'string' || otp.trim().length !== 6) {
    return res.status(400).json({ success: false, message: 'Kripya 6-digit code enter karein' });
  }

  try {
    const cleanSecret = secret.replace(/\s+/g, '');
    const secretHex = base32tohex(cleanSecret);
    const currentEpoch = Math.floor(Date.now() / 1000);
    const step = Math.floor(currentEpoch / 30);

    // Clock drift handle karne ke liye (Previous 30s, Current 30s, Next 30s)
    const validSteps = [step - 1, step, step + 1];
    const cleanOtp = otp.trim();

    let isValid = false;
    for (const s of validSteps) {
      if (getTOTP(secretHex, s) === cleanOtp) {
        isValid = true;
        break;
      }
    }

    if (isValid) {
      return res.status(200).json({ 
        success: true, 
        token: 'khushali_auth_' + Date.now() + '_' + Math.random().toString(36).substring(2) 
      });
    } else {
      return res.status(401).json({ success: false, message: 'Galat OTP code! Google Authenticator se check karein.' });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Verification error: ' + err.message });
  }
}
