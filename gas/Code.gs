/**
 * TRAE SOLO Attendance System - Backend Script (Secure version)
 *
 * ตั้งค่าก่อนใช้งาน (Project Settings > Script properties):
 *   ADMIN_USER      ชื่อผู้ใช้ Super Admin (ไม่ตั้ง = "admin")
 *   ADMIN_PASSWORD  รหัสผ่าน Super Admin (ต้องตั้ง ไม่งั้นล็อกอิน Super Admin ไม่ได้)
 */

const TZ = "Asia/Bangkok";
const SESSION_TTL_SEC = 6 * 60 * 60;   // 6 ชั่วโมง (สูงสุดของ CacheService)
const MAX_LOGIN_FAILS = 5;
const LOGIN_LOCK_SEC = 15 * 60;        // ล็อก 15 นาทีเมื่อกรอกผิดครบ
const MAX_PHOTO_CHARS = 3500000;       // ~2.6MB หลังถอด base64
const PHOTO_MIME = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };

function doGet() {
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('TRAE SOLO | Attendance System')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ===================== Helpers ===================== */

function normalizeDate(val) {
  if (!val) return "";
  if (val instanceof Date) return Utilities.formatDate(val, TZ, "yyyy-MM-dd");
  let str = String(val).trim();
  if (str.indexOf('T') !== -1) str = str.split('T')[0];
  return str.substring(0, 10);
}

function isValidDate_(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(s));
}

function toHex_(bytes) {
  return bytes.map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
}

function sha256_(text) {
  return toHex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8));
}

function hashPassword_(salt, password) {
  return sha256_(salt + ":" + password);
}

// เปรียบเทียบสตริงแบบไม่หยุดเมื่อเจอตัวอักษรแรกที่ต่าง
function safeEqual_(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// กัน Formula Injection ใน Google Sheets (=, +, -, @ นำหน้า)
function safeCell_(v) {
  let s = String(v == null ? "" : v).trim();
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}

function getSuperCreds_() {
  const p = PropertiesService.getScriptProperties();
  return {
    user: p.getProperty("ADMIN_USER") || "admin",
    pass: p.getProperty("ADMIN_PASSWORD") || ""
  };
}

/* ===================== Session / Auth ===================== */

function createSession_(username, role) {
  const token = (Utilities.getUuid() + Utilities.getUuid()).replace(/-/g, "");
  CacheService.getScriptCache().put(
    "sess_" + token,
    JSON.stringify({ username: username, role: role }),
    SESSION_TTL_SEC
  );
  return token;
}

function getSession_(token) {
  if (!token || typeof token !== "string" || token.length !== 64) return null;
  const raw = CacheService.getScriptCache().get("sess_" + token);
  return raw ? JSON.parse(raw) : null;
}

function requireAdmin_(token, superOnly) {
  const s = getSession_(token);
  if (!s) return null;
  if (superOnly && s.role !== "Super Admin") return null;
  return s;
}

function failKey_(username) {
  return "fail_" + sha256_(String(username).toLowerCase());
}

/**
 * เข้าสู่ระบบ — สำเร็จจะได้ token ให้ส่งกลับมากับทุกคำสั่งของแอดมิน
 * @return {{success:boolean, role?:string, token?:string, message?:string}}
 */
function verifyAdmin(username, password) {
  username = String(username || "").trim();
  password = String(password || "");
  if (!username || !password || username.length > 64 || password.length > 128) {
    return { success: false, message: "ข้อมูลไม่ถูกต้อง" };
  }

  const cache = CacheService.getScriptCache();
  const key = failKey_(username);
  const fails = Number(cache.get(key) || 0);
  if (fails >= MAX_LOGIN_FAILS) {
    return { success: false, message: "กรอกผิดหลายครั้ง กรุณารอ 15 นาทีแล้วลองใหม่" };
  }

  let result = null;

  // Super Admin
  const sup = getSuperCreds_();
  if (!sup.pass && username === sup.user) {
    console.warn("ยังไม่ได้ตั้ง ADMIN_PASSWORD ใน Script properties");
  }
  if (sup.pass && username === sup.user) {
    if (safeEqual_(sha256_(password), sha256_(sup.pass))) {
      result = { role: "Super Admin" };
    }
  } else {
    // Co-Admin (Admins sheet: Username | Salt | Hash)
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Admins");
    if (sheet) {
      const data = sheet.getDataRange().getValues();
      for (let i = 1; i < data.length; i++) {
        if (String(data[i][0]).trim() !== username) continue;
        const salt = String(data[i][1] || "");
        const hash = String(data[i][2] || "");
        if (hash) {
          if (safeEqual_(hashPassword_(salt, password), hash)) result = { role: "Co-Admin" };
        } else if (safeEqual_(String(data[i][1]), password)) {
          // รูปแบบเก่า (รหัสผ่านเป็น plain text ในคอลัมน์ B) -> อัปเกรดเป็น hash ทันที
          const newSalt = Utilities.getUuid();
          sheet.getRange(i + 1, 2, 1, 2).setValues([[newSalt, hashPassword_(newSalt, password)]]);
          result = { role: "Co-Admin" };
        }
        break;
      }
    }
  }

  if (!result) {
    cache.put(key, String(fails + 1), LOGIN_LOCK_SEC);
    Utilities.sleep(500); // หน่วงเล็กน้อยให้เดารหัสช้าลง
    return { success: false, message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" };
  }

  cache.remove(key);
  return {
    success: true,
    role: result.role,
    token: createSession_(username, result.role)
  };
}

function logoutAdmin(token) {
  if (token && typeof token === "string") CacheService.getScriptCache().remove("sess_" + token);
  return { success: true };
}

/** ตรวจว่า token ยังใช้ได้ไหม (ใช้ตอนเปิดหน้าซ้ำ) */
function checkSession(token) {
  const s = getSession_(token);
  return s ? { success: true, role: s.role, username: s.username } : { success: false };
}

/* ===================== Admin management (Super Admin only) ===================== */

function addAdmin(token, username, password) {
  if (!requireAdmin_(token, true)) return { success: false, message: "ไม่มีสิทธิ์ดำเนินการ" };

  username = String(username || "").trim();
  password = String(password || "");
  if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username)) {
    return { success: false, message: "ชื่อผู้ใช้ต้องเป็น a-z 0-9 _ . - ยาว 3-30 ตัว" };
  }
  if (password.length < 8 || password.length > 128) {
    return { success: false, message: "รหัสผ่านต้องยาว 8-128 ตัวอักษร" };
  }
  if (username === getSuperCreds_().user) {
    return { success: false, message: "ไม่สามารถใช้ชื่อบัญชีหลักนี้ได้" };
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return { success: false, message: "ระบบกำลังหนาแน่น กรุณาลองใหม่" };
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName("Admins");
    if (!sheet) {
      sheet = ss.insertSheet("Admins");
      sheet.appendRow(["Username", "Salt", "Hash"]);
      sheet.getRange("A1:C1").setFontWeight("bold").setBackground("#f8fafc");
    }
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === username) {
        return { success: false, message: "ชื่อผู้ใช้นี้มีอยู่ในระบบแล้ว" };
      }
    }
    const salt = Utilities.getUuid();
    sheet.appendRow([username, salt, hashPassword_(salt, password)]);
    return { success: true, message: "เพิ่มแอดมินสำเร็จ" };
  } finally {
    lock.releaseLock();
  }
}

function getAdmins(token) {
  if (!requireAdmin_(token, true)) return [];
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Admins");
  if (!sheet) return [];
  const data = sheet.getDataRange().getValues();
  const list = [];
  for (let i = 1; i < data.length; i++) {
    if (data[i][0]) list.push(String(data[i][0]).trim());
  }
  return list;
}

function removeAdmin(token, username) {
  if (!requireAdmin_(token, true)) return { success: false };
  username = String(username || "").trim();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return { success: false };
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Admins");
    if (!sheet) return { success: false };
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === username) {
        sheet.deleteRow(i + 1);
        return { success: true };
      }
    }
    return { success: false };
  } finally {
    lock.releaseLock();
  }
}

/**
 * รันมือครั้งเดียวจาก Apps Script editor เพื่อแปลงรหัสผ่านเก่าในชีต Admins เป็น hash ทั้งหมด
 */
function migrateAdminPasswords() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Admins");
  if (!sheet) return;
  const data = sheet.getDataRange().getValues();
  sheet.getRange("A1:C1").setValues([["Username", "Salt", "Hash"]]);
  for (let i = 1; i < data.length; i++) {
    if (!data[i][0] || data[i][2]) continue;          // ว่างหรือเป็น hash แล้ว
    const plain = String(data[i][1]);
    const salt = Utilities.getUuid();
    sheet.getRange(i + 1, 2, 1, 2).setValues([[salt, hashPassword_(salt, plain)]]);
  }
}

/* ===================== Attendance ===================== */

/**
 * (ไม่บังคับ) ถ้ามีชีต "Students" คอลัมน์ A = รายชื่อ จะอนุญาตเฉพาะชื่อในรายการ
 */
function isKnownStudent_(ss, name) {
  const list = readStudents_(ss);
  return list.length === 0 || list.indexOf(name) !== -1;
}

// หาชีตรายชื่อ: รับ Students / students / รายชื่อ / รายชื่อนักเรียน (ไม่สนตัวพิมพ์เล็ก-ใหญ่และช่องว่างหัวท้าย)
function findStudentSheet_(ss) {
  const wanted = ["students", "รายชื่อ", "รายชื่อนักเรียน"];
  const sheets = ss.getSheets();
  for (let i = 0; i < sheets.length; i++) {
    if (wanted.indexOf(sheets[i].getName().trim().toLowerCase()) !== -1) return sheets[i];
  }
  return null;
}

function readStudents_(ss) {
  const sheet = findStudentSheet_(ss);
  if (!sheet || sheet.getLastRow() < 1) return [];
  return sheet.getRange(1, 1, sheet.getLastRow(), 1).getValues()
    .map(function (r) { return String(r[0]).trim(); })
    .filter(function (n) { return n; });
}

/**
 * รันมือจาก Apps Script editor (เลือกฟังก์ชัน debugSetup > Run) แล้วดูผลที่ Execution log
 * ใช้ตรวจว่าผูกกับสเปรดชีตถูกไหม มีชีตรายชื่อไหม และตั้งรหัสแอดมินแล้วหรือยัง (ไม่แสดงรหัสผ่าน)
 */
function debugSetup() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) {
    console.log("❌ สคริปต์นี้ไม่ได้ผูกกับ Google Sheet — ต้องสร้างจาก Sheet > ส่วนขยาย > Apps Script");
  } else {
    console.log("✅ สเปรดชีต: " + ss.getName());
    console.log("ชีตทั้งหมด: " + ss.getSheets().map(function (s) { return "[" + s.getName() + "]"; }).join(" "));
    const st = readStudents_(ss);
    console.log(st.length
      ? "✅ พบรายชื่อนักเรียน " + st.length + " คน (คนแรก: " + st[0] + ")"
      : "❌ ไม่พบรายชื่อ — ต้องมีชีตชื่อ Students และใส่ชื่อที่คอลัมน์ A");
  }
  const c = getSuperCreds_();
  console.log("ADMIN_USER ที่ใช้ล็อกอิน: [" + c.user + "]");
  console.log(c.pass
    ? "✅ ตั้ง ADMIN_PASSWORD แล้ว (ความยาว " + c.pass.length + " ตัว; ถ้ามีเว้นวรรคหัวท้ายให้แก้)"
    : "❌ ยังไม่ได้ตั้ง ADMIN_PASSWORD ใน Script properties");
}

/**
 * รายชื่อนักเรียนสำหรับ dropdown (ชีต "Students" คอลัมน์ A) — สาธารณะ ไม่มีข้อมูลอื่นนอกจากชื่อ
 */
function getStudents() {
  return readStudents_(SpreadsheetApp.getActiveSpreadsheet());
}

/**
 * บันทึกการเช็คชื่อ
 * - วัน/เวลา: ใช้เวลาเซิร์ฟเวอร์เสมอ (แอดมินที่ล็อกอินเท่านั้นที่ระบุวันย้อนหลังได้)
 * - role: นักเรียนทั่วไป = "นักเรียน", แอดมิน = ชื่อบัญชีที่ล็อกอิน (ไม่เชื่อค่าจาก client)
 */
function saveAttendance(data) {
  if (!data || typeof data !== "object") return { success: false, message: "ข้อมูลไม่ถูกต้อง" };

  const session = getSession_(data.token);
  const name = String(data.name || "").trim();
  if (!name || name.length > 100) return { success: false, message: "กรุณาเลือกชื่อ" };

  const now = new Date();
  let date = Utilities.formatDate(now, TZ, "yyyy-MM-dd");
  if (session && data.date && isValidDate_(data.date)) date = String(data.date);
  const time = Utilities.formatDate(now, TZ, "HH:mm:ss");

  const zone = data.zone === true || data.zone === "true";
  const line = data.line === true || data.line === "true";
  const duty = data.duty === true || data.duty === "true";
  if (!zone && !line && !duty) return { success: false, message: "กรุณาเลือกสถานะอย่างน้อย 1 อย่าง" };

  const role = session ? session.username : "นักเรียน";

  // ตรวจรูปก่อนเข้า lock
  let photoBlob = null;
  if (data.photoBase64) {
    const photo = String(data.photoBase64);
    const m = /^data:(image\/[a-z]+);base64,/.exec(photo.substring(0, 40));
    if (!m || !PHOTO_MIME[m[1]]) return { success: false, message: "ชนิดไฟล์รูปไม่รองรับ" };
    if (photo.length > MAX_PHOTO_CHARS) return { success: false, message: "รูปมีขนาดใหญ่เกินไป" };
    const safeName = name.replace(/[^\wก-๙\-]/g, "_").substring(0, 60);
    const stamp = time.replace(/:/g, "");
    photoBlob = Utilities.newBlob(
      Utilities.base64Decode(photo.substring(m[0].length)),
      m[1],
      safeName + "_" + date + "_" + stamp + "." + PHOTO_MIME[m[1]]
    );
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) {
    return { success: false, message: "ระบบกำลังหนาแน่น กรุณาลองใหม่อีกครั้ง" };
  }
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!isKnownStudent_(ss, name)) return { success: false, message: "ไม่พบชื่อนี้ในรายชื่อ" };

    let sheet = ss.getSheetByName("Attendance");
    if (!sheet) {
      sheet = ss.insertSheet("Attendance");
      sheet.appendRow(["วันที่", "เวลา", "ชื่อ-นามสกุล", "เข้าเขต", "เข้าแถว", "ทำเวร", "ผู้บันทึก", "รูปลิงก์"]);
      sheet.getRange("A1:H1").setFontWeight("bold").setBackground("#f8fafc");
      sheet.getRange("A:A").setNumberFormat("@");
    }

    // หาแถวเดิมของวันเดียวกัน (อ่านเฉพาะคอลัมน์ A-C)
    let rowIndex = -1;
    const last = sheet.getLastRow();
    if (last > 1) {
      const keys = sheet.getRange(2, 1, last - 1, 3).getValues();
      for (let i = 0; i < keys.length; i++) {
        if (normalizeDate(keys[i][0]) === date && String(keys[i][2]).trim() === name) {
          rowIndex = i + 2;
          break;
        }
      }
    }

    let existing = null;
    if (rowIndex !== -1) existing = sheet.getRange(rowIndex, 1, 1, 8).getValues()[0];

    // นักเรียนต้องมีรูปหลักฐาน (ในแถวใหม่ หรือมีอยู่แล้ว)
    const hasOldPhoto = existing && existing[7] && String(existing[7]) !== "-";
    if (!session && !photoBlob && !hasOldPhoto) {
      return { success: false, message: "กรุณาถ่ายรูปหลักฐาน" };
    }

    let photoUrl = hasOldPhoto ? existing[7] : "-";
    if (photoBlob) {
      const folders = DriveApp.getFoldersByName("TRAE_SOLO_Photos");
      const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder("TRAE_SOLO_Photos");
      const file = folder.createFile(photoBlob);
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
      photoUrl = file.getUrl();
    }

    if (existing) {
      const z = String(existing[3]).indexOf("✅") !== -1 || zone;
      const l = String(existing[4]).indexOf("✅") !== -1 || line;
      const d = String(existing[5]).indexOf("✅") !== -1 || duty;
      sheet.getRange(rowIndex, 2, 1, 7).setValues([[
        time, existing[2], z ? "✅" : "-", l ? "✅" : "-", d ? "✅" : "-", role, photoUrl
      ]]);
    } else {
      sheet.appendRow([
        date, time, safeCell_(name),
        zone ? "✅" : "-", line ? "✅" : "-", duty ? "✅" : "-",
        safeCell_(role), photoUrl
      ]);
    }

    return { success: true, message: "บันทึกข้อมูลสำเร็จเรียบร้อย" };
  } catch (error) {
    console.error(error);
    return { success: false, message: "เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่" };
  } finally {
    lock.releaseLock();
  }
}

/**
 * สถิติรายวัน — ทุกคนดูสถานะได้ แต่ลิงก์รูปและชื่อผู้บันทึกเห็นเฉพาะแอดมินที่ล็อกอิน
 */
function getDailyStats(dateStr, token) {
  try {
    const target = String(dateStr || "").trim();
    if (!isValidDate_(target)) return {};

    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Attendance");
    if (!sheet || sheet.getLastRow() < 2) return {};

    const isAdmin = !!getSession_(token);
    const data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 8).getValues();
    const result = {};
    for (let i = 0; i < data.length; i++) {
      if (normalizeDate(data[i][0]) !== target) continue;
      const studentName = String(data[i][2]).trim();
      result[studentName] = {
        time: data[i][1],
        zone: String(data[i][3]).indexOf("✅") !== -1,
        line: String(data[i][4]).indexOf("✅") !== -1,
        duty: String(data[i][5]).indexOf("✅") !== -1,
        role: isAdmin ? data[i][6] : "",
        photo: isAdmin ? data[i][7] : ""
      };
    }
    return result;
  } catch (e) {
    console.error(e);
    return {};
  }
}
