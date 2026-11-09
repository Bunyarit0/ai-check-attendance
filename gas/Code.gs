/**
 * TRAE SOLO Attendance System - Backend Script (Secure version)
 *
 * ตั้งค่าก่อนใช้งาน (Project Settings > Script properties):
 *   ADMIN_USER      ชื่อผู้ใช้ Super Admin (ไม่ตั้ง = "admin")
 *   ADMIN_PASSWORD  รหัสผ่าน Super Admin (ต้องตั้ง ไม่งั้นล็อกอิน Super Admin ไม่ได้)
 *
 * ชีตที่ใช้: Attendance, Admins, Pins (สร้างและซ่อนให้เอง), รายชื่อ (Students)
 */

const TZ = "Asia/Bangkok";
const SESSION_TTL_SEC = 6 * 60 * 60;   // 6 ชั่วโมง (สูงสุดของ CacheService)
const MAX_LOGIN_FAILS = 5;
const MAX_PIN_FAILS = 5;
const LOGIN_LOCK_SEC = 15 * 60;        // ล็อก 15 นาทีเมื่อกรอกผิดครบ
const MAX_PHOTO_CHARS = 3500000;       // ~2.6MB หลังถอด base64
const PHOTO_MIME = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };
const ABSENCE_TYPES = ["", "ลา", "ติดกิจกรรม"];
const HISTORY_LIMIT = 120;

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

function isChecked_(v) {
  return String(v).indexOf("✅") !== -1 || String(v).toUpperCase() === "TRUE";
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
          // รูปแบบเก่า (plain text คอลัมน์ B) -> อัปเกรดเป็น hash ทันที
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
    Utilities.sleep(500);
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

/** รันมือครั้งเดียวเพื่อแปลงรหัสผ่านเก่าในชีต Admins เป็น hash ทั้งหมด */
function migrateAdminPasswords() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Admins");
  if (!sheet) return;
  const data = sheet.getDataRange().getValues();
  sheet.getRange("A1:C1").setValues([["Username", "Salt", "Hash"]]);
  for (let i = 1; i < data.length; i++) {
    if (!data[i][0] || data[i][2]) continue;
    const plain = String(data[i][1]);
    const salt = Utilities.getUuid();
    sheet.getRange(i + 1, 2, 1, 2).setValues([[salt, hashPassword_(salt, plain)]]);
  }
}

/* ===================== Roster ===================== */

// หาชีตรายชื่อ: Students / รายชื่อ / รายชื่อนักเรียน (ไม่สนตัวพิมพ์) หรือชีตเดียวที่เหลือนอกจากชีตระบบ
function findStudentSheet_(ss) {
  const wanted = ["students", "รายชื่อ", "รายชื่อนักเรียน"];
  const sheets = ss.getSheets();
  for (let i = 0; i < sheets.length; i++) {
    if (wanted.indexOf(sheets[i].getName().trim().toLowerCase()) !== -1) return sheets[i];
  }
  const system = ["attendance", "admins", "pins"];
  const others = sheets.filter(function (s) {
    return system.indexOf(s.getName().trim().toLowerCase()) === -1;
  });
  return others.length === 1 ? others[0] : null;
}

function readStudents_(ss) {
  const sheet = findStudentSheet_(ss);
  if (!sheet || sheet.getLastRow() < 1) return [];
  return sheet.getRange(1, 1, sheet.getLastRow(), 1).getValues()
    .map(function (r) { return String(r[0]).trim(); })
    .filter(function (n) { return n; });
}

function isKnownStudent_(ss, name) {
  const list = readStudents_(ss);
  return list.length === 0 || list.indexOf(name) !== -1;
}

/** รายชื่อนักเรียนสำหรับ dropdown — สาธารณะ มีเฉพาะชื่อ */
function getStudents() {
  return readStudents_(SpreadsheetApp.getActiveSpreadsheet());
}

/* ===================== Student PIN ===================== */

function getPinSheet_(ss, create) {
  let sheet = ss.getSheetByName("Pins");
  if (!sheet && create) {
    sheet = ss.insertSheet("Pins");
    sheet.appendRow(["Name", "Salt", "Hash", "Updated"]);
    sheet.getRange("A1:D1").setFontWeight("bold").setBackground("#f8fafc");
    sheet.hideSheet();
  }
  return sheet;
}

function findPinRow_(sheet, name) {
  if (!sheet || sheet.getLastRow() < 2) return null;
  const v = sheet.getRange(2, 1, sheet.getLastRow() - 1, 3).getValues();
  for (let i = 0; i < v.length; i++) {
    if (String(v[i][0]).trim() === name) {
      return { row: i + 2, salt: String(v[i][1]), hash: String(v[i][2]) };
    }
  }
  return null;
}

function hashPin_(salt, name, pin) {
  return sha256_(salt + ":" + name + ":" + pin);
}

/**
 * ตรวจ PIN ของนักเรียน
 * - allowCreate=true และยังไม่เคยตั้ง PIN -> ตั้งจาก PIN ที่ส่งมา (เรียกภายใน lock เท่านั้น)
 * - ผิด 5 ครั้งล็อกชื่อนั้น 15 นาที (กรรมการรีเซ็ตได้)
 */
function checkPin_(ss, name, pin, allowCreate) {
  const cache = CacheService.getScriptCache();
  const key = "pinfail_" + sha256_(name);
  const fails = Number(cache.get(key) || 0);
  if (fails >= MAX_PIN_FAILS) {
    return { ok: false, message: "กรอก PIN ผิดหลายครั้ง กรุณารอ 15 นาที หรือให้กรรมการรีเซ็ต PIN" };
  }
  pin = String(pin || "");
  const cellName = safeCell_(name);
  const sheet = getPinSheet_(ss, allowCreate);
  const found = findPinRow_(sheet, cellName);

  if (!found) {
    if (!allowCreate) return { ok: false, needPin: true, message: "ยังไม่ได้ตั้ง PIN (ตั้งได้ตอนเช็คชื่อครั้งแรก)" };
    if (!/^\d{4,6}$/.test(pin)) return { ok: false, message: "PIN ต้องเป็นตัวเลข 4-6 หลัก" };
    const salt = Utilities.getUuid();
    sheet.appendRow([cellName, salt, hashPin_(salt, cellName, pin), Utilities.formatDate(new Date(), TZ, "yyyy-MM-dd HH:mm")]);
    return { ok: true, created: true };
  }

  if (safeEqual_(hashPin_(found.salt, cellName, pin), found.hash)) {
    cache.remove(key);
    return { ok: true };
  }
  cache.put(key, String(fails + 1), LOGIN_LOCK_SEC);
  return { ok: false, message: "PIN ไม่ถูกต้อง" };
}

/** หน้าเว็บใช้ถามว่าชื่อนี้เคยตั้ง PIN แล้วหรือยัง (เพื่อเลือกแสดงช่องตั้ง/กรอก PIN) */
function getPinStatus(name) {
  name = String(name || "").trim();
  if (!name || name.length > 100) return { hasPin: false };
  const sheet = getPinSheet_(SpreadsheetApp.getActiveSpreadsheet(), false);
  return { hasPin: !!findPinRow_(sheet, safeCell_(name)) };
}

/** กรรมการ (ทุกระดับ) รีเซ็ต PIN ของนักเรียน — นักเรียนจะตั้ง PIN ใหม่ตอนเช็คครั้งถัดไป */
function resetStudentPin(token, name) {
  if (!requireAdmin_(token, false)) return { success: false, message: "ไม่มีสิทธิ์ดำเนินการ" };
  name = String(name || "").trim();
  if (!name) return { success: false, message: "กรุณาเลือกชื่อ" };

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return { success: false, message: "ระบบกำลังหนาแน่น กรุณาลองใหม่" };
  try {
    const sheet = getPinSheet_(SpreadsheetApp.getActiveSpreadsheet(), false);
    const found = findPinRow_(sheet, safeCell_(name));
    CacheService.getScriptCache().remove("pinfail_" + sha256_(name));
    if (!found) return { success: true, message: "นักเรียนคนนี้ยังไม่ได้ตั้ง PIN" };
    sheet.deleteRow(found.row);
    return { success: true, message: "รีเซ็ต PIN แล้ว" };
  } finally {
    lock.releaseLock();
  }
}

/* ===================== Attendance ===================== */

function ensureAttendanceHeaders_(sheet) {
  if (String(sheet.getRange("I1").getValue()) === "") {
    sheet.getRange("I1:J1").setValues([["ลา/กิจกรรม", "หมายเหตุ"]]).setFontWeight("bold").setBackground("#f8fafc");
  }
}

/**
 * บันทึกการเช็คชื่อ
 * - วัน/เวลา: ใช้เวลาเซิร์ฟเวอร์เสมอ (แอดมินที่ล็อกอินเท่านั้นที่ระบุวันย้อนหลังได้)
 * - นักเรียน: ต้องส่ง PIN (ครั้งแรกจะตั้ง PIN ให้จากค่าที่ส่งมา); แอดมิน: ใช้ token ไม่ต้อง PIN
 * - สถานะพิเศษ: absence = "" | "ลา" | "ติดกิจกรรม" (+ note) — ไม่ต้องแนบรูป
 */
function saveAttendance(data) {
  if (!data || typeof data !== "object") return { success: false, message: "ข้อมูลไม่ถูกต้อง" };

  const session = getSession_(data.token);
  const name = String(data.name || "").trim();
  if (!name || name.length > 100) return { success: false, message: "กรุณาเลือกชื่อ" };

  const absence = String(data.absence || "");
  if (ABSENCE_TYPES.indexOf(absence) === -1) return { success: false, message: "สถานะไม่ถูกต้อง" };
  const note = safeCell_(String(data.note || "").substring(0, 200));

  const now = new Date();
  let date = Utilities.formatDate(now, TZ, "yyyy-MM-dd");
  if (session && data.date && isValidDate_(data.date)) date = String(data.date);
  const time = Utilities.formatDate(now, TZ, "HH:mm:ss");

  const zone = data.zone === true || data.zone === "true";
  const line = data.line === true || data.line === "true";
  const duty = data.duty === true || data.duty === "true";
  if (!zone && !line && !duty && !absence) {
    return { success: false, message: "กรุณาเลือกสถานะอย่างน้อย 1 อย่าง" };
  }

  if (!session && !/^\d{4,6}$/.test(String(data.pin || ""))) {
    return { success: false, message: "กรุณากรอก PIN (ตัวเลข 4-6 หลัก)" };
  }

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

    let pinCreated = false;
    if (!session) {
      const p = checkPin_(ss, name, data.pin, true);
      if (!p.ok) return { success: false, message: p.message };
      pinCreated = !!p.created;
    }

    let sheet = ss.getSheetByName("Attendance");
    if (!sheet) {
      sheet = ss.insertSheet("Attendance");
      sheet.appendRow(["วันที่", "เวลา", "ชื่อ-นามสกุล", "เข้าเขต", "เข้าแถว", "ทำเวร", "ผู้บันทึก", "รูปลิงก์", "ลา/กิจกรรม", "หมายเหตุ"]);
      sheet.getRange("A1:J1").setFontWeight("bold").setBackground("#f8fafc");
      sheet.getRange("A:A").setNumberFormat("@");
    } else {
      ensureAttendanceHeaders_(sheet);
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
    if (rowIndex !== -1) existing = sheet.getRange(rowIndex, 1, 1, 10).getValues()[0];

    // นักเรียนต้องมีรูปหลักฐาน (ยกเว้นลา/ติดกิจกรรม หรือมีรูปอยู่แล้ว)
    const hasOldPhoto = existing && existing[7] && String(existing[7]) !== "-";
    if (!session && !absence && !photoBlob && !hasOldPhoto) {
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

    const absenceCell = absence || "-";
    const noteCell = (absence && note) ? note : "-";

    if (existing) {
      const z = isChecked_(existing[3]) || zone;
      const l = isChecked_(existing[4]) || line;
      const d = isChecked_(existing[5]) || duty;
      sheet.getRange(rowIndex, 2, 1, 9).setValues([[
        time, existing[2], z ? "✅" : "-", l ? "✅" : "-", d ? "✅" : "-",
        role, photoUrl, absenceCell, noteCell
      ]]);
    } else {
      sheet.appendRow([
        date, time, safeCell_(name),
        zone ? "✅" : "-", line ? "✅" : "-", duty ? "✅" : "-",
        safeCell_(role), photoUrl, absenceCell, noteCell
      ]);
    }

    return {
      success: true,
      pinCreated: pinCreated,
      message: pinCreated ? "บันทึกสำเร็จ และตั้ง PIN เรียบร้อยแล้ว" : "บันทึกข้อมูลสำเร็จเรียบร้อย"
    };
  } catch (error) {
    console.error(error);
    return { success: false, message: "เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่" };
  } finally {
    lock.releaseLock();
  }
}

/**
 * สถิติรายวัน — ทุกคนเห็นสถานะ/ประเภทลา; ลิงก์รูป ผู้บันทึก และหมายเหตุ เห็นเฉพาะแอดมิน
 */
function getDailyStats(dateStr, token) {
  try {
    const target = String(dateStr || "").trim();
    if (!isValidDate_(target)) return {};

    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Attendance");
    if (!sheet || sheet.getLastRow() < 2) return {};

    const isAdmin = !!getSession_(token);
    // getDisplayValues: ข้อความล้วน (google.script.run ส่ง Date object กลับไม่ได้)
    const data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 10).getDisplayValues();
    const result = {};
    for (let i = 0; i < data.length; i++) {
      if (normalizeDate(data[i][0]) !== target) continue;
      const studentName = String(data[i][2]).trim();
      const absence = String(data[i][8]) === "-" ? "" : String(data[i][8]);
      result[studentName] = {
        time: String(data[i][1]),
        zone: isChecked_(data[i][3]),
        line: isChecked_(data[i][4]),
        duty: isChecked_(data[i][5]),
        absence: absence,
        role: isAdmin ? String(data[i][6]) : "",
        photo: isAdmin ? String(data[i][7]) : "",
        note: isAdmin && String(data[i][9]) !== "-" ? String(data[i][9]) : ""
      };
    }
    return result;
  } catch (e) {
    console.error(e);
    return {};
  }
}

/**
 * ประวัติการเช็คของนักเรียนคนหนึ่ง (ต้องยืนยันด้วย PIN ของตัวเอง)
 */
function getMyHistory(name, pin) {
  try {
    name = String(name || "").trim();
    if (!name || name.length > 100) return { success: false, message: "กรุณาเลือกชื่อ" };
    if (!/^\d{4,6}$/.test(String(pin || ""))) return { success: false, message: "กรุณากรอก PIN (ตัวเลข 4-6 หลัก)" };

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!isKnownStudent_(ss, name)) return { success: false, message: "ไม่พบชื่อนี้ในรายชื่อ" };

    const p = checkPin_(ss, name, pin, false);
    if (!p.ok) return { success: false, needPin: !!p.needPin, message: p.message };

    const sheet = ss.getSheetByName("Attendance");
    const items = [];
    if (sheet && sheet.getLastRow() > 1) {
      const data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 10).getDisplayValues();
      for (let i = data.length - 1; i >= 0 && items.length < HISTORY_LIMIT; i--) {
        if (String(data[i][2]).trim() !== name) continue;
        items.push({
          date: normalizeDate(data[i][0]),
          time: String(data[i][1]),
          zone: isChecked_(data[i][3]),
          line: isChecked_(data[i][4]),
          duty: isChecked_(data[i][5]),
          photo: String(data[i][7]),
          absence: String(data[i][8]) === "-" ? "" : String(data[i][8]),
          note: String(data[i][9]) === "-" ? "" : String(data[i][9])
        });
      }
    }
    return { success: true, items: items };
  } catch (e) {
    console.error(e);
    return { success: false, message: "เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่" };
  }
}

/* ===================== Debug ===================== */

/**
 * รันมือจาก Apps Script editor แล้วดู Execution log
 * ตรวจว่าผูกกับสเปรดชีตถูกไหม มีชีตรายชื่อไหม และตั้งรหัสแอดมินแล้วหรือยัง (ไม่แสดงรหัสผ่าน)
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
