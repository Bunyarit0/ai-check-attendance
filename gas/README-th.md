# คู่มือติดตั้งเวอร์ชันปลอดภัย (Google Apps Script)

## 1) ตั้งรหัสผ่านแอดมิน (ไม่ฝังในโค้ดแล้ว)
Apps Script → ⚙️ Project Settings → **Script properties** → Add:

| Property | ค่า |
|---|---|
| `ADMIN_USER` | ชื่อผู้ใช้หลัก (ไม่ใส่ = `admin`) |
| `ADMIN_PASSWORD` | รหัสผ่านใหม่ ยาว ๆ **ห้ามใช้รหัสเดิมที่เคยฝังในโค้ด เพราะถือว่าหลุดแล้ว** |

## 2) วางไฟล์
- `รหัส.gs` ← วางเนื้อหา `gas/Code.gs` ทั้งหมดแทนของเดิม
- Project Settings → ติ๊ก "Show appsscript.json" แล้ววางเนื้อหา `gas/appsscript.json`
- รันฟังก์ชัน `migrateAdminPasswords` หนึ่งครั้ง (แปลงรหัส Co-Admin เก่าเป็น hash) แล้วอนุญาตสิทธิ์
- (ไม่บังคับ) สร้างชีต `Students` ใส่รายชื่อคอลัมน์ A → ระบบจะรับเฉพาะชื่อในรายการ กันพิมพ์ชื่อมั่ว

## 3) แก้ Index.html ฝั่ง client (สำคัญ)
ฟังก์ชันฝั่งแอดมินต้องส่ง `token` ที่ได้ตอนล็อกอิน (เก็บในตัวแปร JS ไม่ใช้ localStorage):

```js
let adminToken = null;

// ล็อกอิน
google.script.run.withSuccessHandler(res => {
  if (res.success) { adminToken = res.token; /* แสดงหน้าแอดมิน, res.role */ }
  else showToast(res.message || "เข้าสู่ระบบไม่สำเร็จ");
}).verifyAdmin(user, pw);

// ออกจากระบบ
google.script.run.logoutAdmin(adminToken); adminToken = null;

// บันทึก (ไม่ต้องส่ง date/time/role แล้ว ฝั่งเซิร์ฟเวอร์กำหนดเอง)
google.script.run.withSuccessHandler(cb).saveAttendance({
  name, zone, line, duty, photoBase64,
  token: adminToken,          // null สำหรับนักเรียน
  date: selectedDate          // ใช้ได้เฉพาะแอดมิน (ย้อนหลัง)
});

// สถิติ
google.script.run.withSuccessHandler(render).getDailyStats(dateStr, adminToken);

// จัดการแอดมิน (Super Admin เท่านั้น)
google.script.run.addAdmin(adminToken, username, password);
google.script.run.getAdmins(adminToken);
google.script.run.removeAdmin(adminToken, username);
```

ย่อรูปก่อนส่ง (ลดขนาด/เร็วขึ้น):
```js
function resizeImage(file, max = 900, q = 0.7) {
  return new Promise(res => {
    const img = new Image();
    img.onload = () => {
      const k = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = img.width * k; c.height = img.height * k;
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      res(c.toDataURL('image/jpeg', q));
    };
    img.src = URL.createObjectURL(file);
  });
}
```
อย่าใช้ `innerHTML` กับชื่อ/ข้อมูลจากชีต ให้ใช้ `textContent` เพื่อกัน XSS

## 4) Deploy
Deploy → Manage deployments → ✏️ → Version: **New version** → Deploy (ทุกครั้งที่แก้โค้ด)

## สิ่งที่แก้แล้ว
- รหัสผ่านย้ายไป Script Properties; รหัส Co-Admin เก็บเป็น SHA-256 + salt (รูปแบบเก่าอัปเกรดอัตโนมัติ)
- Session token (สุ่ม 256 บิต หมดอายุ 6 ชม.) ทุกฟังก์ชันแอดมินตรวจสิทธิ์ฝั่งเซิร์ฟเวอร์; จัดการแอดมินได้เฉพาะ Super Admin
- กันเดารหัส: ผิด 5 ครั้งล็อก 15 นาที
- วัน/เวลา/ผู้บันทึกกำหนดฝั่งเซิร์ฟเวอร์ (โซนเวลา Asia/Bangkok)
- ตรวจชนิด/ขนาดรูป, ตั้งชื่อไฟล์ปลอดภัย, กัน formula injection ในชีต
- ลิงก์รูป/ผู้บันทึกในหน้าสถิติเห็นเฉพาะแอดมิน
- ซ่อนข้อความ error ภายในจากผู้ใช้

## ข้อจำกัดที่ยังเหลือ (ควรรู้)
- นักเรียนยังเช็คชื่อแทนกันได้ถ้าไม่มี PIN/บัญชี Google ต่อคน (ถ้าต้องการ แจ้งได้ จะเพิ่ม PIN ต่อคนให้)
- ลิงก์รูปเป็น "ทุกคนที่มีลิงก์" (ไม่เดาได้ แต่ถ้าลิงก์หลุดก็เปิดได้)
