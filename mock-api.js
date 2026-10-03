/* =====================================================================
   1st Pay — DEMO mock API (ใช้กับ GitHub Pages / เปิดไฟล์ตรง ๆ)
   ---------------------------------------------------------------------
   จำลอง endpoint /v1/* ของ backend จริงทั้งหมดภายใน browser
   - ข้อมูลผู้ใช้เก็บใน localStorage ของผู้ทดลองแต่ละคนเท่านั้น (ไม่ส่งออกไปไหน)
   - ไม่มีการส่ง SMS / Email จริง — OTP แสดงบนหน้าจอ (Sandbox)
   - กติกาเหมือนระบบจริง: รูปแบบเบอร์ลาว, OTP 6 หลัก หมดอายุ 5 นาที ผิดได้ 5 ครั้ง,
     ขอใหม่ทุก 60 วินาที, PIN ห้ามเลขซ้ำ/เรียง, PIN ผิด 5 ครั้งล็อก 15 นาที
   ===================================================================== */
(function () {
  "use strict";
  const KEY = "1p_demo_db_v1";
  const OTP_TTL = 300, COOLDOWN = 60, MAX_ATTEMPTS = 5, PIN_FAILS = 5, LOCK_MIN = 15;
  const ACCESS_TTL = 15 * 60, REFRESH_TTL = 7 * 86400;

  const now = () => Math.floor(Date.now() / 1000);
  const rid = (n = 16) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, "0")).join("");
  const load = () => { try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch (e) { return {}; } };
  const db = Object.assign({ users: {}, otps: {}, vts: {}, tokens: {}, cool: {} }, load());
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) {} };

  async function sha256(s) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, "0")).join("");
  }
  class E extends Error { constructor(code, status, extra) { super(code); this.code = code; this.status = status || 400; this.extra = extra || {}; } }

  function normPhone(raw) {
    const d = String(raw || "").replace(/[\s\-()]/g, "");
    const m = d.match(/^(?:\+?856|0)?(20\d{8}|30\d{7})$/);
    if (!m) throw new E("ERR_PHONE_FORMAT");
    return "+856" + m[1];
  }
  function normEmail(raw) {
    const e = String(raw || "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw new E("ERR_EMAIL_FORMAT");
    return e;
  }
  const norm = (ch, d) => ch === "sms" ? normPhone(d) : normEmail(d);
  const mask = (ch, d) => ch === "sms" ? d.slice(0, 6) + "*".repeat(Math.max(d.length - 9, 0)) + d.slice(-3) : d.slice(0, 2) + "***@" + d.split("@")[1];
  const findUser = (ch, d) => Object.values(db.users).find(u => (ch === "sms" ? u.phone : u.email) === d);
  function pinStrength(pin) {
    if (!/^\d{6}$/.test(pin)) throw new E("ERR_PIN_FORMAT");
    if (new Set(pin).size === 1) throw new E("ERR_PIN_WEAK");
    const diffs = new Set(); for (let i = 0; i < 5; i++) diffs.add(+pin[i + 1] - +pin[i]);
    if (diffs.size === 1 && (diffs.has(1) || diffs.has(-1))) throw new E("ERR_PIN_WEAK");
  }
  const pub = u => ({ id: u.id, phone: u.phone, email: u.email, full_name: u.full_name, account_type: u.account_type, kyc_level: 0, status: "active", lang: u.lang });
  function issue(u) {
    const a = "demo_at_" + rid(), r = "demo_rt_" + rid();
    db.tokens[a] = { uid: u.id, typ: "access", exp: now() + ACCESS_TTL };
    db.tokens[r] = { uid: u.id, typ: "refresh", exp: now() + REFRESH_TTL };
    save();
    return { access_token: a, refresh_token: r, token_type: "bearer", expires_in: ACCESS_TTL };
  }
  function authUser(headers) {
    const h = headers && (headers.Authorization || headers.authorization) || "";
    const tk = db.tokens[h.replace(/^Bearer\s+/i, "")];
    if (!tk || tk.typ !== "access" || tk.exp < now()) throw new E("ERR_TOKEN_EXPIRED", 401);
    return db.users[tk.uid];
  }
  function useVt(token, purpose) {
    const v = db.vts[token];
    if (!v || v.exp < now()) throw new E("ERR_TOKEN_EXPIRED", 401);
    if (v.purpose !== purpose) throw new E("ERR_TOKEN_INVALID", 401);
    if (v.used) throw new E("ERR_TOKEN_USED", 401);
    v.used = true; save(); return v;
  }

  const routes = {
    "POST /v1/auth/otp/request": async (b) => {
      const dest = norm(b.channel, b.destination);
      const c = db.cool[dest];
      if (c && c > now()) throw new E("ERR_OTP_COOLDOWN", 429, { retry_after: c - now() });
      const purpose = b.purpose || "register", existing = findUser(b.channel, dest);
      if ((purpose === "register" || purpose === "add_contact") && existing) throw new E("ERR_ALREADY_REGISTERED", 409);
      const ref = rid(12), code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      db.otps[ref] = { h: await sha256(ref + ":" + code), ch: b.channel, dest, purpose, attempts: 0, exp: now() + OTP_TTL };
      db.cool[dest] = now() + COOLDOWN; save();
      const out = { otp_ref: ref, expires_in: OTP_TTL, resend_after: COOLDOWN, sent_to: mask(b.channel, dest) };
      if (!(purpose === "reset_pin" && !existing)) out.dev_otp = code;
      return out;
    },
    "POST /v1/auth/otp/verify": async (b) => {
      const o = db.otps[b.otp_ref];
      if (!o || o.exp < now()) throw new E("ERR_OTP_EXPIRED");
      if (o.h !== await sha256(b.otp_ref + ":" + b.code)) {
        o.attempts++; const left = MAX_ATTEMPTS - o.attempts;
        if (left <= 0) { delete db.otps[b.otp_ref]; save(); throw new E("ERR_OTP_LOCKED"); }
        save(); throw new E("ERR_OTP_INVALID", 400, { attempts_left: left });
      }
      delete db.otps[b.otp_ref];
      const vt = "demo_vt_" + rid();
      db.vts[vt] = { ch: o.ch, dest: o.dest, purpose: o.purpose, exp: now() + 600 }; save();
      return { verification_token: vt, expires_in: 600 };
    },
    "POST /v1/auth/register": async (b) => {
      pinStrength(b.pin);
      const v = useVt(b.verification_token, "register");
      if (findUser(v.ch, v.dest)) throw new E("ERR_ALREADY_REGISTERED", 409);
      const u = { id: crypto.randomUUID ? crypto.randomUUID() : rid(16), phone: v.ch === "sms" ? v.dest : null, email: v.ch === "email" ? v.dest : null,
        full_name: b.full_name || null, account_type: b.account_type || "customer", lang: b.lang || "lo", pin: await sha256("pin:" + b.pin), fails: 0, lock: 0 };
      db.users[u.id] = u; save();
      return { user: pub(u), tokens: issue(u) };
    },
    "POST /v1/auth/login": async (b) => {
      const id = String(b.identifier || "").trim();
      let u;
      try { u = id.includes("@") ? findUser("email", normEmail(id)) : findUser("sms", normPhone(id)); } catch (e) { u = null; }
      if (!u) throw new E("ERR_LOGIN_FAILED", 401);
      if (u.lock > now()) throw new E("ERR_PIN_LOCKED", 423);
      if (u.pin !== await sha256("pin:" + b.pin)) {
        u.fails++; const left = Math.max(PIN_FAILS - u.fails, 0);
        if (u.fails >= PIN_FAILS) { u.lock = now() + LOCK_MIN * 60; u.fails = 0; }
        save(); throw new E("ERR_LOGIN_FAILED", 401, { attempts_left: left });
      }
      u.fails = 0; u.lock = 0; save();
      return { user: pub(u), tokens: issue(u) };
    },
    "POST /v1/auth/refresh": async (b) => {
      const tk = db.tokens[b.refresh_token];
      if (!tk || tk.typ !== "refresh" || tk.exp < now()) throw new E("ERR_TOKEN_REVOKED", 401);
      delete db.tokens[b.refresh_token];
      const u = db.users[tk.uid]; if (!u) throw new E("ERR_TOKEN_REVOKED", 401);
      return issue(u);
    },
    "POST /v1/auth/logout": async (b) => { delete db.tokens[b.refresh_token]; save(); return null; },
    "POST /v1/auth/pin/reset": async (b) => {
      pinStrength(b.new_pin);
      const v = useVt(b.verification_token, "reset_pin");
      const u = findUser(v.ch, v.dest); if (!u) throw new E("ERR_NOT_FOUND", 404);
      u.pin = await sha256("pin:" + b.new_pin); u.fails = 0; u.lock = 0; save();
      return null;
    },
    "GET /v1/me": async (b, h) => pub(authUser(h)),
    "POST /v1/me/contact": async (b, h) => {
      const u = authUser(h), v = useVt(b.verification_token, "add_contact");
      if (findUser(v.ch, v.dest)) throw new E("ERR_ALREADY_REGISTERED", 409);
      if (v.ch === "sms") u.phone = v.dest; else u.email = v.dest;
      save(); return pub(u);
    },
  };

  const json = (status, data) => new Response(data === null ? null : JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : input.url;
    const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
    if (!path.startsWith("/v1/")) return realFetch(input, init);
    const method = ((init && init.method) || "GET").toUpperCase();
    const fn = routes[method + " " + path];
    await new Promise(r => setTimeout(r, 250));          // หน่วงให้เหมือนเรียก server จริง
    if (!fn) return json(404, { error: { code: "ERR_NOT_FOUND", message: "not found" } });
    try {
      const body = init && init.body ? JSON.parse(init.body) : {};
      const out = await fn(body, (init && init.headers) || {});
      return out === null ? new Response(null, { status: 204 }) : json(method === "POST" && path === "/v1/auth/register" ? 201 : 200, out);
    } catch (e) {
      if (!(e instanceof E)) { console.error(e); return json(500, { error: { code: "ERR_INTERNAL", message: "demo error" } }); }
      return json(e.status, { error: Object.assign({ code: e.code, message: e.code }, e.extra) });
    }
  };
  window.__1P_DEMO_RESET = () => { localStorage.removeItem(KEY); sessionStorage.clear(); location.reload(); };
})();
