/* =====================================================================
   1st Pay — DEMO mock API (ใช้กับ GitHub Pages / เปิดไฟล์ตรง ๆ)
   ---------------------------------------------------------------------
   จำลอง endpoint /v1/* ของ backend จริงทั้งหมดภายใน browser
   - ข้อมูลผู้ใช้เก็บใน localStorage ของผู้ทดลองแต่ละคนเท่านั้น (ไม่ส่งออกไปไหน)
   - ไม่มีการส่ง SMS / Email จริง — OTP แสดงบนหน้าจอ (Sandbox)
   - กติกาเหมือนระบบจริง: รูปแบบเบอร์ลาว, OTP 6 หลัก หมดอายุ 5 นาที ผิดได้ 5 ครั้ง,
     ขอใหม่ทุก 60 วินาที, PIN ห้ามเลขซ้ำ/เรียง, PIN ผิด 5 ครั้งล็อก 15 นาที
   - QR ชำระเงิน (EMVCo + CRC16) · วงเงิน Level 0 500,000 กีบ/วัน · QR หมดอายุ 15 นาที · Idempotency-Key
     ต่างจากระบบจริง: ร้านค้ารับเงินได้โดยไม่ต้องรอ KYB (เดโมไม่มีเจ้าหน้าที่) · ไม่มี Staff Console
   ===================================================================== */
(function () {
  "use strict";
  const KEY = "1p_demo_db_v1";
  const OTP_TTL = 300, COOLDOWN = 60, MAX_ATTEMPTS = 5, PIN_FAILS = 5, LOCK_MIN = 15;
  const ACCESS_TTL = 15 * 60, REFRESH_TTL = 7 * 86400;

  const now = () => Math.floor(Date.now() / 1000);
  const rid = (n = 16) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, "0")).join("");
  const load = () => { try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch (e) { return {}; } };
  const db = Object.assign({ users: {}, otps: {}, vts: {}, tokens: {}, cool: {}, txs: {}, seq: 0 }, load());
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


  /* ---------------- Part 4: QR / ชำระเงิน (จำลองกติกาเดียวกับ backend) ---------------- */
  const GUID = "LA.1STPAY.SANDBOX", QR_TTL = 15 * 60, L0_DAILY = 500000, L0_PER_TX = 500000, VELOCITY = 10;
  function crc16(str) {
    let crc = 0xFFFF;
    for (const b of new TextEncoder().encode(str)) { crc ^= b << 8; for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF; }
    return crc.toString(16).toUpperCase().padStart(4, "0");
  }
  const tlv = (t, v) => t + String(v.length).padStart(2, "0") + v;
  const asciiName = (n, fb) => ((n || "").normalize("NFKD").replace(/[^A-Za-z0-9 .&'-]/g, "").trim() || fb).slice(0, 25);
  function buildQr(code, name, amount, ref) {
    let s = tlv("00", "01") + tlv("01", amount ? "12" : "11") + tlv("38", tlv("00", GUID) + tlv("01", code)) + tlv("52", "5999") + tlv("53", "418");
    if (amount) s += tlv("54", String(amount));
    s += tlv("58", "LA") + tlv("59", asciiName(name, code)) + tlv("60", "VIENTIANE");
    if (ref) s += tlv("62", tlv("05", ref));
    s += "6304"; return s + crc16(s);
  }
  function parseTlv(s) { const o = {}; let i = 0; while (i < s.length) { const t = s.slice(i, i + 2), n = +s.slice(i + 2, i + 4); o[t] = s.slice(i + 4, i + 4 + n); i += 4 + n; } return o; }
  function parseQr(p) {
    p = String(p || "").trim();
    if (p.slice(-8, -4) !== "6304" || crc16(p.slice(0, -4)) !== p.slice(-4).toUpperCase()) throw new E("ERR_QR_INVALID");
    const top = parseTlv(p.slice(0, -8)), mai = parseTlv(top["38"] || ""), add = parseTlv(top["62"] || "");
    if (mai["00"] !== GUID || top["53"] !== "418") throw new E("ERR_QR_UNSUPPORTED");
    return { dynamic: top["01"] === "12", code: mai["01"], ref: add["05"] || null };
  }
  const dayStart = () => { const d = new Date(Date.now() + 7 * 3600e3); d.setUTCHours(0, 0, 0, 0); return d.getTime() - 7 * 3600e3; };
  const iso = ms => ms ? new Date(ms).toISOString() : null;
  const merchantByCode = c => Object.values(db.users).find(u => u.code === c);
  const shopName = m => (m.kyc && m.kyc.business_name) || m.full_name || m.code;
  const card = m => ({ name: shopName(m), code: m.code });
  const maskPh = p => p ? p.slice(0, 6) + "*".repeat(Math.max(p.length - 9, 0)) + p.slice(-3) : "—";
  function newRef() { const d = new Date(Date.now() + 7 * 3600e3).toISOString(); let r; do { r = "1PAY" + d.slice(2, 4) + d.slice(5, 7) + d.slice(8, 10) + String(Math.floor(Math.random() * 1e6)).padStart(6, "0"); } while (db.txs[r]); return r; }
  function expire(tx) { if (tx.status === "created" && tx.exp < Date.now()) tx.status = "expired"; }
  function txOut(tx, viewer) {
    const m = db.users[tx.mid], payer = tx.pid && db.users[tx.pid], mine = viewer && tx.pid === viewer.id;
    return { ref: tx.ref, kind: tx.kind, status: tx.status, amount: tx.amount, fee: 0, currency: "LAK", category: tx.cat || null,
      created_at: iso(tx.at), paid_at: iso(tx.paid), expires_at: iso(tx.exp), error_code: tx.err || null, provider: "mock",
      direction: mine ? "out" : "in", merchant: m ? card(m) : { name: "—", code: "" },
      payer: { name: payer ? (mine ? "+856 " + (payer.phone || "").slice(4) || payer.email : maskPh(payer.phone)) : (tx.plabel || "—") } };
  }
  function checkMerchant(m) {
    if (!m || m.account_type !== "merchant") throw new E("ERR_MERCHANT_NOT_FOUND", 404);
    // เดโม: ไม่มีเจ้าหน้าที่อนุมัติ KYB จึงให้ร้านค้ารับเงินได้เลย (ระบบจริงต้องผ่าน KYB ก่อน)
  }
  const usedToday = u => Object.values(db.txs).filter(x => x.pid === u.id && ["pending", "success", "unknown"].includes(x.status) && x.at >= dayStart()).reduce((a, x) => a + x.amount, 0);
  const merchantOnly = h => { const u = authUser(h); if (u.account_type !== "merchant") throw new E("ERR_MERCHANT_ONLY", 403); return u; };
  const ownTx = (u, ref) => { const tx = db.txs[String(ref || "").toUpperCase()]; if (!tx || (tx.mid !== u.id && tx.pid !== u.id)) throw new E("ERR_TX_NOT_FOUND", 404); expire(tx); return tx; };
  const charge = tx => { if (tx.amount % 1000 === 999) { tx.status = "failed"; tx.err = "ERR_BANK_DECLINED"; } else { tx.status = "success"; tx.paid = Date.now(); } };
  const LISTED = ["pending", "success", "failed", "unknown"], FILT = { ok: ["success"], pending: ["pending", "unknown"], fail: ["failed"] };
  const patterns = [
    [/^GET \/v1\/merchant\/qr\/([^/]+)$/, (b, h, ref) => { const u = merchantOnly(h); const tx = ownTx(u, ref); save(); return txOut(tx, u); }],
    [/^POST \/v1\/merchant\/qr\/([^/]+)\/cancel$/, (b, h, ref) => { const u = merchantOnly(h); const tx = ownTx(u, ref); if (tx.status === "created") tx.status = "cancelled"; save(); return txOut(tx, u); }],
    [/^POST \/v1\/merchant\/qr\/([^/]+)\/simulate$/, (b, h, ref) => { const u = merchantOnly(h); const tx = ownTx(u, ref);
      if (tx.status !== "created") throw new E("ERR_QR_USED", 409); tx.plabel = "SANDBOX"; charge(tx); save(); return txOut(tx, u); }],
    [/^GET \/v1\/transactions\/([^/]+)$/, (b, h, ref) => { const u = authUser(h); return txOut(ownTx(u, ref), u); }],
  ];
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
      if (u.account_type === "merchant") { db.seq = (db.seq || 0) + 1; u.code = "MER-" + String(db.seq).padStart(5, "0"); }
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

    "GET /v1/merchant/summary": async (b, h) => { const u = merchantOnly(h);
      const ok = Object.values(db.txs).filter(x => x.mid === u.id && x.status === "success" && x.at >= dayStart()), vol = ok.reduce((a, x) => a + x.amount, 0);
      return { today_volume: vol, today_count: ok.length, avg_ticket: ok.length ? Math.floor(vol / ok.length) : 0, pending_payout: vol, merchant: card(u), can_receive: true }; },
    "GET /v1/merchant/static-qr": async (b, h) => { const u = merchantOnly(h); return { merchant: card(u), qr: buildQr(u.code, shopName(u)) }; },
    "POST /v1/merchant/qr": async (b, h) => { const u = merchantOnly(h); const amt = Math.floor(+b.amount || 0);
      if (amt < 1) throw new E("ERR_AMOUNT_INVALID"); if (amt > 5000000) throw new E("ERR_MERCHANT_LIMIT", 422);
      const ref = newRef(); db.txs[ref] = { ref, kind: "qr_dynamic", mid: u.id, pid: null, amount: amt, status: "created", at: Date.now(), exp: Date.now() + QR_TTL * 1000 };
      save(); return Object.assign(txOut(db.txs[ref], u), { qr: buildQr(u.code, shopName(u), amt, ref) }); },
    "POST /v1/pay/resolve": async (b, h) => { const u = authUser(h); let ref = null, code = null;
      if (b.payload) { const p = parseQr(b.payload); ref = p.dynamic ? p.ref : null; code = p.code; }
      else { const c = String(b.code || "").toUpperCase().replace(/\s/g, ""); if (c.startsWith("1PAY")) ref = c; else if (c.startsWith("MER")) code = "MER-" + c.replace("MER-", "").replace("MER", "").padStart(5, "0"); else throw new E("ERR_QR_INVALID"); }
      if (ref) { const tx = db.txs[ref]; if (!tx) throw new E("ERR_TX_NOT_FOUND", 404); expire(tx); save();
        if (tx.status !== "created") throw new E(["expired", "cancelled"].includes(tx.status) ? "ERR_QR_EXPIRED" : "ERR_QR_USED", 409);
        if (tx.mid === u.id) throw new E("ERR_SELF_PAY", 409);
        return { mode: "dynamic", ref, amount: tx.amount, expires_at: iso(tx.exp), merchant: card(db.users[tx.mid]) }; }
      const m = merchantByCode(code); checkMerchant(m); if (m.id === u.id) throw new E("ERR_SELF_PAY", 409);
      return { mode: "static", merchant: card(m) }; },
    "POST /v1/pay": async (b, h) => { const u = authUser(h), key = (h["Idempotency-Key"] || h["idempotency-key"] || "");
      if (key.length < 8) throw new E("ERR_IDEMPOTENCY_KEY");
      const dup = Object.values(db.txs).find(x => x.idem === u.id + ":" + key); if (dup) return Object.assign(txOut(dup, u), { duplicate: true });
      if (u.lock > now()) throw new E("ERR_PIN_LOCKED", 423);
      if (u.pin !== await sha256("pin:" + b.pin)) { u.fails++; const left = Math.max(PIN_FAILS - u.fails, 0); if (u.fails >= PIN_FAILS) { u.lock = now() + LOCK_MIN * 60; u.fails = 0; } save(); throw new E("ERR_PIN_INVALID", 401, { attempts_left: left }); }
      u.fails = 0;
      let tx;
      if (b.ref) { tx = db.txs[b.ref]; if (!tx) throw new E("ERR_TX_NOT_FOUND", 404); expire(tx); if (tx.status !== "created") { save(); throw new E(tx.status === "expired" ? "ERR_QR_EXPIRED" : "ERR_QR_USED", 409); } }
      const m = tx ? db.users[tx.mid] : merchantByCode(b.merchant_code); checkMerchant(m); if (m.id === u.id) throw new E("ERR_SELF_PAY", 409);
      const amt = tx ? tx.amount : Math.floor(+b.amount || 0); if (amt < 1) throw new E("ERR_AMOUNT_INVALID");
      const used = usedToday(u); if (amt > L0_PER_TX || used + amt > L0_DAILY) throw new E("ERR_KYC_REQUIRED", 422, { left_today: Math.max(L0_DAILY - used, 0) });
      if (Object.values(db.txs).filter(x => x.pid === u.id && x.status === "success" && x.at > Date.now() - 3600e3).length >= VELOCITY) throw new E("ERR_VELOCITY_EXCEEDED", 429);
      if (!tx) { const ref = newRef(); tx = db.txs[ref] = { ref, kind: "qr_static", mid: m.id, amount: amt, at: Date.now() }; }
      Object.assign(tx, { pid: u.id, idem: u.id + ":" + key, cat: b.category || null, status: "pending" }); charge(tx); save(); return txOut(tx, u); },
    "GET /v1/pay/limits": async (b, h) => { const u = authUser(h), used = usedToday(u); return { kyc_level: 0, daily_max: L0_DAILY, per_tx_max: L0_PER_TX, used_today: used, left_today: Math.max(L0_DAILY - used, 0) }; },
    "GET /v1/transactions": async (b, h, q) => { const u = authUser(h), st = q.get("status") || "all", lim = Math.min(+q.get("limit") || 50, 200);
      const col = u.account_type === "merchant" ? "mid" : "pid", allow = FILT[st] || LISTED;
      Object.values(db.txs).forEach(expire);
      return { items: Object.values(db.txs).filter(x => x[col] === u.id && allow.includes(x.status)).sort((a, b) => b.at - a.at).slice(0, lim).map(x => txOut(x, u)) }; },
    "GET /v1/me": async (b, h) => pub(authUser(h)),
    "GET /v1/kyc": async (b, h) => { const u = authUser(h); return { kyc_level: 0, case: u.kyc || null }; },
    "POST /v1/kyc": async (b, h) => {        // เดโม: เก็บสถานะ "รอตรวจ" (ไม่มีเจ้าหน้าที่ตรวจในเดโม)
      const u = authUser(h);
      if (u.kyc && u.kyc.status === "pending") throw new E("ERR_KYC_PENDING", 409);
      if (!b.full_name || !b.doc1 || !b.doc2) throw new E("ERR_KYC_FIELD");
      u.kyc = { id: 1, kind: u.account_type === "merchant" ? "kyb" : "kyc", status: "pending", submitted_at: new Date().toISOString(), note: null, business_name: b.business_name || null };
      save(); return { case: u.kyc };
    },
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
    const rel = url.replace(/^https?:\/\/[^/]+/, ""), path = rel.split("?")[0], query = new URLSearchParams(rel.split("?")[1] || "");
    if (!path.startsWith("/v1/")) return realFetch(input, init);
    const method = ((init && init.method) || "GET").toUpperCase();
    let fn = routes[method + " " + path], arg = query;
    if (!fn) for (const [re, f] of patterns) { const mm = (method + " " + path).match(re); if (mm) { fn = f; arg = decodeURIComponent(mm[1]); break; } }
    await new Promise(r => setTimeout(r, 250));          // หน่วงให้เหมือนเรียก server จริง
    Object.assign(db, load());                          // อ่านใหม่ทุกครั้ง: เปิดร้านค้า/ลูกค้าคนละแท็บได้
    if (!fn) return json(404, { error: { code: "ERR_NOT_FOUND", message: "not found" } });
    try {
      let body = {};
      if (init && init.body instanceof FormData) { for (const [k, v] of init.body.entries()) body[k] = typeof v === "string" ? v : true; }
      else if (init && init.body) body = JSON.parse(init.body);
      const out = await fn(body, (init && init.headers) || {}, arg);
      return out === null ? new Response(null, { status: 204 }) : json(method === "POST" && (path === "/v1/auth/register" || path === "/v1/kyc" || path === "/v1/merchant/qr") ? 201 : 200, out);
    } catch (e) {
      if (!(e instanceof E)) { console.error(e); return json(500, { error: { code: "ERR_INTERNAL", message: "demo error" } }); }
      return json(e.status, { error: Object.assign({ code: e.code, message: e.code }, e.extra) });
    }
  };
  window.__1P_DEMO_RESET = () => { localStorage.removeItem(KEY); sessionStorage.clear(); location.reload(); };
})();
