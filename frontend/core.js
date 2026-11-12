"use strict";
// Browser port of password-manager.js (same design as the lab): PBKDF2 -> HMAC sub-keys,
// HMAC-hidden domain names, AES-GCM with the label as additionalData (swap defense),
// 65-byte padding (length hiding), canary (password check), SHA-256 receipt (rollback defense).
const enc = new TextEncoder(), dec = new TextDecoder(), subtle = crypto.subtle;
const stringToBuffer = s => enc.encode(s), bufferToString = b => dec.decode(b);
const encodeBuffer = b => { let s = ""; new Uint8Array(b).forEach(x => s += String.fromCharCode(x)); return btoa(s); };
const decodeBuffer = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const getRandomBytes = n => crypto.getRandomValues(new Uint8Array(n));
const ITER = 100000, MAXLEN = 64, PADDED = 65, CANARY = "keychain-password-check";

async function deriveKeys(pw, salt) {
  const raw = await subtle.importKey("raw", stringToBuffer(pw), "PBKDF2", false, ["deriveKey"]);
  const m = await subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, raw, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
  const hb = await subtle.sign("HMAC", m, stringToBuffer("domain-hmac-key"));
  const ab = await subtle.sign("HMAC", m, stringToBuffer("aes-gcm-key"));
  return {
    hmacKey: await subtle.importKey("raw", hb, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    aesKey: await subtle.importKey("raw", ab, "AES-GCM", false, ["encrypt", "decrypt"])
  };
}
async function makeCanary(k) {
  const iv = getRandomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: stringToBuffer("canary") }, k, stringToBuffer(CANARY));
  return { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
}
function padValue(v) {
  const b = stringToBuffer(v);
  if (b.length > MAXLEN) throw "Password too long (max " + MAXLEN + " bytes)";
  const p = new Uint8Array(PADDED); p[0] = b.length; p.set(b, 1); return p;
}
const unpadValue = buf => { const p = new Uint8Array(buf); return bufferToString(p.slice(1, 1 + p[0])); };

class Keychain {
  constructor(data, secrets) { this.data = data; this.secrets = secrets; }
  static async init(pw) {
    const salt = getRandomBytes(16), keys = await deriveKeys(pw, salt);
    return new Keychain({ salt: encodeBuffer(salt), check: await makeCanary(keys.aesKey), kvs: {} }, keys);
  }
  static async load(pw, repr, check) {
    if (check !== undefined && check !== null) {
      if (encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr))) !== check)
        throw "Integrity check failed: the saved data was tampered with or replaced by an old copy.";
    }
    const p = JSON.parse(repr), keys = await deriveKeys(pw, decodeBuffer(p.salt));
    let plain;
    try {
      plain = await subtle.decrypt({ name: "AES-GCM", iv: decodeBuffer(p.check.iv), additionalData: stringToBuffer("canary") }, keys.aesKey, decodeBuffer(p.check.ct));
    } catch (e) { throw "Wrong master password."; }
    if (bufferToString(plain) !== CANARY) throw "Wrong master password.";
    return new Keychain({ salt: p.salt, check: p.check, kvs: p.kvs }, keys);
  }
  async dump() {
    const repr = JSON.stringify({ salt: this.data.salt, check: this.data.check, kvs: this.data.kvs });
    return [repr, encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)))];
  }
  async tag(n) { return encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(n))); }
  async get(n) {
    const t = await this.tag(n), r = this.data.kvs[t];
    if (r === undefined) return null;
    try {
      return unpadValue(await subtle.decrypt({ name: "AES-GCM", iv: decodeBuffer(r.iv), additionalData: stringToBuffer(t) }, this.secrets.aesKey, decodeBuffer(r.ct)));
    } catch (e) { throw "Tampering detected"; }
  }
  async set(n, v) {
    const t = await this.tag(n), p = padValue(v), iv = getRandomBytes(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: stringToBuffer(t) }, this.secrets.aesKey, p);
    this.data.kvs[t] = { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
  }
  async remove(n) {
    const t = await this.tag(n);
    if (this.data.kvs[t] === undefined) return false;
    delete this.data.kvs[t]; return true;
  }
}