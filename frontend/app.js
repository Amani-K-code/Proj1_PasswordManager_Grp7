"use strict";
const $ = s => document.querySelector(s), LS = localStorage;   // localStorage plays the role of "disk"
const esc = s => String(s).replace(/[&<>"']/g, c => "&#" + c.charCodeAt(0) + ";");
let kc = null, idx = [], user = "", logs = [];                  // kc and idx exist only in memory while signed in
const note = m => logs.unshift({ t: new Date().toLocaleTimeString(), m });
const set = h => { $("#main").innerHTML = h; };

/* ---- storage: the Keychain holds only <=64 byte values, so the account list is stored in chunks ---- */
async function persist() { const [r, s] = await kc.dump(); LS.kc_repr = r; LS.kc_receipt = s; }
async function saveIndex() {
  const b = encodeBuffer(stringToBuffer(JSON.stringify(idx))), parts = b.match(/.{1,60}/g) || [];
  const old = parseInt((await kc.get("__n")) || "0");
  for (let i = 0; i < parts.length; i++) await kc.set("__i" + i, parts[i]);
  for (let i = parts.length; i < old; i++) await kc.remove("__i" + i);
  await kc.set("__n", String(parts.length));
  await persist();
}
async function loadIndex() {
  const n = parseInt((await kc.get("__n")) || "0"); let b = "";
  for (let i = 0; i < n; i++) b += await kc.get("__i" + i);
  idx = n ? JSON.parse(bufferToString(decodeBuffer(b))) : [];
}
const allPw = async () => { const o = []; for (const e of idx) o.push({ ...e, pw: await kc.get("acct:" + e.id) }); return o; };

/* ---- helpers ---- */
function strength(p) {
  const s = +(p.length >= 8) + (p.length >= 12) + (p.length >= 16) + (/[a-z]/.test(p) && /[A-Z]/.test(p)) + /\d/.test(p) + /[^A-Za-z0-9]/.test(p);
  return s <= 1 ? ["Very weak", "bad"] : s == 2 ? ["Weak", "bad"] : s == 3 ? ["Fair", "mid"] : s <= 5 ? ["Strong", "good"] : ["Very strong", "good"];
}
const badge = p => { const [l, c] = strength(p); return `<span class="b ${c}">${l}</span>`; };
function stats(a) {
  const weak = a.filter(e => strength(e.pw)[1] == "bad"), m = {};
  a.forEach(e => (m[e.pw] = m[e.pw] || []).push(e));
  const groups = Object.values(m).filter(g => g.length > 1), old = a.filter(e => Date.now() - e.added > 180 * 864e5);
  return { weak, groups, old, score: Math.max(0, 100 - weak.length * 15 - groups.length * 10 - old.length * 5) };
}
function ask(fn, title = "Enter your master password") {          // modal that only succeeds with the right master password
  return new Promise(res => {
    const d = $("#dlg"); $("#dtitle").textContent = title; $("#dpw").value = ""; $("#derr").textContent = ""; d.showModal(); $("#dpw").focus();
    const done = v => { d.close(); res(v); };
    $("#dok").onclick = async () => { try { done(await fn($("#dpw").value)); } catch (x) { $("#derr").textContent = String(x); } };
    $("#dno").onclick = () => done(null); d.oncancel = () => res(null);
    $("#dpw").onkeydown = e => { if (e.key == "Enter") $("#dok").click(); };
  });
}
const auth = t => ask(pw => Keychain.load(pw, LS.kc_repr, LS.kc_receipt), t);

/* ---- sign in / create ---- */
function showAuth() {
  const has = !!LS.kc_repr;
  $("#app").hidden = true; $("#auth").hidden = false;
  $("#atitle").textContent = has ? "Welcome back" : "Create your vault";
  $("#asub").textContent = has ? "Sign in with your master password." : "Choose a username and a strong master password. It cannot be recovered if you forget it.";
  $("#auser").value = LS.kc_user || ""; $("#auser").readOnly = has;
  $("#aconf").parentElement.hidden = has; $("#abtn").textContent = has ? "Sign in" : "Create vault";
  $("#reset").hidden = !has; $("#aerr").textContent = ""; $("#apw").value = ""; $("#aconf").value = "";
}
$("#authform").onsubmit = async e => {
  e.preventDefault(); const pw = $("#apw").value, err = $("#aerr"); err.textContent = "";
  try {
    if (!LS.kc_repr) {
      if (!$("#auser").value.trim()) throw "Enter a username.";
      if (pw.length < 8) throw "Master password must be at least 8 characters.";
      if (pw !== $("#aconf").value) throw "Passwords do not match.";
      kc = await Keychain.init(pw); user = $("#auser").value.trim(); LS.kc_user = user; idx = []; await saveIndex(); note("Vault created");
    } else { kc = await Keychain.load(pw, LS.kc_repr, LS.kc_receipt); user = LS.kc_user; await loadIndex(); note("Signed in"); }
    $("#auth").hidden = true; $("#app").hidden = false; $("#who").textContent = user; location.hash = "#/dashboard"; route();
  } catch (x) { err.textContent = String(x); }
};
$("#reset").onclick = e => { e.preventDefault(); if (confirm("Delete the saved vault from this browser?")) { ["kc_repr", "kc_receipt", "kc_user"].forEach(k => LS.removeItem(k)); showAuth(); } };
$("#out").onclick = () => { kc = null; idx = []; logs = []; location.hash = ""; showAuth(); };   // keys leave memory

/* ---- router ---- */
const V = {};
async function route() {
  if (!kc) return;
  const [name, arg] = (location.hash.slice(2) || "dashboard").split("/"), n = V[name] ? name : "dashboard";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.hash == "#/" + n));
  await V[n](arg);
}
addEventListener("hashchange", route);

V.dashboard = async () => {
  const a = await allPw(), s = stats(a);
  set(`<div class="top"><h1>Dashboard</h1><a class="btn" href="#/add">+ Add password</a></div>
  <div class="cards"><div class="card"><small>Saved accounts</small><big>${a.length}</big></div>
  <div class="card bad"><small>Weak passwords</small><big>${s.weak.length}</big></div>
  <div class="card mid"><small>Reused passwords</small><big>${s.groups.flat().length}</big></div>
  <div class="card"><small>Vault health</small><big>${s.score}/100</big></div></div>
  <div class="panel"><h3>Recently added</h3><div class="minis">${a.slice(-5).reverse().map(e => `<div class="mini"><b>${esc(e.name)}</b><span>${esc(e.site)}</span></div>`).join("") || `<p class="mut">No passwords yet. Add your first one.</p>`}</div></div>`);
};

V.vault = async () => {
  const a = await allPw();
  set(`<div class="top"><h1>Saved accounts <span class="count">${a.length}</span></h1><a class="btn" href="#/add">+ Add password</a></div>
  <input id="q" class="in" placeholder="Search saved accounts">
  <div id="rows" class="grid"></div>`);
  const draw = () => {
    const q = $("#q").value.toLowerCase();
    $("#rows").innerHTML = a.filter(e => (e.name + e.site + e.user).toLowerCase().includes(q)).map(e =>
      `<div class="acct"><div class="ah"><div><b>${esc(e.name)}</b><small>${esc(e.site)}</small></div>${badge(e.pw)}</div><dl><dt>Username</dt><dd>${esc(e.user)}</dd><dt>Password</dt><dd id="p${e.id}">••••••••</dd><dt>Added</dt><dd>${new Date(e.added).toLocaleDateString()}</dd></dl>
      <div class="act"><button data-a="show" data-i="${e.id}">Show</button><button data-a="copy" data-i="${e.id}">Copy</button><button data-a="edit" data-i="${e.id}">Edit</button><button class="del" data-a="del" data-i="${e.id}">Delete</button></div></div>`).join("")
      || `<p class="mut">No accounts found.</p>`;
  };
  draw(); $("#q").oninput = draw;
  $("#rows").onclick = async ev => {
    const b = ev.target.closest("button"); if (!b) return;
    const id = b.dataset.i, act = b.dataset.a, e = a.find(x => x.id == id);
    if (act == "edit") { location.hash = "#/add/" + id; return; }
    if (!await auth(act == "del" ? "Enter your master password to delete " + e.name : "Enter your master password to unlock " + e.name)) return;
    if (act == "del") { await kc.remove("acct:" + id); idx = idx.filter(x => x.id != id); await saveIndex(); note("Deleted " + e.name); V.vault(); return; }
    const pw = await kc.get("acct:" + id);                               // decrypted only now, after the master password check
    if (act == "copy") { await navigator.clipboard.writeText(pw); note("Copied password for " + e.name); }
    else { $("#p" + id).textContent = pw; note("Revealed password for " + e.name); setTimeout(() => { const c = $("#p" + id); if (c) c.textContent = "••••••••"; }, 8000); }
  };
};

V.add = async id => {
  const e = idx.find(x => x.id == id);
  set(`<div class="top"><h1>${e ? "Edit" : "Add"} password</h1></div>
  <form id="f" class="panel">
  <label>Account name<input class="in" name="aname" required value="${esc(e?.name || "")}"></label>
  <label>Website<input class="in" name="site" placeholder="www.example.com" value="${esc(e?.site || "")}"></label>
  <label>Username or email<input class="in" name="user" value="${esc(e?.user || "")}"></label>
  <label>Password (max 64 characters)<input class="in" name="pw" id="fpw" maxlength="64" ${e ? 'placeholder="Leave blank to keep the current password"' : "required"}></label>
  <div id="meter" class="mut"></div>
  <div class="row"><button type="button" id="gen">Generate strong password</button><button class="btn">Save</button></div><p id="ferr" class="err"></p></form>`);
  $("#fpw").oninput = () => { const v = $("#fpw").value; $("#meter").innerHTML = v ? "Strength: " + badge(v) : ""; };
  $("#gen").onclick = () => {
    const c = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    $("#fpw").value = [...getRandomBytes(20)].map(x => c[x % c.length]).join(""); $("#fpw").dispatchEvent(new Event("input"));
  };
  $("#f").onsubmit = async ev => {
    ev.preventDefault(); const f = ev.target, nid = e ? e.id : encodeBuffer(getRandomBytes(5)).replace(/[^a-z0-9]/gi, "x");
    try {
      if (f.pw.value) await kc.set("acct:" + nid, f.pw.value);
      const rec = { id: nid, name: f.aname.value.trim(), site: f.site.value.trim(), user: f.user.value.trim(), added: e ? e.added : Date.now() };
      idx = e ? idx.map(x => x.id == nid ? rec : x) : [...idx, rec];
      await saveIndex(); note((e ? "Updated " : "Added ") + rec.name); location.hash = "#/vault";
    } catch (x) { $("#ferr").textContent = String(x); }
  };
};

V.audit = async () => {
  const a = await allPw(), s = stats(a), pill = n => `<span class="pill">${esc(n)}</span>`;
  set(`<h1>Security audit</h1>
  <div class="panel"><h3>Vault health</h3><div class="bar"><i style="width:${s.score}%"></i></div><b>${s.score}/100</b>
  <p class="mut">Based on ${a.length} saved passwords. Weak, reused and old passwords lower the score.</p></div>
  <div class="cols"><div class="panel"><h3>Weak passwords (${s.weak.length})</h3>${s.weak.map(e => `<div class="li">${esc(e.name)} <a class="btn" href="#/add/${e.id}">Fix</a></div>`).join("") || `<p class="mut">None.</p>`}</div>
  <div class="panel"><h3>Reused passwords (${s.groups.length} groups)</h3>${s.groups.map(g => `<div class="li">Same password on ${g.length} accounts<br>${g.map(e => pill(e.name)).join("")}</div>`).join("") || `<p class="mut">None.</p>`}</div>
  <div class="panel"><h3>Not changed in 180+ days (${s.old.length})</h3>${s.old.map(e => `<div class="li">${esc(e.name)}</div>`).join("") || `<p class="mut">Everything is recent.</p>`}</div></div>
  <div class="panel"><h3>Activity log</h3>${logs.map(l => `<div class="li">${l.t} <span>${esc(l.m)}</span></div>`).join("")}</div>`);
};

V.backup = async () => {
  set(`<h1>Backup</h1>
  <div class="panel"><h3>Export</h3><p class="mut">Downloads the encrypted vault plus its receipt (SHA-256 checksum). Keep the receipt somewhere safe.</p><button class="btn" id="ex">Download backup</button></div>
  <div class="panel"><h3>Restore</h3><p class="mut">Choose a backup file. The receipt is checked and the backup's master password is required.</p><input type="file" id="fl" accept=".json"><p id="rmsg" class="err"></p></div>`);
  $("#ex").onclick = () => {
    const l = document.createElement("a"); l.href = URL.createObjectURL(new Blob([JSON.stringify({ vault: LS.kc_repr, receipt: LS.kc_receipt })], { type: "application/json" }));
    l.download = "vault-backup.json"; l.click(); note("Backup downloaded");
  };
  $("#fl").onchange = async ev => {
    try {
      const b = JSON.parse(await ev.target.files[0].text());
      const k = await ask(pw => Keychain.load(pw, b.vault, b.receipt), "Enter the master password for this backup"); if (!k) return;
      kc = k; LS.kc_repr = b.vault; LS.kc_receipt = b.receipt; await loadIndex(); note("Backup restored");
      $("#rmsg").className = "ok"; $("#rmsg").textContent = "Restored " + idx.length + " accounts.";
    } catch (x) { $("#rmsg").textContent = String(x); }
  };
};

V.stored = async () => {
  const a = await allPw(), rows = Object.entries(kc.data.kvs);
  const leaks = a.flatMap(e => [e.pw, e.site, e.user]).filter(s => s && s.length >= 4 && LS.kc_repr.includes(s)).length;
  set(`<h1>How it's stored</h1>
  <div class="panel"><h3>What is saved</h3>
  <p class="mut">Only a random salt, an encrypted test value, and encrypted records. Domain names become HMAC labels, every password is padded to the same size and encrypted with AES-GCM. The master password and keys are never saved.</p>
  <p>Leak check: <b class="${leaks ? "err" : "ok"}">${leaks} readable passwords, websites or usernames found in the saved data</b></p>
  <table><thead><tr><th>HMAC label<th>IV<th>Encrypted data<th>Size</tr></thead><tbody>${rows.map(([k, v]) => `<tr><td class="mono">${k.slice(0, 18)}…<td class="mono">${v.iv}<td class="mono">${v.ct.slice(0, 28)}…<td>${decodeBuffer(v.ct).length} bytes</tr>`).join("")}</tbody></table>
  <p class="mut">Receipt (SHA-256 of the saved data): <span class="mono">${LS.kc_receipt}</span></p></div>
  <div class="panel"><h3>Try to attack it</h3><div class="row"><button id="a1">Swap two records</button><button id="a2">Roll back to an old copy</button><button id="a3">Flip a bit</button></div><div id="res"></div></div>`);
  const M = "demo-master-pw", out = m => { const d = document.createElement("div"); d.className = "li"; d.textContent = m; $("#res").prepend(d); };
  const tryit = async f => { try { await f(); return null; } catch (e) { return String(e); } };
  const mk = async () => { const k = await Keychain.init(M); await k.set("a.com", "secret-A"); await k.set("b.com", "secret-B"); return k; };
  $("#a1").onclick = async () => {
    const k = await mk(), o = JSON.parse((await k.dump())[0]), [x, y] = Object.keys(o.kvs); [o.kvs[x], o.kvs[y]] = [o.kvs[y], o.kvs[x]];
    const l = await Keychain.load(M, JSON.stringify(o)), r = await tryit(() => l.get("a.com"));
    out(r ? "Swap stopped, even without the receipt: " + r : "Swap NOT detected");
  };
  $("#a2").onclick = async () => {
    const k = await mk(), old = (await k.dump())[0]; await k.set("a.com", "new-secret");
    const newSum = (await k.dump())[1]; const r = await tryit(() => Keychain.load(M, old, newSum));
    out(r ? "Old copy stopped by the receipt: " + r : "Rollback NOT detected");
  };
  $("#a3").onclick = async () => {
    const k = await mk(), o = JSON.parse((await k.dump())[0]), key = Object.keys(o.kvs)[0], c = decodeBuffer(o.kvs[key].ct); c[0] ^= 1; o.kvs[key].ct = encodeBuffer(c);
    const l = await Keychain.load(M, JSON.stringify(o)); let n = 0;
    for (const d of ["a.com", "b.com"]) if (await tryit(() => l.get(d))) n++;
    out(n == 1 ? "Tampered record detected by AES-GCM" : "Tampering NOT detected");
  };
};

showAuth();