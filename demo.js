"use strict";

/**
 * demo.js - run with node demo.js
 * Walks through every feature and every attack defence, with readable output.
 * Demonstrates the usage of all security features and attack defenses implemented.
 */

const {Keychain} = require("./password-manager");
const {decodeBuffer} = require("./lib");

// ------------- tiny print helpers so the output looks tidy ------------
const line = () => console.log("-".repeat(64));
const title = (t) => { console.log("\n" + "=".repeat(64)); console.log(" " + t); console.log("=".repeat(64)); };
const ok = (msg) => { console.log(" [PASS] " + msg); };
const info = (msg) => console.log("    " + msg);

// Runs fn and reports whether it threw (used to show attacks being caught)
async function expectThrow(fn){
    try {
        await fn();
        return null;
    } catch (e) {
        return String(e);
    }
}

(async () => {
    const MASTER = "correct horse battery sample";

    /* --------------------------------------------1*/
    title("1. Create a key chain and store passwords");
    const kc = await Keychain.init(MASTER);
    await kc.set("www.google.com", "password");
    await kc.set("www.example.com", "123456");
    await kc.set("www.amazon.com", "6U)qA1OBy%3SZX$o");
    await kc.set("www.ebay.com", "guest");
    ok("init() + 4 x set()");


    /*--------------------------------------------2*/
    title("2. Read, update and remove");
    info("get(google)   -> " + (await kc.get("www.google.com")));
    info("get(missing)  -> " + (await kc.get("www.nothere.com")));
    await kc.set("www.google.com", "google_pwd");
    info("after update  -> " + (await kc.get("www.google.com")));
    info("remove(ebay)  -> " + (await kc.remove("www.ebay.com")));
    info("remove(ebay) 2nd -> " + (await kc.remove("www.ebay.com")));
    ok("get, set(update) / remove behave as specified");


    /* ---------------------------------------------------------------- 3 */
  title("3. What does the saved file look like? (dump)");
  const [repr, checksum] = await kc.dump();
  line();
  console.log(JSON.stringify(JSON.parse(repr), null, 2).split("\n").slice(0, 14).join("\n") + "\n  ...");
  line();
  info("Checksum (kept in trusted storage): " + checksum);
  const leaks = ["google", "example", "amazon", "password", "123456", MASTER].filter((s) => repr.includes(s));
  leaks.length === 0
    ? ok("No domain names, passwords or master password appear in the dump")
    : console.log("  [FAIL] leaked: " + leaks);
 
  /* ---------------------------------------------------------------- 4 */
  title("4. Load it back (right and wrong password)");
  const kc2 = await Keychain.load(MASTER, repr, checksum);
  info("get(amazon) after load -> " + (await kc2.get("www.amazon.com")));
  ok("Correct password loads and data survives");
  const bad = await expectThrow(() => Keychain.load("wrong password", repr, checksum));
  bad ? ok("Wrong password rejected: \"" + bad + "\"") : console.log("  [FAIL] wrong password accepted");
 
  /* ---------------------------------------------------------------- 5 */
  title("5. Password LENGTH is hidden (padding)");
  const kcLen = await Keychain.init(MASTER);
  await kcLen.set("short.com", "a");
  await kcLen.set("long.com", "x".repeat(64));
  const sizes = Object.values(kcLen.data.kvs).map((r) => decodeBuffer(r.ct).length);
  info("Ciphertext sizes for a 1-char and a 64-char password: " + sizes.join(" and ") + " bytes");
  sizes[0] === sizes[1]
    ? ok("Identical sizes -> an attacker cannot tell short from long")
    : console.log("  [FAIL] sizes differ");
 
  /* ---------------------------------------------------------------- 6 */
  title("6. SWAP attack (checksum NOT provided)");
  const kcSwap = await Keychain.init(MASTER);
  await kcSwap.set("www.google.com", "google-secret");
  await kcSwap.set("www.evil.com", "evil-secret");
  const [swapRepr] = await kcSwap.dump();
  const stolen = JSON.parse(swapRepr);
  const [keyA, keyB] = Object.keys(stolen.kvs);
  [stolen.kvs[keyA], stolen.kvs[keyB]] = [stolen.kvs[keyB], stolen.kvs[keyA]]; // attacker swaps the two records
  const loadedSwap = await Keychain.load(MASTER, JSON.stringify(stolen)); // no checksum on purpose
  const swapResult = await expectThrow(() => loadedSwap.get("www.evil.com"));
  swapResult
    ? ok("Swap detected even without a checksum: \"" + swapResult + "\"")
    : console.log("  [FAIL] swap NOT detected");
 
  /* ---------------------------------------------------------------- 7 */
  title("7. ROLLBACK attack (checksum provided)");
  const kcRoll = await Keychain.init(MASTER);
  await kcRoll.set("www.google.com", "old_password");
  const [oldRepr] = await kcRoll.dump();                 // attacker saves this OLD copy
  await kcRoll.set("www.google.com", "new_password");
  const [, newChecksum] = await kcRoll.dump();           // user's trusted checksum is for the NEW data
  const rollResult = await expectThrow(() => Keychain.load(MASTER, oldRepr, newChecksum));
  rollResult
    ? ok("Rollback detected: \"" + rollResult + "\"")
    : console.log("  [FAIL] rollback NOT detected");
 
  /* ---------------------------------------------------------------- 8 */
  title("8. Tampering with a ciphertext (checksum NOT provided)");
  const t = JSON.parse(repr);
  const victim = Object.keys(t.kvs)[0];
  const ctBytes = Buffer.from(t.kvs[victim].ct, "base64");
  ctBytes[0] ^= 1;                                       // attacker flips one bit
  t.kvs[victim].ct = ctBytes.toString("base64");
  const kcTamper = await Keychain.load(MASTER, JSON.stringify(t));
  let caught = 0;
  for (const d of ["www.google.com", "www.example.com", "www.amazon.com"]) {
    if (await expectThrow(() => kcTamper.get(d))) caught++;
  }
  caught === 1
    ? ok("The single modified record was detected by AES-GCM")
    : console.log("  [FAIL] expected exactly 1 detection, got " + caught);
 
  console.log("\nDone.\n");
})();