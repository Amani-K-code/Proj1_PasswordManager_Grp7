# Person 3 Explained Like You're 5: `dump()` and `load()`

**Part:** Persistence, Integrity & Defense
**Files touched:** `password-manager.js` (functions `dump()` and `load()`)

---

## 1. The story

Imagine our password manager is a **toy box with a lock**.

- Inside the box are lots of **little envelopes**. Each envelope holds one secret (a password for a website).
- Each envelope is **sealed** so nobody can read it without the key.
- The box has a **label on every envelope**. The label doesn't say the website name. It's a scrambled code that only we can match to a website.

Our job (Person 3) is to **pack the box up** so it can be stored on a shelf (`dump`), and later to **unpack it safely** (`load`).

But there are bad people who might sneak to the shelf and mess with the box. So we also need to **catch cheaters**.

---

## 2. What do `dump` and `load` do?

| Function | Kid-friendly meaning | Real meaning |
|---|---|---|
| `dump()` | "Pack the toy box into a flat package and take a photo of it." | Turn the keychain into a JSON string and compute a SHA-256 checksum. |
| `load()` | "Open the package, check nothing was changed, check the person has the right key, and rebuild the toy box." | Verify the checksum, re-derive keys, check the password, rebuild the Keychain. |

---

## 3. What goes into the package (and what NEVER does)

**Goes in the package (it's safe, an attacker may see it):**

| Item | What it is | Kid-friendly meaning |
|---|---|---|
| `salt` | Random bytes | "A random sprinkle we mixed into the key, so two people with the same password get different keys." |
| `check` (the canary) | A secret message that's locked | "A tiny note locked in a mini-box. If you can open it, you have the right key." |
| `kvs` | The envelopes | "All the sealed envelopes with the scrambled labels." |

**NEVER goes in the package:**

- The master password
- The keys (`hmacKey`, `aesKey`)
- Any hash of the password

That's why in `dump()` we build the object **by hand** with just those three things. If we wrote out the whole keychain, we'd accidentally write the keys too, which would be like taping the key to the box.

---

## 4. The Checksum: "the photo of the box"

When we pack the box, we take a **photo** of it. The photo is a **SHA-256 hash**.

- If even **one tiny thing** in the box changes, the photo looks **completely different**.
- We keep the photo in a **safe place** the bad guy can't reach (a "trusted storage", like a USB stick in your pocket).
- When we unpack, we take a **new photo** and compare it to the saved one. If they don't match, someone cheated, so we shout (`throw`).

### Why is this useful? The Rollback Attack

A **rollback attack** is when a bad guy swaps your box with an **older version** of the box.

> Example: Yesterday your Google password was `oldpass`. Today you changed it to `newpass`. The bad guy puts yesterday's box back on the shelf. Everything inside is still properly sealed, so locks alone can't tell it's old!

The photo catches this: the old box gives an old photo, which doesn't match today's saved photo.

**Important:** the photo only works if it's stored somewhere the bad guy can't touch. If he could change the photo too, he'd just swap both.

---

## 5. The Canary: "how do we know the password is right?"

The problem: if the box has **no envelopes yet**, how do we tell a right password from a wrong one? And we're **not allowed** to save the password (or a hash of it).

The trick is a **canary** (like the canary in a coal mine, a little early-warning sign):

1. When we create the keychain, we lock a **known, boring sentence** (`"keychain-password-check"`) with the key.
2. We store that locked sentence in the package.
3. When loading, we try to unlock it with the key made from the password the person typed.
   - **Right password:** it opens, and we see the boring sentence. Good.
   - **Wrong password:** the lock refuses to open. We shout (`throw`).

Why this is safe: the locked sentence uses a **fresh random IV** each time, so it reveals nothing about the password.

---

## 6. The Swap Attack: "switching the labels"

A **swap attack** is when the bad guy **switches two envelopes**.

> He swaps the envelope for `google.com` with the one for `evil.com`. Now when you visit `evil.com`, the app hands over your Google password!

The defense (built in `set` and `get` by Person 2, tested by us) is to **write the envelope's own label inside the seal** (this is the AES-GCM `additionalData`).

- When opening an envelope, the lock checks: "does the label you're sitting under match the label I was sealed with?"
- If the envelope was moved to a different label, the lock **refuses to open**, and we `throw "Tampering detected"`.

This works **even with no checksum**, because it's built into each envelope. That's exactly what the assignment demands: the two defenses must work **independently**.

---

## 7. Step-by-step: what `load()` does, in order

1. **Is there a trusted photo?** If yes, take a new photo of the package and compare. Different? **Stop and throw** (rollback or tampering).
2. **Open the package** (`JSON.parse`) to get the salt, the canary and the envelopes.
3. **Rebuild the keys** from the typed password plus the stored salt (`deriveKeys`). The slow PBKDF2 happens **once**.
4. **Try to open the canary.** Can't? **Throw** (wrong password).
5. **Rebuild the Keychain** with the envelopes (`kvs`) and the rebuilt keys, then return it.

---

## 8. Tiny cheat-sheet: attack → defense

| Attack | What the attacker does | Who stops it | How |
|---|---|---|---|
| Reading the box | Looks at the dump | AES-GCM + HMAC labels | Everything is scrambled |
| Wrong password | Guesses the password | `load()` canary | Canary won't unlock |
| Edit an envelope | Changes some bytes | AES-GCM | Authentication fails |
| **Swap** | Switches two envelopes | `additionalData` = label (`set`/`get`) | Seal doesn't match the label |
| **Rollback** | Puts an old box back | SHA-256 checksum (`dump`/`load`) | Photo doesn't match |

---

## 9. What this lab teaches (the big picture)

- **Encryption hides** data, but **doesn't prove it's the latest or in the right place**.
- You need **integrity** (checksums, authenticated encryption) as well as **confidentiality**.
- Good security starts with a **threat model**: decide exactly what the attacker can do, then defend against each thing.
- **Never store secrets** (passwords or keys) next to the data they protect.
- **Use trusted libraries** (SubtleCrypto) and don't invent your own crypto.

---

## 10. Things you should be able to say out loud

- "`dump` builds the public state by hand so the keys are never serialized."
- "The checksum is a SHA-256 of the exact JSON string, kept in trusted storage, so a rolled-back database doesn't match."
- "The canary lets us verify the password without storing anything about it, and it also works for an empty database."
- "Swap protection lives in `set`/`get` via the domain's HMAC as GCM additional data, so it works without the checksum."
- "`load` calls PBKDF2 only once."

---

## 11. Quick test commands

```bash
npm test
```

All 11 tests should pass.

Extra checks worth trying (optional, by hand):

1. Dump a keychain, change one character of the JSON, and load it with the checksum. It should **throw**.
2. Dump, swap two values in `kvs`, load **without** a checksum, then `get`. It should **throw**.
3. Load with the wrong password, with and without a checksum. It should **throw**.