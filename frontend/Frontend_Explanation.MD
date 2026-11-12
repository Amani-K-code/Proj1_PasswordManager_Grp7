# Secure Keychain Lab: User Guide

**Goes with:** `keychain-lab.html` (the demo page)
**Technical companion:** `Lab_Explanation.MD`

## 1. What is this page?

The page is a live demo of a **password manager** built around one idea: a **locker room**.

- You have one **master key** (your master password) that opens the whole locker room.
- Each website gets its own **locker**, with its own lock.
- The **locker numbers are hidden**, so nobody can tell which website is which.
- Every locker is the **same size**, so nobody can guess how long a password is.
- If someone **tampers** with a locker, the lock notices.
- You keep a **receipt** that proves your locker room hasn't been swapped for an older copy.

You don't need to know anything about security to use the page. Just follow the five steps.

## 2. How the page matches the explanation document

| Locker-room idea | What you see on the page | Step |
|---|---|---|
| Locker room | Your whole password manager | 1 |
| Master key | The master password you type | 1 |
| Slow locksmith | Setting up takes a moment on purpose, so guessing is slow | 1 |
| Random sticker | A random value added so two people with the same password still get different keys | 1 (automatic) |
| Hidden locker number | The "Locker number" column, a scrambled code instead of the website name | 2 |
| Locker lock | Each password stored locked, one lock per locker | 2 |
| Same-size lockers | The "Size" column is identical for short and long passwords | 2 and 5 |
| Test item | A hidden check that tells whether the master password is correct | 4 |
| Receipt | The "Your receipt" box after packing up | 3 and 4 |

## 3. How to use it

### Step 1: Set up your locker room
1. Type a master password (a sample is already filled in).
2. Click **Set up locker room**.
3. You should see "Locker room ready", and the **Strong master key** badge at the top turns green.

### Step 2: Use your lockers
1. Type a website and a password, then click **Store**. A new row appears in the table. The website name is **not** shown, only a scrambled locker number.
2. Click **Open locker** to see the password again.
3. Click **Empty locker** to delete it.
4. Store a short password and a long one and compare their sizes. They match.

### Step 3: Pack up and keep a receipt
1. Click **Pack up**.
2. The page shows how many lockers were packed and gives you a **receipt**.
3. A green message confirms that no website names, passwords or master password were packed. The **Hidden website names** badge turns green.
4. In real life, you'd keep the receipt somewhere an attacker can't reach, like a USB stick.

### Step 4: Reopen the locker room
1. Type the master password and click **Open saved locker room**. It should open.
2. Type a wrong password. It should refuse, with an amber message.
3. Try it with the "Check against my receipt" box ticked and unticked.

### Step 5: Attack lab
Each button pretends to be a burglar. **Green "Stopped" means the defense worked.**

| Button | What the burglar tries | Why it fails |
|---|---|---|
| **Swap two lockers** | Switches the contents of two lockers (e.g. Google's and a fake site's), even with no receipt | Each locker only opens in its own spot, so the alarm goes off |
| **Old copy** | Puts back an older version of your locker room | The receipt no longer matches |
| **Damage a locker** | Secretly changes one locker | The lock notices, and only that locker is flagged |
| **Guess the password** | Tries a wrong password on an empty locker room | The hidden test item refuses to open |
| **Check password lengths** | Compares a 1 and a 64 character password | Both take up the same size |

The badges at the top turn green as each protection is shown to work. When all six are green, you've seen every protection in action.

## 4. Running the page

1. Put `keychain-lab.html` in your project folder, next to `Lab_Explanation.MD` and this guide.
2. Double-click it to open in Chrome or Edge.
3. If you see "This browser blocked the security tools", run `npx serve` in the folder and open the `http://localhost` address it prints.

## 5. Notes for lecturers and teammates

The page runs a browser copy of the same logic as `password-manager.js` in the project. Technical terms in the explanation document, mapped to the code:

| Plain term | Technical term | In the code |
|---|---|---|
| Slow locksmith | PBKDF2 (Password-Based Key Derivation Function 2) | `deriveKeys()` |
| Hidden locker number | HMAC (Hash-based Message Authentication **Code**) | `tag()`, the keys of `kvs` |
| Locker lock | AES-GCM (Advanced Encryption Standard in **Galois/Counter Mode**) | `set()`, `get()` |
| Random sticker | Salt (16 random bytes) | `init()` |
| Same-size lockers | Padding (65 bytes) | `padValue()`, `unpadValue()` |
| Test item | Canary | `makeCanary()`, checked in `load()` |
| Receipt | SHA-256 checksum | `dump()`, checked in `load()` |

Two small corrections to the explanation document: **GCM stands for Galois/Counter Mode** (not "Galileo Mode"), and **HMAC's last letter stands for "Code"** (not "Call").

> **Important:** this is an educational demo and not a replacement for a real password manager.