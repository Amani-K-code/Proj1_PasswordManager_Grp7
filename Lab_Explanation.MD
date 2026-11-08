# Secure Password Manager --- Project 1 Documentation

**Course:** ICS 3201 Computer Security and Cryptography\
**Project:** Secure Password Manager (Keychain)\
**Main implementation:** `password-manager.js`

## 1. Project overview

This project implements the core part of a password manager. A user
creates a keychain using one master password. The keychain can then
store, retrieve, update, and remove passwords for different websites.

The aim is not just to hide the passwords. The program must also make it
difficult for an attacker to discover website names, guess password
lengths, swap two stored records, or replace the whole database with an
older copy.

The assignment asks us to build the core library, not a complete
application with a graphical interface or actual disk storage. We
represent saving and loading through JSON strings using `dump()` and
`load()`.

> **Important:** This is an educational project. The assignment itself
> warns that this implementation is not a replacement for a production
> password manager.

## 2. Files used

### `password-manager.js` --- main implementation

This is the main file and contains the `Keychain` class and the security
logic.

  ---------------------------------------------------------------------------------------
  Function or part                                    What it does
  --------------------------------------------------- -----------------------------------
  `deriveKeys(password, salt)`                        Uses PBKDF2 once to derive a master
                                                      key, then uses HMAC with two
                                                      different labels to create separate
                                                      keys: one for hiding website names
                                                      and one for AES-GCM encryption.

  `makeCanary(aesKey)`                                Encrypts a known phrase. Later,
                                                      `load()` uses it to check whether
                                                      the supplied master password is
                                                      correct.

  `padValue(value)`                                   Adds a length byte and zero padding
                                                      so every stored password has the
                                                      same 65-byte plaintext size.

  `unpadValue(buffer)`                                Reads the original length and
                                                      returns the actual password after
                                                      decryption.

  `Keychain.constructor(data, secrets)`               Keeps the public stored data
                                                      separate from the secret keys.

  `Keychain.init(password)`                           Creates a new empty keychain,
                                                      generates a random salt, derives
                                                      the keys, and creates the encrypted
                                                      canary.

  `Keychain.set(name, value)`                         Hides the website name with HMAC,
                                                      pads the password, encrypts it with
                                                      AES-GCM, and stores the encrypted
                                                      record. It also updates an existing
                                                      entry.

  `Keychain.get(name)`                                Recomputes the website's HMAC tag,
                                                      finds its record, decrypts it, and
                                                      returns the password. Returns
                                                      `null` if the website is not
                                                      stored.

  `Keychain.remove(name)`                             Finds the website using its HMAC
                                                      tag and deletes the record. Returns
                                                      `true` if removed and `false` if it
                                                      was not found.

  `Keychain.dump()`                                   Creates a JSON representation
                                                      containing only public stored data
                                                      and returns it together with its
                                                      SHA-256 checksum.

  `Keychain.load(password, repr, trustedDataCheck)`   Optionally checks the checksum,
                                                      reads the JSON data, derives the
                                                      keys again, verifies the master
                                                      password using the canary, and
                                                      rebuilds the keychain.
  ---------------------------------------------------------------------------------------

The program uses Node.js `SubtleCrypto` for the cryptographic operations
rather than creating its own encryption algorithms.

### `lib.js` --- helper functions

This file contains small conversion and random-number helper functions
used by the main implementation.

  -----------------------------------------------------------------------
  Helper                              Simple explanation
  ----------------------------------- -----------------------------------
  `stringToBuffer(str)`               Converts normal text into bytes so
                                      it can be used by cryptographic
                                      functions.

  `bufferToString(buf)`               Converts decrypted bytes back into
                                      normal text.

  `encodeBuffer(buf)`                 Converts bytes into Base64 text.
                                      This makes binary data easier to
                                      store in JSON and use as an object
                                      key.

  `decodeBuffer(base64)`              Converts Base64 text back into
                                      bytes for cryptographic operations.

  `getRandomBytes(len)`               Generates the requested number of
                                      random bytes, for example a salt or
                                      AES-GCM IV.
  -----------------------------------------------------------------------

**Base64 is only an encoding format; it is not encryption.** It makes
binary data easier to represent and store.

### `demo.js` --- demonstration and manual security checks

This file is used to demonstrate how the password manager behaves. It is
separate from the main implementation and does not replace the required
`password-manager.js` submission.

The demonstration covers normal operations and security situations,
including wrong passwords, record swapping, rollback, and modified
ciphertext. The expected behaviour of these checks is described in
Section 5 below.

## 3. How the implementation protects the data

### 3.1 Master password, salt, and PBKDF2

When a keychain is created, the program generates a random 16-byte salt.
It combines the master password and salt using PBKDF2 with 100,000
iterations and SHA-256.

PBKDF2 is deliberately slow. This makes repeatedly guessing the master
password more expensive. The salt also means that the same master
password does not automatically produce the same derived key in two
keychains.

The salt is saved in the keychain data because it is needed to derive
the same keys when the keychain is loaded again. The master password
itself is not saved.

### 3.2 Two separate keys

The program uses HMAC with two different labels to derive two separate
keys from the PBKDF2-derived key:

-   `hmacKey` is used to create a hidden tag for each website name.
-   `aesKey` is used to encrypt and decrypt the saved passwords.

This keeps the two jobs separate. The actual website names are not
stored as the keys in the `kvs` object; their HMAC tags are stored
instead.

### 3.3 AES-GCM encryption and IVs

Each password is encrypted separately using AES-GCM. A new random
12-byte IV is generated for each encryption.

AES-GCM protects the password's confidentiality and checks that the
encrypted record has not been modified. If authentication fails during
decryption, the code throws an error rather than returning corrupted
data.

### 3.4 Associated data and swap-attack protection

The HMAC tag for the website name is supplied to AES-GCM as **additional
authenticated data (AAD)**.

AAD is not encrypted, but AES-GCM checks that it has not been changed.
This connects an encrypted password record to its intended website tag.

If an attacker swaps the encrypted records belonging to two websites,
the tag used during decryption will not match the AAD originally used to
encrypt that record. AES-GCM authentication should fail, and `get()`
throws `Tampering detected`.

This protection works independently of the optional whole-database
checksum.

### 3.5 Padding and password-length protection

Before encryption, `padValue()` creates a 65-byte value:

-   1 byte stores the real password length.
-   Up to 64 bytes store the password.
-   Any unused space is filled with zero bytes.

This means passwords of different permitted lengths produce ciphertexts
of the same length. `unpadValue()` reverses this after successful
decryption.

The implementation checks the UTF-8 byte length, not the number of
visible characters. Therefore, some non-ASCII characters can use more
than one byte.

### 3.6 Canary and master-password verification

The canary is a known phrase encrypted using the AES key. When loading a
keychain, the program tries to decrypt it.

If the user enters the wrong master password, the derived AES key will
be different. AES-GCM authentication will fail, so `load()` reports an
invalid password or corrupted data.

The canary lets the program check the password without storing the
password itself.

### 3.7 SHA-256 checksum and rollback protection

`dump()` builds a JSON object containing:

-   `salt`
-   `check` (the encrypted canary)
-   `kvs` (the stored encrypted records)

It deliberately does not serialize the whole `Keychain` object because
that object also contains `this.secrets`, where the secret keys are
kept.

The program calculates a SHA-256 checksum over the exact JSON string and
returns both values:

1.  The JSON representation.
2.  The Base64-encoded checksum.

When `load()` receives a trusted checksum, it calculates the checksum
again and compares the two. If they do not match, loading stops with an
integrity error.

This can detect changes to the saved database and replacement with an
older database version, provided the trusted checksum was kept
separately in a location the attacker cannot change. Without that
trusted checksum, this whole-database rollback check is not available.
The AAD protection against swapping records still applies.

## 4. How the assignment requirements are answered in the code

  -----------------------------------------------------------------------
  What the documentation asks for     How our code addresses it
  ----------------------------------- -----------------------------------
  Protect the keychain using a master `init()` and `load()` derive the
  password.                           keys from the supplied password
                                      using PBKDF2 and the stored salt.

  Do not save the master password or  `dump()` manually builds
  secret keys in the serialized       `publicState` using only `salt`,
  database.                           `check`, and `kvs`. It does not
                                      serialize `this.secrets`.

  Use PBKDF2 to derive keys, and call `deriveKeys()` makes one
  it only once per derivation.        `subtle.deriveKey()` call. It then
                                      derives the two separate sub-keys
                                      using HMAC.

  Hide website/domain names in the    `set()`, `get()`, and `remove()`
  KVS.                                calculate an HMAC tag from the
                                      domain name and use that tag as the
                                      KVS key.

  Encrypt each password separately    `set()` encrypts each padded
  using authenticated encryption.     password with AES-GCM; `get()`
                                      decrypts the selected record.

  Hide password lengths.              `padValue()` makes every permitted
                                      password plaintext 65 bytes before
                                      encryption.

  Prevent records from being swapped  `set()` uses the domain HMAC tag as
  between websites.                   AES-GCM AAD. `get()` supplies the
                                      same tag during decryption,
                                      allowing AES-GCM to detect a
                                      mismatch.

  Detect a wrong master password when `load()` derives the keys and
  loading.                            attempts to decrypt the canary.

  Support saving and restoring the    `dump()` uses `JSON.stringify()`
  keychain.                           and `load()` uses `JSON.parse()` to
                                      serialize and rebuild the state.

  Detect changes to the serialized    `dump()` returns a SHA-256
  database and rollback when          checksum; `load()` verifies it when
  possible.                           a trusted checksum is supplied.

  Implement the required keychain     The `Keychain` class implements
  operations.                         `init()`, `load()`, `dump()`,
                                      `set()`, `get()`, and `remove()`.
  -----------------------------------------------------------------------

## 5. Tests and demonstrations

The project documentation says the provided test suite can be run from
the project directory with:

``` bash
npm test
```

It also says the test suite is in `test/test-password-manager.js`, uses
MochaJS and Expect.js, and that the full grading tests are available
through Gradescope.

The `demo.js` demonstration covers the following scenarios. These are
the behaviours the checks are intended to show; a test should only be
reported as passing after its output confirms that result.

  -----------------------------------------------------------------------
  Test / demonstration    What is checked         Expected result
  ----------------------- ----------------------- -----------------------
  1\. Create and store    Create a keychain and   Entries are stored in
  entries                 save website/password   encrypted form.
                          pairs using `set()`.    

  2\. Get, update, and    Retrieve a saved        The correct value is
  remove                  password, update it,    returned; updates
                          retrieve the updated    replace the old value;
                          value, and remove an    removal succeeds.
                          entry.                  

  3\. Inspect the dump    Examine the serialized  It contains the salt,
                          JSON representation.    canary data, and
                                                  encrypted KVS records,
                                                  but not the master
                                                  password or secret
                                                  keys.

  4\. Load with correct   Load a saved            The correct password
  and incorrect passwords representation using    loads the keychain; the
                          the correct password    wrong password is
                          and then a wrong        rejected by the canary
                          password.               check.

  5\. Compare ciphertext  Store passwords with    Their ciphertext
  sizes                   different permitted     lengths are the same
                          lengths and compare     because the plaintexts
                          their ciphertext        are padded to 65 bytes
                          lengths.                before AES-GCM
                                                  encryption.

  6\. Swap records        Exchange records for    AES-GCM authentication
                          two domains and try to  fails because the AAD
                          retrieve them without   does not match the
                          relying on the          record's original
                          whole-database          domain tag.
                          checksum.               

  7\. Rollback check      Try loading an older    The checksum comparison
                          representation while    fails and loading is
                          supplying a checksum    rejected.
                          belonging to a newer    
                          representation.         

  8\. Modify ciphertext   Change a byte in a      AES-GCM authentication
                          stored ciphertext and   fails for the modified
                          try to retrieve that    record.
                          record.                 
  -----------------------------------------------------------------------

### Running the checks

From the project folder, run:

``` bash
npm test
```

To run the demonstration script, if it is named `demo.js`, run:

``` bash
node demo.js
```

Use the actual output from your terminal when reporting which tests
passed. The table above describes the test purpose and expected
behaviour; it does not claim that a particular run has passed.

## 6. What each security feature does --- quick recap

  -----------------------------------------------------------------------
  Feature                             Main purpose
  ----------------------------------- -----------------------------------
  PBKDF2 + salt                       Makes password guessing more
                                      expensive and derives the keys.

  HMAC domain tags                    Hides the website names in the
                                      stored KVS while still allowing
                                      lookup.

  AES-GCM                             Encrypts each saved password and
                                      detects modification.

  Random IV                           Gives each AES-GCM encryption a
                                      fresh initialization value.

  AAD                                 Binds each encrypted record to its
                                      website tag and helps prevent swap
                                      attacks.

  Padding                             Hides the length of each stored
                                      password within the supported
                                      limit.

  Canary                              Checks whether the master password
                                      supplied during loading is correct.

  SHA-256 checksum                    Detects changes to the serialized
                                      database when checked against a
                                      trusted copy.

  Base64                              Represents binary data as text so
                                      it can be stored in JSON; it does
                                      not provide security by itself.
  -----------------------------------------------------------------------

## 7. Important limitations to understand

-   The assignment is a simplified educational password manager, not a
    production-ready product.
-   The number of stored records is visible in the serialized KVS.
-   HMAC tags are deterministic, so the same domain produces the same
    tag within a keychain. This supports lookup but can reveal that two
    saved database versions contain the same domain.
-   Rollback detection depends on keeping the checksum somewhere the
    attacker cannot modify.
-   The code supports passwords up to 64 bytes because it checks
    `Buffer` byte length. This is slightly different from saying 64
    characters for all possible text.
-   The project does not implement a graphical user interface or actual
    disk-writing functionality; it uses serialization to represent
    saving and loading.

## 8. Short conclusion

The implementation meets the main design goals by using PBKDF2 to derive
keys, HMAC to hide website names, AES-GCM to encrypt and authenticate
individual passwords, padding to hide password lengths, a canary to
verify the master password, and a SHA-256 checksum to check the saved
database when a trusted checksum is available.

The main idea is that the password manager must protect more than the
password text: it must also protect the relationship between each
password and its website, and detect unauthorized changes to the stored
keychain.