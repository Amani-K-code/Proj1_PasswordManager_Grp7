"use strict";

/**
 *  SECURE PASSWORD MANAGER (Keychain)
 * 
 * =========================================================================
 * - Your MASTER PASSWORD is the key to "vault"
 * - PBKDF2 turns password into a strong master key
 * 
 * - From the master key , TWO sub -keys:
 *   - hmacKey -> scrambles the LABELS on the boxes (domain names)
 *   - aesKey -> locks the CONTENTS of each box (password entries)
 * 
 * - Every box has the same size (padding), so nobody cant tell the length of the stored passwords
 * - Each box is tied to its own label (AAD), so swapping boxes is detected.
 * - A receipt (SHA-256 checksum) kept somewhere safe lets us notice if someone replaced the whole vault with an OLD copy(rollback)
 * 
 * =========================================================================
 */

/********* External Imports ********/

// External libraries and utilities for cryptographic operations
// Helper functions from starter code (string <-> bytes <-> Base64, random bytes)
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");


// SubtleCrypto: Node's built-in, well-tested crypto library (Not invented by us(No self generated crypto))
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const PADDED_SIZE = MAX_PASSWORD_LENGTH +1; // every plaintext becomes exactly 65 bytes (1 length byte + 64 daata bytes)
const CANARY_TEXT = "keychain-password-check"; //known plaintext used to verify the password





/**
 * ==========================================================================
 * HELPER 1: Key derivation
 * 
 * deriveKeys(password, salt)
 *      Turns (master passowrd + salt) into TWO independent keys.
 *      Only ONE slow PBKDF2 call happens here (spec requirement)
 *      Returns { hmacKey, aesKey }.
 */

// Thoraway: stands in for Person1 - key derivation
async function deriveKeys(password, salt) {
  // 1. Wrap the raw password so PBKDF2 can use it.
  // "raw" = plain bytes, "PBKDF2" = only usable for PBKDF2, false = not exportale
  // ["derieKey"] = the only thing this key may do is derive other keys.

  const raw = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  // 2 THE ONE slow PBKDF2 call: password + salt -> a 256-bit master key
  // The salt makes every user's key different, even with identical pw
  // Atacker cannot reuse one dictionary attack against everybody.
  const master = await subtle.deriveKey(
    {name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    raw,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false, ["sign"]);

  // 3 Use HMAC as a PRF: signing2 different lavels to get two independent sub-keys
  const hmacBits = await subtle.sign("HMAC", master, stringToBuffer("domain-hmac-key"));
  const aesBits = await subtle.sign("HMAC", master, stringToBuffer("aes-gcm-key"));

  // 4 Import raw bytes as proper Cryptokeys, each limited to 1 job
  const hmacKey = await subtle.importKey(
    "raw", hmacBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const aesKey = await subtle.importKey(
    "raw", aesBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { hmacKey, aesKey };
}

// Throwaway: the "canary", an encrypted known string stored in the dump.
// Decrypting it later proves the pw is right, and reveals nothing about it.
async function makeCanary(aesKey) {
  const iv = getRandomBytes(12); // fresh random IV every time(for GCM)
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: stringToBuffer("canary") },
     aesKey, stringToBuffer(CANARY_TEXT));
  return { iv: encodeBuffer(iv), ct: encodeBuffer(ct) }; // Base64 so JSON can hold them
}



  /********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(data, secrets){
    this.data = data;
    this.secrets = secrets;
  }

  static async init(password) {
    const salt = getRandomBytes(16);
    const keys = await deriveKeys(password, salt);
    return new Keychain(
      { salt: encodeBuffer(salt), check: await makeCanary(keys.aesKey), kvs: {} },
      keys);
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    //throw "Not Implemented!";

    //Run first only if checksum was provided
    // Recompute the hash and compare to the trusted one.(optional per the spec)
    if (trustedDataCheck !== undefined && trustedDataCheck !== null) {
      const actual = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (actual !== trustedDataCheck) {
        throw "Integrity check failed: data was tampered with or rolled back ";
      }
    }

    // Parse the stored state
    const parsed = JSON.parse(repr);

    // Re -drive the keys from the password and salt
    // Its only the PBKDF2 call in this function
    const keys = await deriveKeys(password, decodeBuffer(parsed.salt));
    
    // PW CHECK: Tr to decrypt the canary, a wrong pw gives a wrong key, so GCM auth fails and decrypt() will throw
    let plain;
    try {
      plain = await subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(parsed.check.iv),
          additionalData: stringToBuffer("canary")
        },
        keys.aesKey, decodeBuffer(parsed.check.ct));
        } catch (e) {
          throw "Invalid password (or corupted data)";
    }
    if (bufferToString(plain) !== CANARY_TEXT) {
      throw "Invalid password (or corrupted data)";
    }

    // Rebuild the keychain from the stored public state plus the derived keys.
    // The kvs comes from the parse data, so edits to it are reflected.
    return new Keychain(
      {salt: parsed.salt, check: parsed.check, kvs: parsed.kvs },
      keys);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 

  /** AMANI's part - Part 3 
   * Turn in-memory state into a string without leaking secrets, and rebuild it faithfully
   * Passowrd verification without storing anything about the password.
   * Why the encryption alone doesn't give integrity of the whole db
   */
  async dump() {
    //throw "Not Implemented!";
    
    // Building the object to serialize By HAND
    // We don't JSON.stringify(this), because it would expose/write out this.secrets(the keys)

    const publicState = {
      salt: this.data.salt,
      check: this.data.check,
      kvs: this.data.kvs
    };

    const repr = JSON.stringify(publicState) /// string "written to disk"

    // SHA-256 over the EXACT string, keeping the caller in the trusted storage.
    // Any change in characters to repr later on changes the whole hash

    const digest = await subtle. digest("SHA-256", stringToBuffer(repr));

    return [repr, encodeBuffer(digest)]; // serialization , Base64 checksum


  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */


  /**MOCK UP code for Ivan's part for testing the functionality */
  // Person 2 

  async get(name) {
    // throw "Not Implemented!";
    const tag = encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name)));
    const rec = this.data.kvs[tag]
    if (rec === undefined) return null;
    try {
      const pt = await subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(rec.iv), additionalData: stringToBuffer(tag) },
        this.secrets.aesKey, decodeBuffer(rec.ct));
      return bufferToString(pt);
    } catch (e) {
      throw "Tampering detected"; // GCM auth failed
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */

  async set(name, value) {
    // throw "Not Implemented!";
    const tag = encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name)));
    const iv = getRandomBytes(12);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(tag) },
      this.secrets.aesKey, stringToBuffer(value));
      this.data.kvs[tag] = { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    //throw "Not Implemented!";
    const tag = encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name)));
    if (this.data.kvs[tag] === undefined) return false;
    delete this.data.kvs[tag];
    return true;
  };
};

module.exports = { Keychain }
