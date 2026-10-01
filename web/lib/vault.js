// Encrypted local store for device state (IndexedDB + WebCrypto).
//
// - Every record is AES-256-GCM encrypted under a key derived from a user
//   passphrase with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt).
//   The derived key is a non-extractable CryptoKey that lives only in memory
//   for the unlocked session; it is never written to storage.
// - A record's ciphertext is bound to its id through AES-GCM additional data,
//   so ciphertexts cannot be swapped between records undetected.
// - commit() writes several records in ONE IndexedDB transaction, which is
//   all-or-nothing, with durability 'strict' where the browser supports it.
//   A client must commit new ratchet state before acknowledging a message.
// - A copied browser profile yields only the salt and ciphertexts; recovering
//   the data requires guessing the passphrase. PBKDF2 is GPU-friendly, so a
//   weak passphrase is weak protection (see VALIDATION_REPORT.md).

const DB_NAME = 'signal-web';
const DB_VERSION = 1;
const ITERATIONS = 600_000;
const KEY_CHECK_ID = '__key_check__';
const KEY_CHECK_TEXT = 'signal-web vault key check v1';
const enc = new TextEncoder();

export class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'VaultError';
    this.code = code; // NO_VAULT | EXISTS | WRONG_PASSPHRASE | CORRUPT_RECORD | MISSING_RECORD
  }
}

const req = (r) => new Promise((resolve, reject) => {
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});

const done = (tx) => new Promise((resolve, reject) => {
  tx.oncomplete = () => resolve();
  tx.onerror = () => reject(tx.error);
  tx.onabort = () => reject(tx.error ?? new Error('transaction aborted'));
});

export function openDb() {
  const r = indexedDB.open(DB_NAME, DB_VERSION);
  r.onupgradeneeded = () => {
    r.result.createObjectStore('meta');
    r.result.createObjectStore('records');
  };
  return req(r);
}

async function deriveKey(passphrase, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
}

const aad = (id) => enc.encode(`signal-web/v1/record/${id}`);

async function seal(key, id, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(id) }, key, plaintext));
  return { v: 1, iv, ct };
}

async function unseal(key, id, rec) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: aad(id) }, key, rec.ct));
  } catch {
    throw new VaultError('CORRUPT_RECORD', `record "${id}" failed authentication (corrupted, swapped or wrong key)`);
  }
}

export class Vault {
  #db;
  #key;

  constructor(db, key) {
    this.#db = db;
    this.#key = key;
  }

  static async exists() {
    const db = await openDb();
    try {
      return Boolean(await req(db.transaction('meta').objectStore('meta').get('vault')));
    } finally {
      db.close();
    }
  }

  static async create(passphrase) {
    const db = await openDb();
    if (await req(db.transaction('meta').objectStore('meta').get('vault'))) {
      db.close();
      throw new VaultError('EXISTS', 'a vault already exists in this browser profile');
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(passphrase, salt, ITERATIONS);
    const check = await seal(key, KEY_CHECK_ID, enc.encode(KEY_CHECK_TEXT));
    const tx = db.transaction('meta', 'readwrite', { durability: 'strict' });
    tx.objectStore('meta').put({ v: 1, kdf: { name: 'PBKDF2-SHA256', iterations: ITERATIONS, salt }, check }, 'vault');
    await done(tx);
    return new Vault(db, key);
  }

  static async unlock(passphrase) {
    const db = await openDb();
    const meta = await req(db.transaction('meta').objectStore('meta').get('vault'));
    if (!meta) {
      db.close();
      throw new VaultError('NO_VAULT', 'no stored device state in this browser profile');
    }
    const key = await deriveKey(passphrase, meta.kdf.salt, meta.kdf.iterations);
    try {
      await unseal(key, KEY_CHECK_ID, meta.check);
    } catch {
      db.close();
      throw new VaultError('WRONG_PASSPHRASE', 'unlock failed: wrong passphrase (or a corrupted key-check record)');
    }
    return new Vault(db, key);
  }

  static async destroy() {
    await req(indexedDB.deleteDatabase(DB_NAME));
  }

  async get(id) {
    const rec = await req(this.#db.transaction('records').objectStore('records').get(id));
    if (!rec) throw new VaultError('MISSING_RECORD', `record "${id}" not found`);
    return unseal(this.#key, id, rec);
  }

  /** Atomically encrypts and writes all entries ({ id: Uint8Array }). */
  async commit(entries) {
    const sealed = await Promise.all(
      Object.entries(entries).map(async ([id, bytes]) => [id, await seal(this.#key, id, bytes)]),
    );
    const tx = this.#db.transaction('records', 'readwrite', { durability: 'strict' });
    for (const [id, rec] of sealed) tx.objectStore('records').put(rec, id);
    await done(tx);
  }

  close() {
    this.#key = null;
    this.#db.close();
  }
}

/** Test helper: raw (still encrypted) record and meta access. */
export async function rawStore(store, id, value) {
  const db = await openDb();
  try {
    if (value === undefined) return await req(db.transaction(store).objectStore(store).get(id));
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value, id);
    await done(tx);
    return value;
  } finally {
    db.close();
  }
}
