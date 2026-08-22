import fs from 'node:fs';
import path from 'node:path';

function assertNonceKey(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError('nonce key must be a non-empty string');
  }
}

/**
 * In-memory nonce store.
 *
 * checkAndAdd() is the preferred API because the check + insertion
 * is performed as one synchronous operation within the JavaScript
 * execution context.
 */
export class InMemoryNonceStore {
  constructor() {
    this.seen = new Map();
  }

  has(key) {
    assertNonceKey(key);
    return this.seen.has(key);
  }

  add(key) {
    assertNonceKey(key);
    this.seen.set(key, true);
  }

  /**
   * Atomically check whether a nonce exists and record it if not.
   *
   * @returns {boolean}
   *   true  = nonce was newly recorded
   *   false = nonce was already present
   */
  checkAndAdd(key) {
    assertNonceKey(key);

    if (this.seen.has(key)) {
      return false;
    }

    this.seen.set(key, true);
    return true;
  }

  size() {
    return this.seen.size;
  }
}

/**
 * File-backed nonce store.
 *
 * The file format remains one nonce key per line, preserving
 * compatibility with the original implementation.
 *
 * NOTE:
 * checkAndAdd() is protected by a filesystem lock so multiple
 * verifier processes sharing the same nonce file do not perform
 * an unsafe has()+add() sequence concurrently.
 */
export class FileNonceStore extends InMemoryNonceStore {
  constructor(filePath, {
    lockTimeoutMs = 5000,
    staleLockMs = 30000
  } = {}) {
    super();

    if (typeof filePath !== 'string' || filePath.length === 0) {
      throw new TypeError('filePath must be a non-empty string');
    }

    if (
      !Number.isSafeInteger(lockTimeoutMs) ||
      lockTimeoutMs < 0
    ) {
      throw new TypeError('lockTimeoutMs must be a non-negative safe integer');
    }

    if (
      !Number.isSafeInteger(staleLockMs) ||
      staleLockMs <= 0
    ) {
      throw new TypeError('staleLockMs must be a positive safe integer');
    }

    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.lockTimeoutMs = lockTimeoutMs;
    this.staleLockMs = staleLockMs;

    const dir = path.dirname(this.filePath);

    fs.mkdirSync(dir, {
      recursive: true
    });

    this.#load();
  }

  #load() {
    if (!fs.existsSync(this.filePath)) {
      return;
    }

    const contents = fs.readFileSync(
      this.filePath,
      'utf8'
    );

    for (const line of contents.split('\n')) {
      const trimmed = line.trim();

      if (trimmed) {
        this.seen.set(trimmed, true);
      }
    }
  }

  #sleep(ms) {
    /*
     * Node has no synchronous sleep primitive in the standard
     * library. Atomics.wait provides a synchronous bounded wait
     * without external dependencies.
     */
    if (ms <= 0) {
      return;
    }

    const buffer = new SharedArrayBuffer(4);
    const view = new Int32Array(buffer);

    Atomics.wait(
      view,
      0,
      0,
      ms
    );
  }

  #lock() {
    const startedAt = Date.now();

    while (true) {
      try {
        /*
         * mkdir is atomic at the filesystem level.
         *
         * Only one process can successfully create the directory.
         */
        fs.mkdirSync(this.lockPath);

        /*
         * Write owner metadata for stale-lock diagnostics.
         */
        try {
          fs.writeFileSync(
            path.join(this.lockPath, 'owner'),
            JSON.stringify({
              pid: process.pid,
              created_at: Date.now()
            }),
            'utf8'
          );
        } catch {
          /*
           * Lock ownership is still established by mkdir().
           * Metadata is diagnostic only.
           */
        }

        return;
      } catch (err) {
        if (err?.code !== 'EEXIST') {
          throw err;
        }

        /*
         * Detect a stale lock.
         */
        try {
          const stat = fs.statSync(this.lockPath);

          if (
            Date.now() - stat.mtimeMs >
            this.staleLockMs
          ) {
            fs.rmSync(
              this.lockPath,
              {
                recursive: true,
                force: true
              }
            );

            continue;
          }
        } catch (statErr) {
          /*
           * Another process may have released the lock between
           * our failed mkdir and stat.
           */
          if (statErr?.code !== 'ENOENT') {
            throw statErr;
          }

          continue;
        }

        if (
          Date.now() - startedAt >=
          this.lockTimeoutMs
        ) {
          const error = new Error(
            'nonce store lock acquisition timed out'
          );

          error.code = 'NONCE_LOCK_TIMEOUT';

          throw error;
        }

        this.#sleep(10);
      }
    }
  }

  #unlock() {
    fs.rmSync(
      this.lockPath,
      {
        recursive: true,
        force: true
      }
    );
  }

  #reloadFromDisk() {
    /*
     * Another verifier process may have appended a nonce since this
     * instance was created. Reload while holding the lock.
     */
    this.seen.clear();
    this.#load();
  }

  checkAndAdd(key) {
    assertNonceKey(key);

    this.#lock();

    try {
      /*
       * Refresh state while holding the inter-process lock.
       */
      this.#reloadFromDisk();

      if (this.seen.has(key)) {
        return false;
      }

      /*
       * Persist first. Only update the in-memory state after the
       * append succeeds.
       */
      fs.appendFileSync(
        this.filePath,
        `${key}\n`,
        'utf8'
      );

      this.seen.set(key, true);

      return true;
    } finally {
      this.#unlock();
    }
  }

  add(key) {
    assertNonceKey(key);

    /*
     * Preserve the old API, but route it through the safe operation.
     *
     * Existing callers that blindly call add() retain their behavior;
     * duplicate insertion is simply ignored.
     */
    this.checkAndAdd(key);
  }
}
