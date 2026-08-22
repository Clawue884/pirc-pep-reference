import fs from 'node:fs';
import path from 'node:path';

export class InMemoryNonceStore {
  constructor() {
    this.seen = new Map();
  }

  has(key) {
    return this.seen.has(key);
  }

  add(key) {
    this.seen.set(key, true);
  }

  size() {
    return this.seen.size;
  }
}

export class FileNonceStore extends InMemoryNonceStore {
  constructor(filePath) {
    super();
    this.filePath = filePath;
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(filePath)) {
      for (const line of fs.readFileSync(filePath, 'utf8').split('\n')) {
        const trimmed = line.trim();
        if (trimmed) this.seen.set(trimmed, true);
      }
    }
  }

  add(key) {
    super.add(key);
    fs.appendFileSync(this.filePath, key + '\n', 'utf8');
  }
}
