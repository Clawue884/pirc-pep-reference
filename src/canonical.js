export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanonicalError';
  }
}

export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new CanonicalError(`non-canonical number: ${value}`);
    }
    return String(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new CanonicalError(`unsupported type: ${t}`);
}

export function isCanonical(text) {
  try {
    return canonicalize(JSON.parse(text)) === text;
  } catch {
    return false;
  }
}
