import { Buffer } from 'buffer';

// bip39 (and some transitive deps) expect Node's `Buffer` — missing in browsers / Hermes by default.
const g = globalThis as typeof globalThis & { Buffer?: typeof Buffer };
if (typeof g.Buffer === 'undefined') {
  g.Buffer = Buffer;
}
