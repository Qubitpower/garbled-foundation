// A single garbled AND gate, built and evaluated with only the browser's
// native Web Crypto API (crypto.subtle.digest, crypto.getRandomValues) — no
// external crypto library, unlike Pedersen Foundation's EC demos.
//
// This is a deliberately simplified, "no Oblivious Transfer" version: since
// the whole thing runs in one browser tab with no second untrusted party over
// a network, there is nothing to hide from anyone, so wire labels for both
// sides are just handed over directly. See /how-it-works for why that would
// be a critical security hole in a real two-party protocol.

/** 128-bit (16-byte) random wire label. */
export function randomLabel() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytes;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrs) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const ZERO16 = new Uint8Array(16);
const enc = new TextEncoder();

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * keystream = SHA256(k1‖k2‖gate_id‖"0") ‖ SHA256(k1‖k2‖gate_id‖"1")  (32 bytes)
 *
 * Each SHA-256 call natively outputs 256 bits; for the concatenation of two
 * of them to total 256 bits (matching the 128-bit label + 128-bit zero-check
 * the ciphertext XORs against), each half is truncated to its first 128 bits
 * before concatenating.
 */
async function keystream(k1, k2, gateId) {
  const gateIdBytes = enc.encode(gateId);
  const h0 = await sha256(concatBytes(k1, k2, gateIdBytes, enc.encode('0')));
  const h1 = await sha256(concatBytes(k1, k2, gateIdBytes, enc.encode('1')));
  return concatBytes(h0.slice(0, 16), h1.slice(0, 16));
}

/** ciphertext = keystream ⊕ (label ‖ 0^128) */
async function encryptCell(k1, k2, gateId, label) {
  const ks = await keystream(k1, k2, gateId);
  const plaintext = concatBytes(label, ZERO16);
  return xorBytes(ks, plaintext);
}

/**
 * Garble a single two-input AND gate.
 * @returns {Promise<{gateId: string, rows: Array, table: Uint8Array[]}>}
 *   rows: the 4 truth-table rows in original (unshuffled) order, each with
 *     {a, b, k1, k2, outLabel, ciphertext} — useful for showing how the table
 *     was built, step by step.
 *   table: the same 4 ciphertexts, randomly shuffled — what the Evaluator
 *     actually receives.
 */
export async function garbleAndGate(gateId, wires) {
  const { W1_0, W1_1, W2_0, W2_1, Wout_0, Wout_1 } = wires;
  const truthTable = [
    { a: 0, b: 0, k1: W1_0, k2: W2_0, outLabel: Wout_0 },
    { a: 0, b: 1, k1: W1_0, k2: W2_1, outLabel: Wout_0 },
    { a: 1, b: 0, k1: W1_1, k2: W2_0, outLabel: Wout_0 },
    { a: 1, b: 1, k1: W1_1, k2: W2_1, outLabel: Wout_1 },
  ];

  const rows = [];
  for (const row of truthTable) {
    const ciphertext = await encryptCell(row.k1, row.k2, gateId, row.outLabel);
    rows.push({ ...row, ciphertext });
  }

  const table = rows.map((r) => r.ciphertext);
  for (let i = table.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [table[i], table[j]] = [table[j], table[i]];
  }

  return { gateId, rows, table };
}

/**
 * Evaluate a garbled AND gate given exactly one label per input wire.
 * @returns {Promise<{attempts: Array, matchIndex: number, outputLabel: Uint8Array}>}
 *   attempts: all 4 XOR results, each with {index, plaintext, label, check, isZero}
 *   matchIndex: which attempt had a zero tail (the real one)
 *   outputLabel: the recovered 128-bit output label
 */
export async function evaluateAndGate(gateId, L1, L2, table) {
  const ks = await keystream(L1, L2, gateId);
  const attempts = [];
  let matchIndex = -1;
  let outputLabel = null;

  for (let i = 0; i < table.length; i++) {
    const plaintext = xorBytes(ks, table[i]);
    const label = plaintext.slice(0, 16);
    const check = plaintext.slice(16, 32);
    const isZero = bytesEqual(check, ZERO16);
    attempts.push({ index: i, plaintext, label, check, isZero });
    if (isZero && matchIndex === -1) {
      matchIndex = i;
      outputLabel = label;
    }
  }

  return { attempts, matchIndex, outputLabel };
}

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function labelsEqual(a, b) {
  return bytesEqual(a, b);
}
