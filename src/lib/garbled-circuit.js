// A small garbled circuit — several AND/XOR/NOT gates chained together —
// built and evaluated with only the browser's native Web Crypto API. Used by
// the 2-bit comparator demo: reuses the exact same gate construction as
// src/lib/garbled-and.js (see that file for the single-gate walkthrough),
// generalized to (a) 1-input gates (NOT) as well as 2-input gates (AND, XOR),
// and (b) chaining — a gate's output wire becomes the next gate's input wire.
//
// Generalizing the keystream to a 1-input gate: the construction on
// /how-it-works defines keystream(k1, k2, gate_id) for a 2-input gate. For a
// 1-input gate (NOT) there is naturally only one key to hash in — this file
// hashes whatever keys the gate actually has (one or two) into the same
// keystream formula.

function randomLabel() {
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

/** keystream over 1 or 2 input keys — see file header for the generalization. */
async function keystream(gateId, keys) {
  const gateIdBytes = enc.encode(gateId);
  const h0 = await sha256(concatBytes(...keys, gateIdBytes, enc.encode('0')));
  const h1 = await sha256(concatBytes(...keys, gateIdBytes, enc.encode('1')));
  return concatBytes(h0.slice(0, 16), h1.slice(0, 16));
}

async function encryptCell(gateId, keys, label) {
  const ks = await keystream(gateId, keys);
  const plaintext = concatBytes(label, ZERO16);
  return xorBytes(ks, plaintext);
}

/** AND(bits), XOR(bits), NOT(bits) — bits is an array of 0/1, one per input wire. */
export const AND = (bits) => bits[0] & bits[1];
export const XOR = (bits) => bits[0] ^ bits[1];
export const NOT = (bits) => (bits[0] ? 0 : 1);

export function newWirePair() {
  return [randomLabel(), randomLabel()];
}

/**
 * Garble a gate with 1 or 2 input wires.
 * @param gateId unique id for this gate
 * @param wirePairs array of [w0, w1] pairs, one per input wire
 * @param outPair [w0, w1] for the output wire
 * @param truthFn (bits: number[]) => 0 | 1
 * @returns {Promise<{rows: Array, table: Uint8Array[]}>}
 */
export async function garbleGate(gateId, wirePairs, outPair, truthFn) {
  const n = wirePairs.length;
  const rows = [];
  for (let i = 0; i < 1 << n; i++) {
    const bits = [];
    for (let b = n - 1; b >= 0; b--) bits.push((i >> b) & 1);
    const keys = bits.map((bit, idx) => wirePairs[idx][bit]);
    const outBit = truthFn(bits);
    const outLabel = outPair[outBit];
    const ciphertext = await encryptCell(gateId, keys, outLabel);
    rows.push({ bits, keys, outLabel, ciphertext });
  }
  const table = rows.map((r) => r.ciphertext);
  for (let i = table.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [table[i], table[j]] = [table[j], table[i]];
  }
  return { rows, table };
}

/** Evaluate a gate given exactly the right number of input keys. */
export async function evaluateGate(gateId, keys, table) {
  const ks = await keystream(gateId, keys);
  const attempts = [];
  let matchIndex = -1;
  let outputLabel = null;
  for (let i = 0; i < table.length; i++) {
    const plaintext = xorBytes(ks, table[i]);
    const label = plaintext.slice(0, 16);
    const check = plaintext.slice(16, 32);
    const isZero = bytesEqual(check, ZERO16);
    attempts.push({ index: i, label, check, isZero });
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

/**
 * Build the 2-bit "who's bigger" comparator: gt(a1a0, b1b0) computes a > b.
 *   gt = (a1 AND NOT b1) OR (NOT(a1 XOR b1) AND (a0 AND NOT b0))
 * OR is built from AND + NOT via De Morgan's law (X OR Y = NOT(NOT X AND NOT Y))
 * to keep to only AND/XOR/NOT gates, as on /how-it-works.
 */
export async function buildComparatorCircuit() {
  const A1 = newWirePair(), A0 = newWirePair(), B1 = newWirePair(), B0 = newWirePair();
  const N_B1 = newWirePair(), N_B0 = newWirePair();
  const T1 = newWirePair(), X = newWirePair(), N_X = newWirePair();
  const T2A = newWirePair(), T2 = newWirePair();
  const N_T1 = newWirePair(), N_T2 = newWirePair(), N_OR = newWirePair();
  const GT = newWirePair();

  const gates = [
    { id: 'g1-not-b1', label: 'NOT(b₁)', ins: [B1], out: N_B1, fn: NOT },
    { id: 'g2-not-b0', label: 'NOT(b₀)', ins: [B0], out: N_B0, fn: NOT },
    { id: 'g3-t1', label: 'a₁ AND NOT(b₁)', ins: [A1, N_B1], out: T1, fn: AND },
    { id: 'g4-xor', label: 'a₁ XOR b₁', ins: [A1, B1], out: X, fn: XOR },
    { id: 'g5-not-xor', label: 'NOT(a₁ XOR b₁)', ins: [X], out: N_X, fn: NOT },
    { id: 'g6-t2a', label: 'a₀ AND NOT(b₀)', ins: [A0, N_B0], out: T2A, fn: AND },
    { id: 'g7-t2', label: 'NOT(a₁ XOR b₁) AND (a₀ AND NOT(b₀))', ins: [N_X, T2A], out: T2, fn: AND },
    { id: 'g8-not-t1', label: 'NOT(t₁)', ins: [T1], out: N_T1, fn: NOT },
    { id: 'g9-not-t2', label: 'NOT(t₂)', ins: [T2], out: N_T2, fn: NOT },
    { id: 'g10-nor', label: 'NOT(t₁) AND NOT(t₂)', ins: [N_T1, N_T2], out: N_OR, fn: AND },
    { id: 'g11-gt', label: 'gt = NOT(that) = t₁ OR t₂', ins: [N_OR], out: GT, fn: NOT },
  ];

  const wireName = new Map([
    [A1, 'A1'], [A0, 'A0'], [B1, 'B1'], [B0, 'B0'],
  ]);

  const tables = {};
  for (const g of gates) {
    tables[g.id] = (await garbleGate(g.id, g.ins, g.out, g.fn)).table;
    wireName.set(g.out, g.id + '-out');
  }

  return { A1, A0, B1, B0, GT, gates, tables, wireName };
}

/**
 * Evaluate the comparator for specific input bits, returning a trace of every
 * gate's evaluation in order (for step-by-step display).
 */
export async function evaluateComparatorCircuit(circuit, a1bit, a0bit, b1bit, b0bit) {
  const labelOf = new Map();
  labelOf.set('A1', circuit.A1[a1bit]);
  labelOf.set('A0', circuit.A0[a0bit]);
  labelOf.set('B1', circuit.B1[b1bit]);
  labelOf.set('B0', circuit.B0[b0bit]);

  const trace = [];
  for (const g of circuit.gates) {
    const keys = g.ins.map((wirePair) => labelOf.get(circuit.wireName.get(wirePair)));
    const { attempts, matchIndex, outputLabel } = await evaluateGate(g.id, keys, circuit.tables[g.id]);
    const outName = circuit.wireName.get(g.out);
    labelOf.set(outName, outputLabel);
    const outBit = labelsEqual(outputLabel, g.out[1]) ? 1 : 0;
    trace.push({ gate: g, matchIndex, attemptsCount: attempts.length, outBit });
  }

  const gtLabel = labelOf.get(circuit.wireName.get(circuit.GT));
  const gtBit = labelsEqual(gtLabel, circuit.GT[1]) ? 1 : 0;
  return { trace, gtBit };
}
