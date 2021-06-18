/*! noble-bls12-381 - MIT License (c) Paul Miller (paulmillr.com) */
// bls12-381 is a construction of two curves:
// 1. Fq: (x, y)
// 2. Fq2: ((x1, x2+i), (y1, y2+i)) - (imaginary numbers)
//
// Bilinear Pairing (ate pairing) is used to combine both elements into a paired one:
//   Fq12 = e(Fq, Fq2)
//   where Fq12 = 12-degree polynomial
// Pairing is used to verify signatures.
//
// We are using Fq for private keys (shorter) and Fq2 for signatures (longer).
// Some projects may prefer to swap this relation, it is not supported for now.
// prettier-ignore
import {
  Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve, ProjectivePoint,
  map_to_curve_SSWU_G2, isogenyMapG2,
  millerLoop, psi, psi2, calcPairingPrecomputes,
  mod, powMod
} from './math';
export { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve };
export let DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';

type Bytes = Uint8Array | string;
type PrivateKey = Bytes | bigint | number;

const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32;

export const utils = {
  async sha256(message: Uint8Array): Promise<Uint8Array> {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      const buffer = await window.crypto.subtle.digest('SHA-256', message.buffer);
      // @ts-ignore
      return new Uint8Array(buffer);
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { createHash } = require('crypto');
      const hash = createHash('sha256');
      hash.update(message);
      return Uint8Array.from(hash.digest());
    } else {
      throw new Error("The environment doesn't have sha256 function");
    }
  },
  randomPrivateKey: (bytesLength: number = 32): Uint8Array => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      return window.crypto.getRandomValues(new Uint8Array(bytesLength));
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { randomBytes } = require('crypto');
      return new Uint8Array(randomBytes(bytesLength).buffer);
    } else {
      throw new Error("The environment doesn't have randomBytes function");
    }
  },
  mod,
};

function bytesToNumberBE(bytes: Uint8Array) {
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('Expected valid hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

function toPaddedHex(num: bigint, padding: number) {
  if (num < 0n) throw new Error('Expected valid number');
  if (typeof padding !== 'number') throw new TypeError('Expected valid padding');
  return num.toString(16).padStart(padding * 2, '0');
}

function expectHex(item: unknown): void {
  if (typeof item !== 'string' && !(item instanceof Uint8Array)) {
    throw new TypeError('Expected hex string or Uint8Array');
  }
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// UTF8 to ui8a
function stringToBytes(str: string) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

// Octet Stream to Integer
function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

// Integer to Octet Stream
function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1 << (8 * length)) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8;
  }
  return new Uint8Array(res);
}

function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}

async function expand_message_xmd(
  msg: Uint8Array,
  DST: Uint8Array,
  len_in_bytes: number
): Promise<Uint8Array> {
  const H = utils.sha256;
  const b_in_bytes = SHA256_DIGEST_SIZE;
  const r_in_bytes = b_in_bytes * 2;

  const ell = Math.ceil(len_in_bytes / b_in_bytes);
  if (ell > 255) throw new Error('Invalid xmd length');
  const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(len_in_bytes, 2);
  const b = new Array<Uint8Array>(ell);
  const b_0 = await H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = await H(concatBytes(b_0, i2osp(1, 1), DST_prime));
  for (let i = 1; i <= ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
    b[i] = await H(concatBytes(...args));
  }
  const pseudo_random_bytes = concatBytes(...b);
  return pseudo_random_bytes.slice(0, len_in_bytes);
}

// degree - extension degree, 1 for Fp, 2 for Fp2
// isRandomOracle - specifies NU or RO as per spec
export async function hash_to_field(
  msg: Uint8Array,
  degree: number,
  isRandomOracle = true
): Promise<bigint[][]> {
  const count = isRandomOracle ? 2 : 1;
  const m = degree;
  const L = 64; // 64 for sha2, shake, sha3, blake
  const len_in_bytes = count * m * L;
  const DST = stringToBytes(DST_LABEL);
  const pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes);
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const e = new Array(m);
    for (let j = 0; j < m; j++) {
      const elm_offset = L * (j + i * m);
      const tv = pseudo_random_bytes.slice(elm_offset, elm_offset + L);
      e[j] = mod(os2ip(tv), CURVE.P);
    }
    u[i] = e;
  }
  return u;
}

function normalizePrivKey(key: PrivateKey): bigint {
  let int: bigint;
  if (key instanceof Uint8Array && key.length === 32) int = bytesToNumberBE(key);
  else if (typeof key === 'string' && key.length === 64) int = BigInt(`0x${key}`);
  else if (typeof key === 'number' && key > 0 && Number.isSafeInteger(key)) int = BigInt(key);
  else if (typeof key === 'bigint' && key > 0n) int = key;
  else throw new TypeError('Expected valid private key');
  int = mod(int, CURVE.r);
  if (int < 1n) throw new Error('Private key must be 0 < key < CURVE.r');
  return int;
}

export class PointG1 extends ProjectivePoint<Fq> {
  static BASE = new PointG1(new Fq(CURVE.Gx), new Fq(CURVE.Gy), Fq.ONE);
  static ZERO = new PointG1(Fq.ONE, Fq.ONE, Fq.ZERO);

  constructor(x: Fq, y: Fq, z: Fq) {
    super(x, y, z, Fq);
  }

  static fromHex(bytes: Bytes) {
    expectHex(bytes);
    if (typeof bytes === 'string') bytes = hexToBytes(bytes);
    const {P} = CURVE;

    let point;
    if (bytes.length === 48) {
      const compressedValue = bytesToNumberBE(bytes);
      const bflag = mod(compressedValue, POW_2_383) / POW_2_382;
      if (bflag === 1n) {
        return this.ZERO;
      }
      const x = mod(compressedValue, POW_2_381);
      const fullY = mod(x ** 3n + new Fq(CURVE.b).value, P);
      let y = powMod(fullY, (P + 1n) / 4n, P);
      if (powMod(y, 2n, P) - fullY !== 0n) {
        throw new Error('The given point is not on G1: y**2 = x**3 + b');
      }
      const aflag = mod(compressedValue, POW_2_382) / POW_2_381;
      if ((y * 2n) / P !== aflag) {
        y = P - y;
      }
      point = new PointG1(new Fq(x), new Fq(y), new Fq(1n));
    } else if (bytes.length === 96) {
      // Check if the infinity flag is set
      if ((bytes[0] & (1 << 6)) !== 0) {
        return PointG1.ZERO;
      }

      const x = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
      const y = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH));

      point = new PointG1(new Fq(x), new Fq(y), Fq.ONE);
    } else {
      throw new Error('Invalid point G1, expected 48/96 bytes');
    }

    point.assertValidity();
    return point;
  }

  static fromPrivateKey(privateKey: PrivateKey) {
    return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
  }

  toRawBytes(isCompressed = false) {
    return hexToBytes(this.toHex(isCompressed));
  }

  toHex(isCompressed = false) {
    const {P} = CURVE;
    if (isCompressed) {
      let hex;
      if (this.equals(PointG1.ZERO)) {
        hex = POW_2_383 + POW_2_382;
      } else {
        const [x, y] = this.toAffine();
        const flag = (y.value * 2n) / P;
        hex = x.value + flag * POW_2_381 + POW_2_383;
      }
      return toPaddedHex(hex, PUBLIC_KEY_LENGTH);
    } else {
      if (this.equals(PointG1.ZERO)) {
        // 2x PUBLIC_KEY_LENGTH
        return '4'.padEnd(2 * 2 * PUBLIC_KEY_LENGTH, '0'); // bytes[0] |= 1 << 6;
      } else {
        const [x, y] = this.toAffine();
        return toPaddedHex(x.value, PUBLIC_KEY_LENGTH) + toPaddedHex(y.value, PUBLIC_KEY_LENGTH);
      }
    }
  }

  assertValidity() {
    const b = new Fq(CURVE.b);
    if (this.isZero()) return;
    const { x, y, z } = this;
    const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
    const right = b.multiply(z.pow(3n) as Fq);
    if (!left.subtract(right).equals(Fq.ZERO)) throw new Error('Invalid point: not on curve Fq');
  }

  toRepr() {
    return [this.x, this.y, this.z].map((v) => v.value);
  }

  // Sparse multiplication against precomputed coefficients
  millerLoop(P: PointG2): Fq12 {
    return millerLoop(P.pairingPrecomputes(), this.toAffine());
  }
}

type EllCoefficients = [Fq2, Fq2, Fq2];

export class PointG2 extends ProjectivePoint<Fq2> {
  static BASE = new PointG2(new Fq2(CURVE.G2x), new Fq2(CURVE.G2y), Fq2.ONE);
  static ZERO = new PointG2(Fq2.ONE, Fq2.ONE, Fq2.ZERO);

  private _PPRECOMPUTES: EllCoefficients[] | undefined;

  constructor(x: Fq2, y: Fq2, z: Fq2) {
    super(x, y, z, Fq2);
  }

  // clearCofactorG2 from spec
  _clearCofactorG2(): PointG2 {
    const P = this;
    // BLS_X is negative number
    const t1 = P.multiplyUnsafe(CURVE.x).negate();
    const t2 = P.fromAffineTuple(psi(...P.toAffine()));
    // psi2(2 * P) - T2 + ((T1 + T2) * (-X)) - T1 - P
    const p2 = P.fromAffineTuple(psi2(...P.double().toAffine()));
    return p2.subtract(t2).add(t1.add(t2).multiplyUnsafe(CURVE.x).negate()).subtract(t1).subtract(P);
  }

  // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-3
  static async hashToCurve(msg: Bytes) {
    expectHex(msg);
    if (typeof msg === 'string') msg = hexToBytes(msg);
    const u = await hash_to_field(msg, 2);
    //console.log(`hash_to_curve(msg}) u0=${new Fq2(u[0])} u1=${new Fq2(u[1])}`);
    const Q0 = new PointG2(...isogenyMapG2(map_to_curve_SSWU_G2(u[0])));
    const Q1 = new PointG2(...isogenyMapG2(map_to_curve_SSWU_G2(u[1])));
    const R = Q0.add(Q1);
    const P = R._clearCofactorG2();
    //console.log(`hash_to_curve(msg) Q0=${Q0}, Q1=${Q1}, R=${R} P=${P}`);
    return P;
  }

  // TODO: Optimize, it's very slow because of sqrt.
  static fromSignature(hex: Bytes): PointG2 {
    expectHex(hex);
    if (typeof hex === 'string') hex = hexToBytes(hex);
    const {P} = CURVE;
    const half = hex.length / 2;
    if (half !== 48 && half !== 96)
      throw new Error('Invalid compressed signature length, must be 96 or 192');
    const z1 = bytesToNumberBE(hex.slice(0, half));
    const z2 = bytesToNumberBE(hex.slice(half));
    // Indicates the infinity point
    const bflag1 = mod(z1, POW_2_383) / POW_2_382;
    if (bflag1 === 1n) return this.ZERO;

    const x1 = z1 % POW_2_381;
    const x2 = z2;
    const x = new Fq2([x2, x1]);
    // The slow part
    let y = x.pow(3n).add(new Fq2(CURVE.b2)).sqrt();
    if (!y) throw new Error('Failed to find a square root');

    // Choose the y whose leftmost bit of the imaginary part is equal to the a_flag1
    // If y1 happens to be zero, then use the bit of y0
    const [y0, y1] = y.values;
    const aflag1 = (z1 % POW_2_382) / POW_2_381;
    const isGreater = y1 > 0n && (y1 * 2n) / P !== aflag1;
    const isZero = y1 === 0n && (y0 * 2n) / P !== aflag1;
    if (isGreater || isZero) y = y.multiply(-1n);
    const point = new PointG2(x, y, Fq2.ONE);
    point.assertValidity();
    return point;
  }

  static fromHex(bytes: Bytes) {
    expectHex(bytes);
    if (typeof bytes === 'string') bytes = hexToBytes(bytes);

    let point;
    if (bytes.length === 96) {
      throw new Error('Compressed format not supported yet.');
    } else if (bytes.length === 192) {
      // Check if the infinity flag is set
      if ((bytes[0] & (1 << 6)) !== 0) {
        return PointG2.ZERO;
      }

      const x1 = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
      const x0 = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH, 2 * PUBLIC_KEY_LENGTH));
      const y1 = bytesToNumberBE(bytes.slice(2 * PUBLIC_KEY_LENGTH, 3 * PUBLIC_KEY_LENGTH));
      const y0 = bytesToNumberBE(bytes.slice(3 * PUBLIC_KEY_LENGTH));

      point = new PointG2(new Fq2([x0, x1]), new Fq2([y0, y1]), Fq2.ONE);
    } else {
      throw new Error('Invalid uncompressed point G2, expected 192 bytes');
    }

    point.assertValidity();
    return point;
  }

  static fromPrivateKey(privateKey: PrivateKey) {
    return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
  }

  toSignature() {
    if (this.equals(PointG2.ZERO)) {
      const sum = POW_2_383 + POW_2_382;
      return toPaddedHex(sum, PUBLIC_KEY_LENGTH) + toPaddedHex(0n, PUBLIC_KEY_LENGTH);
    }
    this.assertValidity();
    const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
    const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
    const aflag1 = tmp / CURVE.P;
    const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
    const z2 = x0;
    return toPaddedHex(z1, PUBLIC_KEY_LENGTH) + toPaddedHex(z2, PUBLIC_KEY_LENGTH);
  }

  toRawBytes(isCompressed = false) {
    return hexToBytes(this.toHex(isCompressed));
  }

  toHex(isCompressed = false) {
    if (isCompressed) {
      throw new Error('Not supported');
    } else {
      if (this.equals(PointG2.ZERO)) {
        return '4'.padEnd(2 * 4 * PUBLIC_KEY_LENGTH, '0'); // bytes[0] |= 1 << 6;
      } else {
        this.assertValidity();
        const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
        return (
          toPaddedHex(x1, PUBLIC_KEY_LENGTH) +
          toPaddedHex(x0, PUBLIC_KEY_LENGTH) +
          toPaddedHex(y1, PUBLIC_KEY_LENGTH) +
          toPaddedHex(y0, PUBLIC_KEY_LENGTH)
        );
      }
    }
  }

  assertValidity() {
    const b = new Fq2(CURVE.b2);
    if (this.isZero()) return;
    const { x, y, z } = this;
    const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
    const right = b.multiply(z.pow(3n) as Fq2);
    if (!left.subtract(right).equals(Fq2.ZERO)) throw new Error('Invalid point: not on curve Fq2');
  }

  toRepr() {
    return [this.x, this.y, this.z].map((v) => v.values);
  }

  clearPairingPrecomputes() {
    this._PPRECOMPUTES = undefined;
  }

  pairingPrecomputes(): EllCoefficients[] {
    if (this._PPRECOMPUTES) return this._PPRECOMPUTES;
    this._PPRECOMPUTES = calcPairingPrecomputes(...this.toAffine());
    return this._PPRECOMPUTES;
  }
}

export function pairing(P: PointG1, Q: PointG2, withFinalExponent: boolean = true): Fq12 {
  if (P.isZero() || Q.isZero()) throw new Error('No pairings at point of Infinity');
  P.assertValidity();
  Q.assertValidity();
  // Performance: 9ms for millerLoop and ~14ms for exp.
  const looped = P.millerLoop(Q);
  return withFinalExponent ? looped.finalExponentiate() : looped;
}

type PB1 = Bytes | PointG1;
type PB2 = Bytes | PointG2;
function normP1(point: PB1): PointG1 {
  if (point instanceof PointG1) return point;
  expectHex(point);
  return PointG1.fromHex(point);
}
function normP2(point: PB2): PointG2 {
  if (point instanceof PointG2) return point;
  expectHex(point);
  return PointG2.fromSignature(point);
}
async function normP2H(point: PB2): Promise<PointG2> {
  if (point instanceof PointG2) return point;
  expectHex(point);
  return await PointG2.hashToCurve(point);
}

// Multiplies generator by private key.
// P = pk x G
export function getPublicKey(privateKey: PrivateKey): Uint8Array | string {
  const bytes = PointG1.fromPrivateKey(privateKey).toRawBytes(true);
  return typeof privateKey === 'string' ? bytesToHex(bytes) : bytes;
}

// Sign executes `hashToCurve` on the message and then multiplies the result by private key.
// S = pk x H(m)
export async function sign(message: Uint8Array, privateKey: PrivateKey): Promise<Uint8Array>;
export async function sign(message: string, privateKey: PrivateKey): Promise<string>;
export async function sign(message: PointG2, privateKey: PrivateKey): Promise<PointG2>;
export async function sign(message: PB2, privateKey: PrivateKey): Promise<Bytes | PointG2> {
  const msgPoint = await normP2H(message);
  msgPoint.assertValidity();
  const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
  if (message instanceof PointG2) return sigPoint;
  const bytes = sigPoint.toSignature();
  return typeof message === 'string' ? bytes : hexToBytes(bytes);
}

// Verify checks if pairing of public key & hash is equal to pairing of generator & signature.
// e(P, H(m)) == e(G, S)
export async function verify(signature: PB2, message: PB2, publicKey: PB1): Promise<boolean> {
  const P = normP1(publicKey);
  const Hm = await normP2H(message);
  const G = PointG1.BASE;
  const S = normP2(signature);
  // Instead of doing 2 exponentiations, we use property of billinear maps
  // and do one exp after multiplying 2 points.
  const ePHm = pairing(P.negate(), Hm, false);
  const eGS = pairing(G, S, false);
  const exp = eGS.multiply(ePHm).finalExponentiate();
  return exp.equals(Fq12.ONE);
}

// Adds a bunch of public key points together.
// pk1 + pk2 + pk3 = pkA
export function aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array;
export function aggregatePublicKeys(publicKeys: string[]): string;
export function aggregatePublicKeys(publicKeys: PointG1[]): PointG1;
export function aggregatePublicKeys(publicKeys: PB1[]): Uint8Array | string | PointG1 {
  if (!publicKeys.length) throw new Error('Expected non-empty array');
  const agg = publicKeys.map(normP1).reduce((sum, p) => sum.add(p), PointG1.ZERO);
  if (publicKeys[0] instanceof PointG1) return agg;
  const bytes = agg.toRawBytes(true);
  if (publicKeys[0] instanceof Uint8Array) return bytes;
  return bytesToHex(bytes);
}

// Adds a bunch of signature points together.
export function aggregateSignatures(signatures: Uint8Array[]): Uint8Array;
export function aggregateSignatures(signatures: string[]): string;
export function aggregateSignatures(signatures: PointG2[]): PointG2;
export function aggregateSignatures(signatures: PB2[]): Uint8Array | string | PointG2 {
  if (!signatures.length) throw new Error('Expected non-empty array');
  const agg = signatures.map(normP2).reduce((sum, s) => sum.add(s), PointG2.ZERO);
  if (signatures[0] instanceof PointG2) return agg;
  const bytes = agg.toSignature();
  if (signatures[0] instanceof Uint8Array) return bytes;
  return bytes;
}

// ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
// e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
export async function verifyBatch(
  signature: PB2,
  messages: PB2[],
  publicKeys: PB1[]
): Promise<boolean> {
  if (!messages.length) throw new Error('Expected non-empty messages array');
  if (publicKeys.length !== messages.length) throw new Error('Pubkey count should equal msg count');
  const sig = normP2(signature);
  const nMessages = await Promise.all(messages.map(normP2H));
  const nPublicKeys = publicKeys.map(normP1);
  try {
    const paired = [];
    for (const message of new Set(nMessages)) {
      const groupPublicKey = nMessages.reduce(
        (groupPublicKey, subMessage, i) =>
          subMessage === message ? groupPublicKey.add(nPublicKeys[i]) : groupPublicKey,
        PointG1.ZERO
      );
      // const msg = message instanceof PointG2 ? message : await PointG2.hashToCurve(message);
      // Possible to batch pairing for same msg with different groupPublicKey here
      paired.push(pairing(groupPublicKey, message, false));
    }
    paired.push(pairing(PointG1.BASE.negate(), sig, false));
    const product = paired.reduce((a, b) => a.multiply(b), Fq12.ONE);
    const exp = product.finalExponentiate();
    return exp.equals(Fq12.ONE);
  } catch {
    return false;
  }
}

// Pre-compute points. Refer to README.
PointG1.BASE.calcMultiplyPrecomputes(4);
