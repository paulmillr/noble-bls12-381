// bls12-381 is a construction of two curves.
// 1. Fq: (x, y) - can be used for private keys
// 2. Fq2: (x1, x2+i), (y1, y2+i) - (imaginary numbers) can be used for signatures
// We can also get Fq12 by combining Fq & Fq2 using Ate pairing.
// prettier-ignore
import {
  Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve, ProjectivePoint,
  map_to_curve_SSWU_G2, isogenyMapG2,
  millerLoop, psi, psi2, calcPairingPrecomputes,
  mod, powMod
} from './math';

const P = CURVE.P;
export let DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';

type Bytes = Uint8Array | string;
type PrivateKey = Bytes | bigint | number;
export { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve };

const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;

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
  mod,
};

function hexToNumberBE(hex: string) {
  return BigInt(`0x${hex}`);
}

function bytesToNumberBE(bytes: Bytes) {
  if (typeof bytes === 'string') {
    return hexToNumberBE(bytes);
  }
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

function padStart(bytes: Uint8Array, count: number, element: number) {
  if (bytes.length >= count) {
    return bytes;
  }
  const diff = count - bytes.length;
  const elements = Array(diff)
    .fill(element)
    .map((i: number) => i);
  return concatBytes(new Uint8Array(elements), bytes);
}

function toBytesBE(num: bigint | number | string, padding: number = 0) {
  let hex = typeof num === 'string' ? num : num.toString(16);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length && i < len * 2; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return padStart(u8, padding, 0);
}

function toBigInt(num: string | Uint8Array | bigint | number) {
  if (typeof num === 'string') return hexToNumberBE(num);
  if (typeof num === 'number') return BigInt(num);
  if (num instanceof Uint8Array) return bytesToNumberBE(num);
  return num;
}

function hexToBytes(hex: string) {
  if (!hex.length) return new Uint8Array([]);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return result;
}

function concatBytes(...bytes: Bytes[]) {
  return new Uint8Array(
    bytes.reduce((res: number[], bytesView: Bytes) => {
      bytesView = bytesView instanceof Uint8Array ? bytesView : hexToBytes(bytesView);
      return [...res, ...bytesView];
    }, [])
  );
}

function stringToBytes(str: string) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

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
  const b_in_bytes = Number(SHA256_DIGEST_SIZE);
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

function normalizePrivKey(privateKey: PrivateKey): Fq {
  const fq = new Fq(toBigInt(privateKey));
  if (fq.isZero()) throw new Error('Private key cannot be 0');
  return fq;
}

export class PointG1 extends ProjectivePoint<Fq> {
  static BASE = new PointG1(new Fq(CURVE.Gx), new Fq(CURVE.Gy), Fq.ONE);
  static ZERO = new PointG1(Fq.ONE, Fq.ONE, Fq.ZERO);

  constructor(x: Fq, y: Fq, z: Fq) {
    super(x, y, z, Fq);
  }

  static fromCompressedHex(hex: Bytes) {
    const compressedValue = bytesToNumberBE(hex);
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
    const p = new PointG1(new Fq(x), new Fq(y), new Fq(1n));
    return p;
  }

  static fromPrivateKey(privateKey: PrivateKey) {
    return this.BASE.multiply(normalizePrivKey(privateKey));
  }

  toCompressedHex() {
    let hex;
    if (this.equals(PointG1.ZERO)) {
      hex = POW_2_383 + POW_2_382;
    } else {
      const [x, y] = this.toAffine();
      const flag = (y.value * 2n) / P;
      hex = x.value + flag * POW_2_381 + POW_2_383;
    }
    return toBytesBE(hex, PUBLIC_KEY_LENGTH);
  }

  assertValidity() {
    const b = new Fq(CURVE.b);
    if (this.isZero()) return;
    const { x, y, z } = this;
    const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
    const right = b.multiply(z.pow(3n) as Fq);
    if (!left.equals(right)) throw new Error('Invalid point: not on curve over Fq');
  }
  // Sparse multiplication against precomputed coefficients
  millerLoop(P: PointG2): Fq12 {
    return millerLoop(P.pairingPrecomputes(), this.toAffine());
  }
}

export function clearCofactorG2(P: PointG2) {
  // BLS_X is negative number
  const t1 = P.multiplyUnsafe(CURVE.x).negate();
  const t2 = P.fromAffineTuple(psi(...P.toAffine()));
  // psi2(2 * P) - T2 + ((T1 + T2) * (-X)) - T1 - P
  const p2 = P.fromAffineTuple(psi2(...P.double().toAffine()));
  return p2.subtract(t2).add(t1.add(t2).multiplyUnsafe(CURVE.x).negate()).subtract(t1).subtract(P);
}

type EllCoefficients = [Fq2, Fq2, Fq2];

export class PointG2 extends ProjectivePoint<Fq2> {
  static BASE = new PointG2(new Fq2(CURVE.G2x), new Fq2(CURVE.G2y), Fq2.ONE);
  static ZERO = new PointG2(Fq2.ONE, Fq2.ONE, Fq2.ZERO);

  private _PPRECOMPUTES: EllCoefficients[] | undefined;

  constructor(x: Fq2, y: Fq2, z: Fq2) {
    super(x, y, z, Fq2);
  }

  // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-3
  static async hashToCurve(msg: Bytes) {
    if (typeof msg === 'string') msg = hexToBytes(msg);
    const u = await hash_to_field(msg, 2);
    //console.log(`hash_to_curve(msg}) u0=${new Fq2(u[0])} u1=${new Fq2(u[1])}`);
    const Q0 = new PointG2(...isogenyMapG2(map_to_curve_SSWU_G2(u[0])));
    const Q1 = new PointG2(...isogenyMapG2(map_to_curve_SSWU_G2(u[1])));
    const R = Q0.add(Q1);
    const P = clearCofactorG2(R);
    //console.log(`hash_to_curve(msg) Q0=${Q0}, Q1=${Q1}, R=${R} P=${P}`);
    return P;
  }

  static fromSignature(hex: Bytes): PointG2 {
    const half = hex.length / 2;
    if (half != 96) throw new Error('Invalid compressed signature length, must be 96');
    const z1 = bytesToNumberBE(hex.slice(0, half));
    const z2 = bytesToNumberBE(hex.slice(half));
    // indicates the infinity point
    const bflag1 = mod(z1, POW_2_383) / POW_2_382;
    if (bflag1 === 1n) return this.ZERO;

    const x1 = z1 % POW_2_381;
    const x2 = z2;
    const x = new Fq2([x2, x1]);
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

  static fromPrivateKey(privateKey: PrivateKey) {
    return this.BASE.multiply(normalizePrivKey(privateKey));
  }

  toSignature() {
    if (this.equals(PointG2.ZERO)) {
      const sum = POW_2_383 + POW_2_382;
      return concatBytes(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
    }
    this.assertValidity();
    const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
    const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
    const aflag1 = tmp / CURVE.P;
    const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
    const z2 = x0;
    return concatBytes(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
  }

  assertValidity() {
    const b = new Fq2(CURVE.b2);
    if (this.isZero()) return;
    const { x, y, z } = this;
    const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
    const right = b.multiply(z.pow(3n) as Fq2);
    if (!left.equals(right)) throw new Error('Invalid point: not on curve over Fq2');
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
  let res = P.millerLoop(Q);
  return withFinalExponent ? res.finalExponentiate() : res;
}

// P = pk x G
export function getPublicKey(privateKey: PrivateKey) {
  return PointG1.fromPrivateKey(privateKey).toCompressedHex();
}

// S = pk x H(m)
export async function sign(message: Bytes, privateKey: PrivateKey): Promise<Uint8Array> {
  const msgPoint = await PointG2.hashToCurve(message);
  const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
  return sigPoint.toSignature();
}

// e(P, H(m)) == e(G,S)
export async function verify(signature: Bytes, message: Bytes, publicKey: Bytes): Promise<boolean> {
  const P = PointG1.fromCompressedHex(publicKey).negate();
  const Hm = await PointG2.hashToCurve(message);
  const G = PointG1.BASE;
  const S = PointG2.fromSignature(signature);
  // Instead of doing 2 exponentiations, we use property of billinear maps
  // and do one exp after multiplying 2 points.
  const ePHm = pairing(P, Hm, false);
  const eGS = pairing(G, S, false);
  const exp = eGS.multiply(ePHm).finalExponentiate();
  return exp.equals(Fq12.ONE);
}

export function aggregatePublicKeys(publicKeys: Bytes[]): Uint8Array {
  if (!publicKeys.length) throw new Error('Expected non-empty array');
  const agg = publicKeys
    .map((p) => PointG1.fromCompressedHex(p))
    .reduce((sum, p) => sum.add(p), PointG1.ZERO);
  return agg.toCompressedHex();
}

// e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
export function aggregateSignatures(signatures: Bytes[]): Uint8Array {
  if (!signatures.length) throw new Error('Expected non-empty array');
  const agg = signatures
    .map((s) => PointG2.fromSignature(s))
    .reduce((sum, s) => sum.add(s), PointG2.ZERO);
  return agg.toSignature();
}

export async function verifyBatch(messages: Bytes[], publicKeys: Bytes[], signature: Bytes) {
  if (!messages.length) throw new Error('Expected non-empty messages array');
  if (publicKeys.length !== messages.length) throw new Error('Pubkey count should equal msg count');
  try {
    let producer = Fq12.ONE;
    for (const message of new Set(messages)) {
      const groupPublicKey = messages.reduce(
        (groupPublicKey, m, i) =>
          m !== message
            ? groupPublicKey
            : groupPublicKey.add(PointG1.fromCompressedHex(publicKeys[i])),
        PointG1.ZERO
      );
      const msg = await PointG2.hashToCurve(message);
      // Possible to batch pairing for same msg with different groupPublicKey here
      producer = producer.multiply(pairing(groupPublicKey, msg, false) as Fq12);
    }
    const sig = PointG2.fromSignature(signature);
    producer = producer.multiply(pairing(PointG1.BASE.negate(), sig, false) as Fq12);
    const finalExponent = producer.finalExponentiate();
    return finalExponent.equals(Fq12.ONE);
  } catch {
    return false;
  }
}

PointG1.BASE.calcMultiplyPrecomputes(4);
