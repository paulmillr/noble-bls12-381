// bls12-381 is a construction of two curves.
// 1. Fq: (x, y) - can be used for private keys
// 2. Fq2: (x1, x2+i), (y1, y2+i) - (imaginary numbers) can be used for signatures
// We can also get Fq12 by combining Fq & Fq2 using Ate pairing.
'use strict';

// prettier-ignore
import {
  Fq, Fq2, Fq6, Fq12, ProjectivePoint, CURVE, BLS_X_LEN, bitGet, mod, powMod, isogenyCoefficients
} from './math';

const P = CURVE.P;
//export let DST_LABEL = 'BLS12381G2_XMD:SHA-256_SSWU_RO_';
export let DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';

type Bytes = Uint8Array | string;
type Hash = Bytes;
type PrivateKey = Bytes | bigint | number;
type PublicKey = Bytes;
type Signature = Bytes;
type BigintTuple = [bigint, bigint];

// prettier-ignore
export type BigintTwelve = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint
];

export { Fq, Fq2, Fq12, CURVE };

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
};

function fromHexBE(hex: string) {
  return BigInt(`0x${hex}`);
}

function fromBytesBE(bytes: Bytes) {
  if (typeof bytes === 'string') {
    return fromHexBE(bytes);
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
  return concatTypedArrays(new Uint8Array(elements), bytes);
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
  if (typeof num === 'string') {
    return fromHexBE(num);
  }
  if (typeof num === 'number') {
    return BigInt(num);
  }
  if (num instanceof Uint8Array) {
    return fromBytesBE(num);
  }
  return num;
}

function hexToArray(hex: string) {
  if (!hex.length) return new Uint8Array([]);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return result;
}

function concatTypedArrays(...bytes: Bytes[]) {
  return new Uint8Array(
    bytes.reduce((res: number[], bytesView: Bytes) => {
      bytesView = bytesView instanceof Uint8Array ? bytesView : hexToArray(bytesView);
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

// hash-to-curve start

function os2ip(bytes: Uint8Array) {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

function i2osp(value: number, length: number) {
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

// 3-isogeny map from E' to E
// Converts from Jacobi (xyz) to Projective (xyz) coordinates.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#appendix-C.3
function isogenyMapG2(xyz: [Fq2, Fq2, Fq2]) {
  const [x, y, z] = xyz;
  // x-numerator, x-denominator, y-numerator, y-denominator
  const mapped = [Fq2.ZERO, Fq2.ZERO, Fq2.ZERO, Fq2.ZERO];
  const zPowers = [z, z.pow(2n), z.pow(3n)];

  // Horner Polynomial Evaluation
  for (let i = 0; i < isogenyCoefficients.length; i++) {
    const k_i = isogenyCoefficients[i];
    mapped[i] = k_i.slice(-1)[0];
    const arr = k_i.slice(0, -1).reverse();
    for (let j = 0; j < arr.length; j++) {
      const k_i_j = arr[j];
      mapped[i] = mapped[i].multiply(x).add(zPowers[j].multiply(k_i_j));
    }
  }

  mapped[2] = mapped[2].multiply(y); // y-numerator * y
  mapped[3] = mapped[3].multiply(z); // y-denominator * z

  const z2 = mapped[1].multiply(mapped[3]);
  const x2 = mapped[0].multiply(mapped[3]);
  const y2 = mapped[1].multiply(mapped[2]);
  return new PointG2(x2, y2, z2);
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
  const DST_prime = concatTypedArrays(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(len_in_bytes, 2);
  const b = new Array<Uint8Array>(ell);
  const b_0 = await H(concatTypedArrays(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = await H(concatTypedArrays(b_0, i2osp(1, 1), DST_prime));
  for (let i = 1; i <= ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
    b[i] = await H(concatTypedArrays(...args));
  }
  const pseudo_random_bytes = concatTypedArrays(...b);
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

function sgn0(x: Fq2) {
  const [x0, x1] = x.value;
  const sign_0 = x0 % 2n;
  const zero_0 = x0 === 0n;
  const sign_1 = x1 % 2n;
  return BigInt(sign_0 || (zero_0 && sign_1));
}

const P_MINUS_9_DIV_16 = (P ** 2n - 9n) / 16n;
// Does not return a square root.
// Returns uv^7 * (uv^15)^((p^2 - 9) / 16) * root of unity
// if valid square root is found
function sqrt_div_fq2(u: Fq2, v: Fq2): [boolean, Fq2] {
  const uv7 = u.multiply(v.pow(7n));
  const uv15 = uv7.multiply(v.pow(8n));
  // gamma =  uv^7 * (uv^15)^((p^2 - 9) / 16)
  const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
  let success = false;
  let result = gamma;
  // Constant-time routine, so we do not early-return.
  const positiveRootsOfUnity = Fq2.ROOTS_OF_UNITY.slice(0, 4);
  for (const root of positiveRootsOfUnity) {
    // Valid if (root * gamma)^2 * v - u == 0
    const candidate = root.multiply(gamma);
    if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
      success = true;
      result = candidate;
    }
  }
  return [success, result];
}

// Optimized SWU Map - FQ2 to G2': y^2 = x^3 + 240i * x + 1012 + 1012i
// Found in Section 4 of https://eprint.iacr.org/2019/403
// Note: it's constant-time
function map_to_curve_SSWU_G2(t: bigint[] | Fq2): [Fq2, Fq2, Fq2] {
  const iso_3_a = new Fq2([0n, 240n]);
  const iso_3_b = new Fq2([1012n, 1012n]);
  const iso_3_z = new Fq2([-2n, -1n]);
  if (Array.isArray(t)) t = new Fq2(t as BigintTuple);

  const t2 = t.pow(2n);
  const iso_3_z_t2 = iso_3_z.multiply(t2);
  const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n)); // (Z * t^2 + Z^2 * t^4)
  let denominator = iso_3_a.multiply(ztzt).negate(); // -a(Z * t^2 + Z^2 * t^4)
  let numerator = iso_3_b.multiply(ztzt.add(Fq2.ONE)); // b(Z * t^2 + Z^2 * t^4 + 1)

  // Exceptional case
  if (denominator.isZero()) denominator = iso_3_z.multiply(iso_3_a);

  // v = D^3
  let v = denominator.pow(3n);
  // u = N^3 + a * N * D^2 + b * D^3
  let u = numerator
    .pow(3n)
    .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
    .add(iso_3_b.multiply(v));
  // Attempt y = sqrt(u / v)
  const [success, sqrtCandidateOrGamma] = sqrt_div_fq2(u, v);
  let y;
  if (success) y = sqrtCandidateOrGamma;
  // Handle case where (u / v) is not square
  // sqrt_candidate(x1) = sqrt_candidate(x0) * t^3
  const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));

  // u(x1) = Z^3 * t^6 * u(x0)
  u = iso_3_z_t2.pow(3n).multiply(u);
  let success2 = false;
  for (const eta of Fq2.ETAs) {
    // Valid solution if (eta * sqrt_candidate(x1))^2 * v - u == 0
    const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
    const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
    if (temp.isZero() && !success && !success2) {
      y = etaSqrtCandidate;
      success2 = true;
    }
  }

  if (!success && !success2) throw new Error('Hash to Curve - Optimized SWU failure');
  if (success2) numerator = numerator.multiply(iso_3_z_t2);
  y = y as Fq2;
  if (sgn0(t) !== sgn0(y)) y = y.negate();
  y = y.multiply(denominator);
  return [numerator, y, denominator];
}

function normalizePrivKey(privateKey: PrivateKey): Fq {
  return new Fq(toBigInt(privateKey));
}

export class PointG1 extends ProjectivePoint<Fq> {
  static BASE = new PointG1(new Fq(CURVE.Gx), new Fq(CURVE.Gy), Fq.ONE);
  static ZERO = new PointG1(Fq.ONE, Fq.ONE, Fq.ZERO);

  constructor(x: Fq, y: Fq, z: Fq) {
    super(x, y, z, Fq);
  }

  static fromCompressedHex(hex: PublicKey) {
    const compressedValue = fromBytesBE(hex);
    const bflag = mod(compressedValue, POW_2_383) / POW_2_382;
    if (bflag === 1n) {
      return this.ZERO;
    }
    const x = mod(compressedValue, POW_2_381);
    const fullY = mod(x ** 3n + new Fq(CURVE.b).value, P);
    let y = powMod(fullY, (P + 1n) / 4n, P);
    if (powMod(y, 2n, P) !== fullY) {
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
    const ell = P.pairingPrecomputes();
    let f12 = Fq12.ONE;
    let [x, y] = this.toAffine();
    let [Px, Py] = [x as Fq, y as Fq];

    for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
      f12 = f12.multiplyBy014(
        ell[j][0],
        ell[j][1].multiply(Px.value),
        ell[j][2].multiply(Py.value)
      );
      if (bitGet(CURVE.BLS_X, i)) {
        j += 1;
        f12 = f12.multiplyBy014(
          ell[j][0],
          ell[j][1].multiply(Px.value),
          ell[j][2].multiply(Py.value)
        );
      }
      if (i != 0) f12 = f12.square();
    }
    return f12.conjugate();
  }
}

const ut_root = new Fq6([Fq2.ZERO, Fq2.ONE, Fq2.ZERO]);
const wsq = new Fq12([ut_root, Fq6.ZERO]);
const wsq_inv = wsq.invert();
const wcu = new Fq12([Fq6.ZERO, ut_root]);
const wcu_inv = wcu.invert();

function psi(P: PointG2) {
  let [x, y] = P.toAffine();
  // Untwist Fq2->Fq12 && frobenius(1) && twist back
  let new_x = wsq_inv.multiplyByFq2(x).frobeniusMap(1).multiply(wsq).c[0].c[0];
  let new_y = wcu_inv.multiplyByFq2(y).frobeniusMap(1).multiply(wcu).c[0].c[0];
  return new PointG2(new_x, new_y, Fq2.ONE);
}

// 1 / F2(2)^((p - 1) / 3) in GF(p^2)
const PSI2_C1 = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
function psi2(P: PointG2) {
  let [x, y] = P.toAffine();
  return new PointG2(x.multiply(PSI2_C1), y.negate(), Fq2.ONE);
}

export function clearCofactorG2(P: PointG2) {
  // BLS_X is negative number
  let t1 = P.multiplyUnsafe(CURVE.BLS_X).negate();
  let t2 = psi(P);
  // psi2(2 * P) - T2 + ((T1 + T2) * (-X)) - T1 - P
  return psi2(P.double())
    .subtract(t2)
    .add(t1.add(t2).multiplyUnsafe(CURVE.BLS_X).negate())
    .subtract(t1)
    .subtract(P);
}

type EllCoefficients = [Fq2, Fq2, Fq2];

export class PointG2 extends ProjectivePoint<Fq2> {
  static BASE = new PointG2(new Fq2(CURVE.G2x), new Fq2(CURVE.G2y), Fq2.ONE);
  static ZERO = new PointG2(Fq2.ONE, Fq2.ONE, Fq2.ZERO);

  private pair_precomputes: EllCoefficients[] | undefined;

  constructor(x: Fq2, y: Fq2, z: Fq2) {
    super(x, y, z, Fq2);
  }

  static async hashToCurve(msg: PublicKey) {
    if (typeof msg === 'string') msg = hexToArray(msg);
    const u = await hash_to_field(msg, 2);
    //console.log(`hash_to_curve(msg}) u0=${new Fq2(u[0])} u1=${new Fq2(u[1])}`);
    const Q0 = isogenyMapG2(map_to_curve_SSWU_G2(u[0]));
    const Q1 = isogenyMapG2(map_to_curve_SSWU_G2(u[1]));
    const R = Q0.add(Q1);
    const P = clearCofactorG2(R);
    //console.log(`hash_to_curve(msg) Q0=${Q0}, Q1=${Q1}, R=${R} P=${P}`);
    return P;
  }
  static fromSignature(hex: Signature): PointG2 {
    const half = hex.length / 2;
    const z1 = fromBytesBE(hex.slice(0, half));
    const z2 = fromBytesBE(hex.slice(half));

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
    const [y0, y1] = y.value;
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
      return concatTypedArrays(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
    }
    this.assertValidity();
    const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.value);
    const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
    const aflag1 = tmp / CURVE.P;
    const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
    const z2 = x0;
    return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
  }

  assertValidity() {
    const b = new Fq2(CURVE.b2);
    if (this.isZero()) return;
    const { x, y, z } = this;
    const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
    const right = b.multiply(z.pow(3n) as Fq2);
    if (!left.equals(right)) throw new Error('Invalid point: not on curve over Fq2');
  }

  // Pre-compute coefficients for sparse multiplication
  // Point addition and point double calculations is reused for coefficients
  calculatePrecomputes() {
    const [x, y] = this.toAffine();
    const [Qx, Qy, Qz] = [x as Fq2, y as Fq2, Fq2.ONE];
    let [Rx, Ry, Rz] = [Qx, Qy, Qz];
    let ell_coeff: EllCoefficients[] = [];
    for (let i = BLS_X_LEN - 2; i >= 0; i--) {
      // Double
      let t0 = Ry.square(); // Ry^2
      let t1 = Rz.square(); // Rz^2
      let t2 = t1.multiply(3n).multiplyByB(); // 3 * T1 * B
      let t3 = t2.multiply(3n); // 3 * T2
      let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0); // (Ry + Rz)^2 - T1 - T0
      ell_coeff.push([
        t2.subtract(t0), // T2 - T0
        Rx.square().multiply(3n), // 3 * Rx^2
        t4.negate(), // -T4
      ]);
      Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n); // ((T0 - T3) * Rx * Ry) / 2
      Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n)); // ((T0 + T3) / 2)^2 - 3 * T2^2
      Rz = t0.multiply(t4); // T0 * T4
      if (bitGet(CURVE.BLS_X, i)) {
        // Addition
        let t0 = Ry.subtract(Qy.multiply(Rz)); // Ry - Qy * Rz
        let t1 = Rx.subtract(Qx.multiply(Rz)); // Rx - Qx * Rz
        ell_coeff.push([
          t0.multiply(Qx).subtract(t1.multiply(Qy)), // T0 * Qx - T1 * Qy
          t0.negate(), // -T0
          t1, // T1
        ]);
        let t2 = t1.square(); // T1^2
        let t3 = t2.multiply(t1); // T2 * T1
        let t4 = t2.multiply(Rx); // T2 * Rx
        let t5 = t3.subtract(t4.multiply(2n)).add(t0.square().multiply(Rz)); // T3 - 4 * T4 + T0^2 * Rz
        Rx = t1.multiply(t5); // T1 * T5
        Ry = t4.subtract(t5).multiply(t0).subtract(t3.multiply(Ry)); // (T4 - T5) * T0 - T3 * Ry
        Rz = Rz.multiply(t3); // Rz * T3
      }
    }
    return ell_coeff;
  }

  clearPairingPrecomputes() {
    this.pair_precomputes = undefined;
  }

  pairingPrecomputes(): EllCoefficients[] {
    if (this.pair_precomputes) return this.pair_precomputes;
    return (this.pair_precomputes = this.calculatePrecomputes()) as EllCoefficients[];
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
export async function sign(message: Hash, privateKey: PrivateKey): Promise<Uint8Array> {
  const msgPoint = await PointG2.hashToCurve(message);
  const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
  return sigPoint.toSignature();
}

// e(P, H(m)) == e(G,S)
export async function verify(
  signature: Signature,
  message: Hash,
  publicKey: PublicKey
): Promise<boolean> {
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

// function pairs(array: any[]) {
//   return array.reduce((acc, curr, index) => {
//     acc[index % 2].push(curr);
//     return acc;
//   }, [[], []]);
// }

export function aggregatePublicKeys(publicKeys: PublicKey[]) {
  if (!publicKeys.length) throw new Error('Expected non-empty array');
  return publicKeys.reduce(
    (sum, publicKey) => sum.add(PointG1.fromCompressedHex(publicKey)),
    PointG1.ZERO
  );
}

// e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
export function aggregateSignatures(signatures: Signature[]) {
  if (!signatures.length) throw new Error('Expected non-empty array');
  const aggregatedSignature = signatures.reduce(
    (sum, signature) => sum.add(PointG2.fromSignature(signature)),
    PointG2.ZERO
  );
  return aggregatedSignature.toSignature();
}

export async function verifyBatch(messages: Hash[], publicKeys: PublicKey[], signature: Signature) {
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
