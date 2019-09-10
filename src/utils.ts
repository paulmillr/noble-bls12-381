import { Fp } from "./fp";
import { Fp12 } from "./fp12";
import { Point } from "./point";
import { Group } from "./group";
import { Fp2, BigintTuple } from "./fp2";

export type Bytes = Uint8Array | string;
export type Hash = Bytes;

// https://eprint.iacr.org/2019/403.pdf
// 2.1 The BLS12-381 elliptic curve
// q =  z**4 − z**2 + 1
export const PRIME_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
// p = z + (z**4 − z**2 + 1) * (z − 1)**2 / 3
export const P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
export const DOMAIN_LENGTH = 8;
export const SHA256_DIGEST_SIZE = 32n;
const P_ORDER_X_9 = (P ** 2n - 9n) / 16n;
const P_ORDER_X_12 = P ** 12n - 1n;
export const P_ORDER_X_12_DIVIDED = P_ORDER_X_12 / PRIME_ORDER;
const G2_COFACTOR = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n;

Fp.ORDER = P;
Fp2.ORDER = P ** 2n - 1n;
Fp2.COFACTOR = G2_COFACTOR;

// Curve is y**2 = x**3 + 4
export const B = new Fp(4n);
// Twisted curve over Fp2
export const B2 = new Fp2(4n, 4n);
// Extension curve over Fp12; same b value as over Fp
export const B12 = new Fp12(4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);

export const Z1 = new Point(new Fp(1n), new Fp(1n), new Fp(0n), Fp);
export const Z2 = new Point(
  new Fp2(1n, 0n),
  new Fp2(1n, 0n),
  new Fp2(0n, 0n),
  Fp2
);

const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;

const kQix = new Fp(
  0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn
);
const kQiy = new Fp(
  0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n
);
const kCx = new Fp2(
  0n,
  0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn
);
const kCy = new Fp2(
  0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
  0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n
);

const IWSC = 0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556n;
const iwsc = new Fp2(IWSC, IWSC - 1n);

let hmac256: (a: Uint8Array, b: Uint8Array) => Promise<Uint8Array>;

if (typeof window == "object" && "crypto" in window) {
  hmac256 = async (key: Uint8Array, message: Uint8Array) => {
    const keyBuffer = await window.crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"]
    );
    const buffer = await window.crypto.subtle.sign("HMAC", keyBuffer, message);
    return new Uint8Array(buffer);
  };
} else if (typeof process === "object" && "node" in process.versions) {
  const { createHmac } = require("crypto");
  hmac256 = async (key: Uint8Array, message: Uint8Array) => {
    const hash = createHmac("sha256", key);
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have sha256 function");
}

function fromHexBE(hex: string) {
  return BigInt(`0x${hex}`);
}

function fromBytesBE(bytes: Bytes) {
  if (typeof bytes === "string") {
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
  return concatBytes(new Uint8Array(elements), bytes);
}

export function toBytesBE(num: bigint | number | string, padding: number = 0) {
  let hex = typeof num === "string" ? num : num.toString(16);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length && i < len * 2; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return padStart(u8, padding, 0);
}

export function toBigInt(num: string | Uint8Array | bigint | number) {
  if (typeof num === "string") {
    return fromHexBE(num);
  }
  if (typeof num === "number") {
    return BigInt(num);
  }
  if (num instanceof Uint8Array) {
    return fromBytesBE(num);
  }
  return num;
}

function hexToBytes(hex: string) {
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
      bytesView =
        bytesView instanceof Uint8Array ? bytesView : hexToBytes(bytesView);
      return [...res, ...bytesView];
    }, [])
  );
}

function powMod(x: bigint, power: bigint, order: bigint) {
  let fx = new Fp(x);
  let res = new Fp(1n);
  while (power > 0) {
    if (power & 1n) {
      res = res.multiply(fx);
    }
    power >>= 1n;
    fx = fx.square();
  }
  return res.value;
}

const POW_SUM = POW_2_383 + POW_2_382;

function compressG1(point: Point<bigint>) {
  if (point.isEmpty()) {
    return POW_SUM;
  }
  const [x, y] = point.to2D() as [Fp, Fp];
  const flag = (y.value * 2n) / P;
  return x.value + flag * POW_2_381 + POW_2_383;
}

const PART_OF_P = (P + 1n) / 4n;

function uncompressG1(compressedValue: bigint) {
  const bflag = (compressedValue % POW_2_383) / POW_2_382;
  if (bflag === 1n) {
    return Z1;
  }
  const x = compressedValue % POW_2_381;
  const fullY = (x ** 3n + B.value) % P;
  let y = powMod(fullY, PART_OF_P, P);
  // if (powMod(y, 2n, P) !== fullY) {
  //   throw new Error("The given point is not on G1: y**2 = x**3 + b");
  // }
  const aflag = (compressedValue % POW_2_382) / POW_2_381;
  if ((y * 2n) / P !== aflag) {
    y = P - y;
  }
  return new Point(new Fp(x), new Fp(y), new Fp(1n), Fp);
}

function compressG2(point: Point<[bigint, bigint]>) {
  if (!point.isOnCurve(B2)) {
    throw new Error("The given point is not on the twisted curve over Fp2");
  }
  if (point.isEmpty()) {
    return [POW_2_383 + POW_2_382, 0n];
  }
  const [[x0, x1], [y0, y1]] = point.to2D().map(a => a.value);
  const producer = y1 > 0 ? y1 : y0;
  const aflag1 = (producer * 2n) / P;
  const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
  const z2 = x0;
  return [z1, z2];
}

function uncompressG2([z1, z2]: [bigint, bigint]) {
  const bflag1 = (z1 % POW_2_383) / POW_2_382;
  if (bflag1 === 1n) {
    return Z2;
  }
  const x = new Fp2(z2, z1 % POW_2_381);
  let y = x
    .pow(3n)
    .add(B2)
    .modularSquereRoot();
  if (y === null) {
    throw new Error("Failed to find a modular squareroot");
  }
  const [y0, y1] = y.value;
  const aflag1 = (z1 % POW_2_382) / POW_2_381;
  const isGreaterCoefficient = y1 > 0 && (y1 * 2n) / P !== aflag1;
  const isZeroCoefficient = y1 === 0n && (y0 * 2n) / P !== aflag1;
  if (isGreaterCoefficient || isZeroCoefficient) {
    y = y.multiply(-1n);
  }
  const point = new Point(x, y, y.one, Fp2);
  if (!point.isOnCurve(B2)) {
    throw new Error("The given point is not on the twisted curve over Fp2");
  }
  return point;
}

export function publicKeyFromG1(point: Point<bigint>) {
  const z = compressG1(point);
  return toBytesBE(z, PUBLIC_KEY_LENGTH);
}

export function publicKeyToG1(publicKey: Bytes) {
  const z = fromBytesBE(publicKey);
  return uncompressG1(z);
}

export function signatureFromG2(point: Point<[bigint, bigint]>) {
  const [z1, z2] = compressG2(point);
  return concatBytes(
    toBytesBE(z1, PUBLIC_KEY_LENGTH),
    toBytesBE(z2, PUBLIC_KEY_LENGTH)
  );
}

export function signatureToG2(signature: Bytes) {
  const halfSignature = signature.length / 2;
  const z1 = fromBytesBE(signature.slice(0, halfSignature));
  const z2 = fromBytesBE(signature.slice(halfSignature));
  return uncompressG2([z1, z2]);
}

function bytesToHex(bytes: number[]) {
  let res = "";
  for (let i = 0; i < bytes.length; i++) {
    res = `${res}${bytes[i].toString(16).padStart(2, "0")}`;
  }
  return res;
}

function stringToBytes(str: string) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

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

async function hkdfExpand(messagePrime: Uint8Array, info: Hash, length: number) {
  const wordsPerElement =
    (BigInt(length) + SHA256_DIGEST_SIZE - 1n) / SHA256_DIGEST_SIZE;
  let last = new Uint8Array(0);
  let result = new Uint8Array(0);
  for (let i = 0; i < wordsPerElement; i++) {
    last = await hmac256(
      messagePrime,
      concatBytes(last, info, i2osp(i + 1, 1))
    );
    result = concatBytes(result, last);
  }
  return result.slice(0, length);
}

async function hashToBase(
  message: Uint8Array,
  current: number,
  domain: Uint8Array,
  length: number,
  blen: number
) {
  const messagePrime = await hmac256(domain, message);
  const result: Fp[] = new Array(length);
  const info = concatBytes(stringToBytes("H2C"), i2osp(current, 1));
  for (let i = 0; i < length; i++) {
    const tmp = await hkdfExpand(
      messagePrime,
      concatBytes(info, i2osp(i + 1, 1)),
      blen
    );
    result[i] = new Fp(os2ip(tmp));
  }
  return result;
}

function hashToP2(message: Hash, current: number, domain: Bytes) {
  message = typeof message === "string" ? hexToBytes(message) : message;
  domain = typeof domain === "string" ? hexToBytes(domain) : domain;
  return hashToBase(message, current, domain, 2, 64);
}

function getSign(xi: bigint, thresh: bigint, sign: bigint) {
  if (xi > thresh) {
    return sign || -1n;
  }
  if (xi > 0n) {
    return sign || 1n;
  }
  return sign;
}

function sign0(x: Fp2) {
  const thresh = (P - 1n) / 2n;
  const [x1, x2] = x.value;
  let sign = 0n;
  sign = getSign(x2, thresh, sign);
  sign = getSign(x1, thresh, sign);
  return sign || 1n;
}

const Ell2pA = new Fp2(0n, 240n);
const Ell2pB = new Fp2(1012n, 1012n);
const ONE = new Fp2(1n, 1n);
// roots of unity, used for computing square roots in Fp2
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const rootsOfUnity = [
  new Fp2(1n, 0n),
  new Fp2(0n, 1n),
  new Fp2(rv1, rv1),
  new Fp2(rv1, P - rv1)
];
const ev1 = 0x2c4a7244a026bd3e305cc456ad9e235ed85f8b53954258ec8186bb3d4eccef7c4ee7b8d4b9e063a6c88d0aa3e03ba01n;
const ev2 = 0x85fa8cd9105715e641892a0f9a4bb2912b58b8d32f26594c60679cc7973076dc6638358daf3514d6426a813ae01f51an;
const etas = [
  new Fp2(ev1, 0n),
  new Fp2(0n, ev1),
  new Fp2(ev2, ev2),
  new Fp2(ev2, P - ev2)
];

function osswu2help(t: Fp2) {
  // first, compute X0(t), detecting and handling exceptional case
  const denominator = ONE.square()
    .multiply(t.pow(4n))
    .add(ONE.multiply(t.square()));
  const x0Numerator = Ell2pB.multiply(denominator.add(denominator.one));
  const tmp = Ell2pA.negative().multiply(denominator);
  const x0Denominator = tmp.equals(tmp.zero) ? Ell2pA.multiply(ONE) : tmp;

  // compute num and den of g(X0(t))
  const gx0Denominator = x0Denominator.pow(3n);
  const gx0Numerator = Ell2pB.multiply(gx0Denominator)
    .add(Ell2pA.multiply(x0Numerator).multiply(x0Denominator.square()))
    .add(x0Numerator.pow(3n));

  // try taking sqrt of g(X0(t))
  // this uses the trick for combining division and sqrt from Section 5 of
  // Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures."
  // J Crypt Eng 2(2):77--89, Sept. 2012. http://ed25519.cr.yp.to/ed25519-20110926.pdf
  let tmp1 = gx0Denominator.pow(7n);
  let tmp2 = gx0Numerator.multiply(tmp1);
  tmp1 = tmp1.multiply(tmp2).multiply(gx0Denominator);
  let sqrtCandidate = tmp2.multiply(tmp1.pow(P_ORDER_X_9));

  // check if g(X0(t)) is square and return the sqrt if so
  for (const root of rootsOfUnity) {
    const y0 = sqrtCandidate.multiply(root);
    const candidate = y0.square().multiply(gx0Denominator);
    if (!candidate.equals(gx0Numerator)) {
      continue;
    }
    const y = y0.multiply(sign0(y0) * sign0(t));
    return new Point(
      x0Numerator.multiply(x0Denominator),
      y.multiply(x0Denominator.pow(3n)),
      x0Denominator,
      Fp2
    );
  }

  // if we've gotten here, then g(X0(t)) is not square. convert srqt_candidate to sqrt(g(X1(t)))
  const x1Numerator = ONE.multiply(t.square()).multiply(x0Numerator);
  const x1Denomirator = x0Denominator;
  const gx1Numerator = ONE.pow(3n)
    .multiply(t.pow(6n))
    .multiply(gx0Numerator);
  const gx1Denominator = gx0Denominator;
  sqrtCandidate = sqrtCandidate.multiply(t.pow(3n));

  for (const eta of etas) {
    const y1 = sqrtCandidate.multiply(eta);
    const candidate = y1.square().multiply(gx1Denominator);
    if (!candidate.equals(gx1Numerator)) {
      continue;
    }
    // found sqrt(g(X1(t))). force sign of y to equal sign of t
    const y = y1.multiply(sign0(y1) * sign0(t));
    return new Point(
      x1Numerator.multiply(x1Denomirator),
      y.multiply(x1Denomirator.pow(3n)),
      x1Denomirator,
      Fp2
    );
  }

  throw new Error("osswu2help failed for unknown reasons!");
}

// 3-Isogeny from Ell2' to Ell2
// coefficients for the 3-isogeny map from Ell2' to Ell2

const xnum: [
  Group<BigintTuple>,
  Group<BigintTuple>,
  Group<BigintTuple>,
  Group<BigintTuple>
] = [
  new Fp2(
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n
  ),
  new Fp2(
    0x0n,
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an
  ),
  new Fp2(
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn
  ),
  new Fp2(
    0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
    0x0n
  )
];

const xden = [
  new Fp2(
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n
  ),
  new Fp2(
    0xcn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn
  ),
  new Fp2(0x1n, 0x0n)
];
const ynum = [
  new Fp2(
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n
  ),
  new Fp2(
    0x0n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben
  ),
  new Fp2(
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn
  ),
  new Fp2(
    0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
    0x0n
  )
];
const yden = [
  new Fp2(
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn
  ),
  new Fp2(
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n
  ),
  new Fp2(
    0x12n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n
  ),
  new Fp2(0x1n, 0x0n)
];

// compute 3-isogeny map from Ell2' to Ell2
function computeIsogeny3(p: Point<BigintTuple>) {
  return p.evalIsogeny([xnum, xden, ynum, yden]);
}

// Addition chain for multiplication by 0xd201000000010000 == -x, the BLS parameter
function mxChain(point: Point<BigintTuple>) {
  let Q = point.double();
  for (let n of [2, 3, 9, 32, 16]) {
    Q = Q.add(point);
    while (n--) {
      Q = Q.double();
    }
  }
  return Q;
}

function qiX(x: Fp2) {
  const [x1, x2] = x.value;
  return new Fp2(
    kQix.multiply(x1),
    kQix
      .multiply(x2)
      .negative()
      .add(P)
  );
}

function qiY(y: Fp2) {
  const [y1, y2] = y.value;
  return new Fp2(kQiy.multiply(y1 + y2), kQiy.multiply(y1 - y2));
}

function psi(point: Point<BigintTuple>) {
  const z2 = point.z.pow(2n) as Fp2;
  const xNumerator = kCx.multiply(qiX(iwsc.multiply(point.x as Fp2)));
  const xDenominator = qiX(iwsc.multiply(z2));
  const yNumerator = kCy.multiply(qiY(iwsc.multiply(point.y as Fp2)));
  const yDenominator = qiY(iwsc.multiply(z2.multiply(point.z as Fp2)));
  const z = xDenominator.multiply(yDenominator);
  const x = xNumerator.multiply(yDenominator).multiply(z);
  const y = yNumerator
    .multiply(xDenominator)
    .multiply(z)
    .multiply(z);
  return new Point(x, y, z, Fp2);
}

function clearh2(point: Point<BigintTuple>) {
  const minusPsi = psi(point).negative();
  let work = mxChain(point)
    .add(point)
    .add(minusPsi); // (-x + 1) P - psi(P)
  work = mxChain(work)
    .add(minusPsi)
    .add(point.negative()); // (x^2 - x - 1) P + (x - 1) psi(P)
  const doublePsi = psi(psi(point.double())); // psi(psi(2P))
  work = work.add(doublePsi); // (x^2 - x - 1) P + (x - 1) psi(P) + psi(psi(2P))
  return work;
}

// map from Fp2 element(s) to point in G2 subgroup of Ell2
function optswu2map(t1: Fp2, t2?: Fp2) {
  let tmp = osswu2help(t1);
  if (t2 instanceof Fp2) {
    const point2 = osswu2help(t2);
    tmp = tmp.add(point2);
  }
  const point = computeIsogeny3(tmp);
  return clearh2(point);
}

export async function hashToG2(hash: Hash, domain: Bytes) {
  const [tuple1, tuple2] = await Promise.all([
    hashToP2(hash, 0, domain),
    hashToP2(hash, 1, domain)
  ]);
  const t1 = new Fp2(...tuple1);
  const t2 = new Fp2(...tuple2);
  return optswu2map(t1, t2);
}
