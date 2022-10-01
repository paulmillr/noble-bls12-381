// To verify curve parameters, see pairing-friendly-curves spec:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09
// Basic math is done over finite fields over p.
// More complicated math is done over polynominal extension fields.
// To simplify calculations in Fp12, we construct extension tower:
// Fp₁₂ = Fp₆² => Fp₂³
// Fp(u) / (u² - β) where β = -1
// Fp₂(v) / (v³ - ξ) where ξ = u + 1
// Fp₆(w) / (w² - γ) where γ = v
export const CURVE = {
  // G1 is the order-q subgroup of E1(Fp) : y² = x³ + 4, #E1(Fp) = h1q, where
  // characteristic; z + (z⁴ - z² + 1)(z - 1)²/3
  P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
  // order; z⁴ − z² + 1
  r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
  // cofactor; (z - 1)²/3
  h: 0x396c8c005555e1568c00aaab0000aaabn,
  // generator's coordinates
  // x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
  // y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
  Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
  Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
  b: 4n,

  // G2 is the order-q subgroup of E2(Fp²) : y² = x³+4(1+√−1),
  // where Fp2 is Fp[√−1]/(x2+1). #E2(Fp2 ) = h2q, where
  // G² - 1
  // h2q
  P2:
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn **
      2n -
    1n,
  // cofactor
  h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
  G2x: [
    0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
    0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
  ],
  // y =
  // 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582,
  // 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
  G2y: [
    0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
    0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
  ],
  b2: [4n, 4n],
  // The BLS parameter x for BLS12-381
  x: 0xd201000000010000n,
  h2Eff:
    0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n,
};

const BLS_X_LEN = bitLen(CURVE.x);

type BigintTuple = [bigint, bigint];
type FpTuple = [Fp, Fp];
type BigintSix = [bigint, bigint, bigint, bigint, bigint, bigint];
// prettier-ignore
type BigintTwelve = [
  bigint, bigint, bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint, bigint, bigint
];

// Finite field
interface Field<T> {
  isZero(): boolean;
  equals(rhs: T): boolean;
  negate(): T;
  add(rhs: T): T;
  subtract(rhs: T): T;
  invert(): T;
  multiply(rhs: T | bigint): T;
  square(): T;
  pow(n: bigint): T;
  div(rhs: T | bigint): T;
}

type FieldStatic<T extends Field<T>> = { ZERO: T; ONE: T };

export function mod(a: bigint, b: bigint) {
  const res = a % b;
  return res >= 0n ? res : b + res;
}

/**
 * Efficiently exponentiate num to power and do modular division.
 * @example
 * powMod(2n, 6n, 11n) // 64n % 11n == 9n
 */
export function powMod(num: bigint, power: bigint, modulo: bigint) {
  if (modulo <= 0n || power < 0n) throw new Error('Expected power/modulo > 0');
  if (modulo === 1n) return 0n;
  let res = 1n;
  while (power > 0n) {
    if (power & 1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= 1n;
  }
  return res;
}

function genInvertBatch<T extends Field<T>>(cls: FieldStatic<T>, nums: T[]): T[] {
  const tmp = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (num.isZero()) return acc;
    tmp[i] = acc;
    return acc.multiply(num);
  }, cls.ONE);
  // Invert last element
  const inverted = lastMultiplied.invert();
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (num.isZero()) return acc;
    tmp[i] = acc.multiply(tmp[i]);
    return acc.multiply(num);
  }, inverted);
  return tmp;
}

// Amount of bits inside bigint
function bitLen(n: bigint) {
  let len;
  for (len = 0; n > 0n; n >>= 1n, len += 1);
  return len;
}

// Get single bit from bigint at pos
function bitGet(n: bigint, pos: number) {
  return (n >> BigInt(pos)) & 1n;
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  const _0n = 0n;
  const _1n = 1n;
  if (number === _0n || modulo <= _0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    if (hexByte.length !== 2) throw new Error('Invalid byte sequence');
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

function numberToHex(num: number | bigint, byteLength: number): string {
  if (!byteLength) throw new Error('byteLength target must be specified');
  const hex = num.toString(16);
  const p1 = hex.length & 1 ? `0${hex}` : hex;
  return p1.padStart(byteLength * 2, '0');
}

export function numberToBytesBE(num: bigint, byteLength: number): Uint8Array {
  const res = hexToBytes(numberToHex(num, byteLength));
  if (res.length !== byteLength) throw new Error('numberToBytesBE: wrong byteLength');
  return res;
}

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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

// Finite field over p.
export class Fp implements Field<Fp> {
  static readonly ORDER = CURVE.P;
  static readonly MAX_BITS = bitLen(CURVE.P);
  static readonly BYTES_LEN = Math.ceil(this.MAX_BITS / 8);
  static readonly ZERO = new Fp(0n);
  static readonly ONE = new Fp(1n);
  readonly value: bigint;

  constructor(value: bigint) {
    this.value = mod(value, Fp.ORDER);
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  equals(rhs: Fp): boolean {
    return this.value === rhs.value;
  }

  negate(): Fp {
    return new Fp(-this.value);
  }

  invert(): Fp {
    return new Fp(invert(this.value, Fp.ORDER));
  }

  add(rhs: Fp): Fp {
    return new Fp(this.value + rhs.value);
  }

  square(): Fp {
    return new Fp(this.value * this.value);
  }

  pow(n: bigint): Fp {
    return new Fp(powMod(this.value, n, Fp.ORDER));
  }

  // square root computation for p ≡ 3 (mod 4)
  // a^((p-3)/4)) ≡ 1/√a (mod p)
  // √a ≡ a * 1/√a ≡ a^((p+1)/4) (mod p)
  // It's possible to unwrap the exponentiation, but (P+1)/4 has 228 1's out of 379 bits.
  // https://eprint.iacr.org/2012/685.pdf
  sqrt(): Fp | undefined {
    const root = this.pow((Fp.ORDER + 1n) / 4n);
    if (!root.square().equals(this)) return;
    return root;
  }

  subtract(rhs: Fp): Fp {
    return new Fp(this.value - rhs.value);
  }

  multiply(rhs: Fp | bigint): Fp {
    if (rhs instanceof Fp) rhs = rhs.value;
    return new Fp(this.value * rhs);
  }

  div(rhs: Fp | bigint): Fp {
    if (typeof rhs === 'bigint') rhs = new Fp(rhs);
    return this.multiply(rhs.invert());
  }

  toString() {
    const str = this.value.toString(16).padStart(96, '0');
    return str.slice(0, 2) + '.' + str.slice(-2);
  }
  static fromBytes(b: Uint8Array): Fp {
    if (b.length !== Fp.BYTES_LEN) throw new Error(`fromBytes wrong length=${b.length}`);
    return new Fp(bytesToNumberBE(b));
  }
  toBytes(): Uint8Array {
    return numberToBytesBE(this.value, Fp.BYTES_LEN);
  }
}

// Finite field over r.
// This particular field is not used anywhere in bls12-381, but it is still useful.
export class Fr implements Field<Fr> {
  static readonly ORDER = CURVE.r;
  static readonly ZERO = new Fr(0n);
  static readonly ONE = new Fr(1n);
  readonly value: bigint;

  constructor(value: bigint) {
    this.value = mod(value, Fr.ORDER);
  }

  static isValid(b: bigint) {
    return b <= Fr.ORDER;
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  equals(rhs: Fr): boolean {
    return this.value === rhs.value;
  }

  negate(): Fr {
    return new Fr(-this.value);
  }

  invert(): Fr {
    return new Fr(invert(this.value, Fr.ORDER));
  }

  add(rhs: Fr): Fr {
    return new Fr(this.value + rhs.value);
  }

  square(): Fr {
    return new Fr(this.value * this.value);
  }

  pow(n: bigint): Fr {
    return new Fr(powMod(this.value, n, Fr.ORDER));
  }

  subtract(rhs: Fr): Fr {
    return new Fr(this.value - rhs.value);
  }

  multiply(rhs: Fr | bigint): Fr {
    if (rhs instanceof Fr) rhs = rhs.value;
    return new Fr(this.value * rhs);
  }

  div(rhs: Fr | bigint): Fr {
    if (typeof rhs === 'bigint') rhs = new Fr(rhs);
    return this.multiply(rhs.invert());
  }
  legendre(): Fr {
    return this.pow((Fr.ORDER - 1n) / 2n);
  }
  // Tonelli-Shanks algorithm
  sqrt(): Fr | undefined {
    if (!this.legendre().equals(Fr.ONE)) return;
    const P = Fr.ORDER;
    let q, s, z;
    for (q = P - 1n, s = 0; q % 2n === 0n; q /= 2n, s++);
    if (s === 1) return this.pow((P + 1n) / 4n);
    for (z = 2n; z < P && new Fr(z).legendre().value !== P - 1n; z++);

    let c = powMod(z, q, P);
    let r = powMod(this.value, (q + 1n) / 2n, P);
    let t = powMod(this.value, q, P);

    let t2 = 0n;
    while (mod(t - 1n, P) !== 0n) {
      t2 = mod(t * t, P);
      let i;
      for (i = 1; i < s; i++) {
        if (mod(t2 - 1n, P) === 0n) break;
        t2 = mod(t2 * t2, P);
      }
      let b = powMod(c, BigInt(1 << (s - i - 1)), P);
      r = mod(r * b, P);
      c = mod(b * b, P);
      t = mod(t * c, P);
      s = i;
    }
    return new Fr(r);
  }

  toString() {
    return '0x' + this.value.toString(16).padStart(64, '0');
  }
}

function powMod_FQP(fqp: any, fqpOne: any, n: bigint) {
  const elm = fqp;
  if (n === 0n) return fqpOne;
  if (n === 1n) return elm;
  let p = fqpOne;
  let d = elm;
  while (n > 0n) {
    if (n & 1n) p = p.multiply(d);
    n >>= 1n;
    d = d.square();
  }
  return p;
}

// Fp₂ over complex plane
export class Fp2 implements Field<Fp2> {
  static readonly ORDER = CURVE.P2;
  static readonly MAX_BITS = bitLen(CURVE.P2);
  static readonly BYTES_LEN = Math.ceil(this.MAX_BITS / 8);
  static readonly ZERO = new Fp2(Fp.ZERO, Fp.ZERO);
  static readonly ONE = new Fp2(Fp.ONE, Fp.ZERO);

  constructor(readonly c0: Fp, readonly c1: Fp) {
    if (typeof c0 === 'bigint') throw new Error('c0: Expected Fp');
    if (typeof c1 === 'bigint') throw new Error('c1: Expected Fp');
  }
  static fromBigTuple(tuple: BigintTuple | bigint[]): Fp2 {
    const fps = tuple.map((n) => new Fp(n)) as [Fp, Fp];
    return new Fp2(...fps);
  }
  one() {
    return Fp2.ONE;
  }
  isZero(): boolean {
    return this.c0.isZero() && this.c1.isZero();
  }
  toString() {
    return `Fp2(${this.c0} + ${this.c1}×i)`;
  }
  // real, imaginary
  reim() {
    return { re: this.c0.value, im: this.c1.value };
  }
  negate(): Fp2 {
    const { c0, c1 } = this;
    return new Fp2(c0.negate(), c1.negate());
  }
  equals(rhs: Fp2): boolean {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return c0.equals(r0) && c1.equals(r1);
  }
  add(rhs: Fp2): Fp2 {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return new Fp2(c0.add(r0), c1.add(r1));
  }
  subtract(rhs: Fp2): Fp2 {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return new Fp2(c0.subtract(r0), c1.subtract(r1));
  }

  multiply(rhs: Fp2 | bigint): Fp2 {
    const { c0, c1 } = this;
    if (typeof rhs === 'bigint') {
      return new Fp2(c0.multiply(rhs), c1.multiply(rhs));
    }
    // (a+bi)(c+di) = (ac−bd) + (ad+bc)i
    const { c0: r0, c1: r1 } = rhs;
    let t1 = c0.multiply(r0); // c0 * o0
    let t2 = c1.multiply(r1); // c1 * o1
    // (T1 - T2) + ((c0 + c1) * (r0 + r1) - (T1 + T2))*i
    return new Fp2(t1.subtract(t2), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)));
  }
  pow(n: bigint): Fp2 {
    return powMod_FQP(this, Fp2.ONE, n);
  }
  div(rhs: Fp2 | bigint): Fp2 {
    const inv = typeof rhs === 'bigint' ? new Fp(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }
  // multiply by u + 1
  mulByNonresidue() {
    const c0 = this.c0;
    const c1 = this.c1;
    return new Fp2(c0.subtract(c1), c0.add(c1));
  }

  square() {
    const c0 = this.c0;
    const c1 = this.c1;
    const a = c0.add(c1);
    const b = c0.subtract(c1);
    const c = c0.add(c0);
    return new Fp2(a.multiply(b), c.multiply(c1));
  }

  sqrt(): Fp2 | undefined {
    // TODO: Optimize this line. It's extremely slow.
    // Speeding this up would boost aggregateSignatures.
    // https://eprint.iacr.org/2012/685.pdf applicable?
    // https://github.com/zkcrypto/bls12_381/blob/080eaa74ec0e394377caa1ba302c8c121df08b07/src/fp2.rs#L250
    // https://github.com/supranational/blst/blob/aae0c7d70b799ac269ff5edf29d8191dbd357876/src/exp2.c#L1
    // Inspired by https://github.com/dalek-cryptography/curve25519-dalek/blob/17698df9d4c834204f83a3574143abacb4fc81a5/src/field.rs#L99
    const candidateSqrt = this.pow((Fp2.ORDER + 8n) / 16n);
    const check = candidateSqrt.square().div(this);
    const R = FP2_ROOTS_OF_UNITY;
    const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
    if (!divisor) return;
    const index = R.indexOf(divisor);
    const root = R[index / 2];
    if (!root) throw new Error('Invalid root');
    const x1 = candidateSqrt.div(root);
    const x2 = x1.negate();
    const { re: re1, im: im1 } = x1.reim();
    const { re: re2, im: im2 } = x2.reim();
    if (im1 > im2 || (im1 === im2 && re1 > re2)) return x1;
    return x2;
  }

  // We wish to find the multiplicative inverse of a nonzero
  // element a + bu in Fp2. We leverage an identity
  //
  // (a + bu)(a - bu) = a² + b²
  //
  // which holds because u² = -1. This can be rewritten as
  //
  // (a + bu)(a - bu)/(a² + b²) = 1
  //
  // because a² + b² = 0 has no nonzero solutions for (a, b).
  // This gives that (a - bu)/(a² + b²) is the inverse
  // of (a + bu). Importantly, this can be computing using
  // only a single inversion in Fp.
  invert() {
    const { re: a, im: b } = this.reim();
    const factor = new Fp(a * a + b * b).invert();
    return new Fp2(factor.multiply(new Fp(a)), factor.multiply(new Fp(-b)));
  }

  // Raises to q**i -th power
  frobeniusMap(power: number): Fp2 {
    return new Fp2(this.c0, this.c1.multiply(FP2_FROBENIUS_COEFFICIENTS[power % 2]));
  }
  multiplyByB() {
    let c0 = this.c0;
    let c1 = this.c1;
    let t0 = c0.multiply(4n); // 4 * c0
    let t1 = c1.multiply(4n); // 4 * c1
    // (T0-T1) + (T0+T1)*i
    return new Fp2(t0.subtract(t1), t0.add(t1));
  }
  static fromBytes(b: Uint8Array): Fp2 {
    if (b.length !== Fp2.BYTES_LEN) throw new Error(`fromBytes wrong length=${b.length}`);
    return new Fp2(
      Fp.fromBytes(b.subarray(0, Fp.BYTES_LEN)),
      Fp.fromBytes(b.subarray(Fp.BYTES_LEN))
    );
  }
  toBytes(): Uint8Array {
    return concatBytes(this.c0.toBytes(), this.c1.toBytes());
  }
}

// Finite extension field over irreducible polynominal.
// Fp2(v) / (v³ - ξ) where ξ = u + 1
export class Fp6 implements Field<Fp6> {
  static readonly ZERO = new Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO);
  static readonly ONE = new Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO);
  static readonly BYTES_LEN = 3 * Fp2.BYTES_LEN;
  static fromBigSix(t: BigintSix): Fp6 {
    if (!Array.isArray(t) || t.length !== 6) throw new Error('Invalid Fp6 usage');
    const c = [t.slice(0, 2), t.slice(2, 4), t.slice(4, 6)].map((t) => Fp2.fromBigTuple(t)) as [
      Fp2,
      Fp2,
      Fp2
    ];
    return new Fp6(...c);
  }

  constructor(readonly c0: Fp2, readonly c1: Fp2, readonly c2: Fp2) {}
  fromTriple(triple: [Fp2, Fp2, Fp2]) {
    return new Fp6(...triple);
  }
  one() {
    return Fp6.ONE;
  }
  isZero(): boolean {
    return this.c0.isZero() && this.c1.isZero() && this.c2.isZero();
  }
  negate(): Fp6 {
    const { c0, c1, c2 } = this;
    return new Fp6(c0.negate(), c1.negate(), c2.negate());
  }
  toString() {
    return `Fp6(${this.c0} + ${this.c1} * v, ${this.c2} * v^2)`;
  }
  equals(rhs: Fp6): boolean {
    const { c0, c1, c2 } = this;
    const { c0: r0, c1: r1, c2: r2 } = rhs;
    return c0.equals(r0) && c1.equals(r1) && c2.equals(r2);
  }
  add(rhs: Fp6): Fp6 {
    const { c0, c1, c2 } = this;
    const { c0: r0, c1: r1, c2: r2 } = rhs;
    return new Fp6(c0.add(r0), c1.add(r1), c2.add(r2));
  }
  subtract(rhs: Fp6): Fp6 {
    const { c0, c1, c2 } = this;
    const { c0: r0, c1: r1, c2: r2 } = rhs;
    return new Fp6(c0.subtract(r0), c1.subtract(r1), c2.subtract(r2));
  }

  multiply(rhs: Fp6 | bigint) {
    if (typeof rhs === 'bigint') {
      return new Fp6(this.c0.multiply(rhs), this.c1.multiply(rhs), this.c2.multiply(rhs));
    }
    let { c0, c1, c2 } = this;
    let { c0: r0, c1: r1, c2: r2 } = rhs;
    let t0 = c0.multiply(r0); // c0 * o0
    let t1 = c1.multiply(r1); // c1 * o1
    let t2 = c2.multiply(r2); // c2 * o2
    return new Fp6(
      // t0 + (c1 + c2) * (r1 * r2) - (T1 + T2) * (u + 1)
      t0.add(c1.add(c2).multiply(r1.add(r2)).subtract(t1.add(t2)).mulByNonresidue()),
      // (c0 + c1) * (r0 + r1) - (T0 + T1) + T2 * (u + 1)
      c0.add(c1).multiply(r0.add(r1)).subtract(t0.add(t1)).add(t2.mulByNonresidue()),
      // T1 + (c0 + c2) * (r0 + r2) - T0 + T2
      t1.add(c0.add(c2).multiply(r0.add(r2)).subtract(t0.add(t2)))
    );
  }
  pow(n: bigint): Fp6 {
    return powMod_FQP(this, Fp6.ONE, n);
  }
  div(rhs: Fp6 | bigint): Fp6 {
    const inv = typeof rhs === 'bigint' ? new Fp(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }
  // Multiply by quadratic nonresidue v.
  mulByNonresidue() {
    return new Fp6(this.c2.mulByNonresidue(), this.c0, this.c1);
  }
  // Sparse multiplication
  multiplyBy1(b1: Fp2): Fp6 {
    return new Fp6(
      this.c2.multiply(b1).mulByNonresidue(),
      this.c0.multiply(b1),
      this.c1.multiply(b1)
    );
  }
  // Sparse multiplication
  multiplyBy01(b0: Fp2, b1: Fp2): Fp6 {
    let { c0, c1, c2 } = this;
    let t0 = c0.multiply(b0); // c0 * b0
    let t1 = c1.multiply(b1); // c1 * b1
    return new Fp6(
      // ((c1 + c2) * b1 - T1) * (u + 1) + T0
      c1.add(c2).multiply(b1).subtract(t1).mulByNonresidue().add(t0),
      // (b0 + b1) * (c0 + c1) - T0 - T1
      b0.add(b1).multiply(c0.add(c1)).subtract(t0).subtract(t1),
      // (c0 + c2) * b0 - T0 + T1
      c0.add(c2).multiply(b0).subtract(t0).add(t1)
    );
  }

  multiplyByFp2(rhs: Fp2): Fp6 {
    let { c0, c1, c2 } = this;
    return new Fp6(c0.multiply(rhs), c1.multiply(rhs), c2.multiply(rhs));
  }

  square() {
    let { c0, c1, c2 } = this;
    let t0 = c0.square(); // c0²
    let t1 = c0.multiply(c1).multiply(2n); // 2 * c0 * c1
    let t3 = c1.multiply(c2).multiply(2n); // 2 * c1 * c2
    let t4 = c2.square(); // c2²
    return new Fp6(
      t3.mulByNonresidue().add(t0), // T3 * (u + 1) + T0
      t4.mulByNonresidue().add(t1), // T4 * (u + 1) + T1
      // T1 + (c0 - c1 + c2)² + T3 - T0 - T4
      t1.add(c0.subtract(c1).add(c2).square()).add(t3).subtract(t0).subtract(t4)
    );
  }

  invert() {
    let { c0, c1, c2 } = this;
    let t0 = c0.square().subtract(c2.multiply(c1).mulByNonresidue()); // c0² - c2 * c1 * (u + 1)
    let t1 = c2.square().mulByNonresidue().subtract(c0.multiply(c1)); // c2² * (u + 1) - c0 * c1
    let t2 = c1.square().subtract(c0.multiply(c2)); // c1² - c0 * c2
    // 1/(((c2 * T1 + c1 * T2) * v) + c0 * T0)
    let t4 = c2.multiply(t1).add(c1.multiply(t2)).mulByNonresidue().add(c0.multiply(t0)).invert();
    return new Fp6(t4.multiply(t0), t4.multiply(t1), t4.multiply(t2));
  }
  // Raises to q**i -th power
  frobeniusMap(power: number) {
    return new Fp6(
      this.c0.frobeniusMap(power),
      this.c1.frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_1[power % 6]),
      this.c2.frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_2[power % 6])
    );
  }
  static fromBytes(b: Uint8Array): Fp6 {
    if (b.length !== Fp6.BYTES_LEN) throw new Error(`fromBytes wrong length=${b.length}`);
    return new Fp6(
      Fp2.fromBytes(b.subarray(0, Fp2.BYTES_LEN)),
      Fp2.fromBytes(b.subarray(Fp2.BYTES_LEN, 2 * Fp2.BYTES_LEN)),
      Fp2.fromBytes(b.subarray(2 * Fp2.BYTES_LEN))
    );
  }
  toBytes(): Uint8Array {
    return concatBytes(this.c0.toBytes(), this.c1.toBytes(), this.c2.toBytes());
  }
}

// Finite extension field over irreducible polynominal.
// Fp₁₂ = Fp₆² => Fp₂³
// Fp₆(w) / (w² - γ) where γ = v
export class Fp12 implements Field<Fp12> {
  static readonly ZERO = new Fp12(Fp6.ZERO, Fp6.ZERO);
  static readonly ONE = new Fp12(Fp6.ONE, Fp6.ZERO);
  static readonly BYTES_LEN = 2 * Fp6.BYTES_LEN;
  static fromBigTwelve(t: BigintTwelve): Fp12 {
    return new Fp12(
      Fp6.fromBigSix(t.slice(0, 6) as BigintSix),
      Fp6.fromBigSix(t.slice(6, 12) as BigintSix)
    );
  }
  constructor(readonly c0: Fp6, readonly c1: Fp6) {}
  fromTuple(c: [Fp6, Fp6]) {
    return new Fp12(...c);
  }
  one() {
    return Fp12.ONE;
  }
  isZero(): boolean {
    return this.c0.isZero() && this.c1.isZero();
  }
  toString() {
    return `Fp12(${this.c0} + ${this.c1} * w)`;
  }
  negate(): Fp12 {
    const { c0, c1 } = this;
    return new Fp12(c0.negate(), c1.negate());
  }
  equals(rhs: Fp12): boolean {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return c0.equals(r0) && c1.equals(r1);
  }
  add(rhs: Fp12): Fp12 {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return new Fp12(c0.add(r0), c1.add(r1));
  }
  subtract(rhs: Fp12): Fp12 {
    const { c0, c1 } = this;
    const { c0: r0, c1: r1 } = rhs;
    return new Fp12(c0.subtract(r0), c1.subtract(r1));
  }

  multiply(rhs: Fp12 | bigint) {
    if (typeof rhs === 'bigint') return new Fp12(this.c0.multiply(rhs), this.c1.multiply(rhs));
    let { c0, c1 } = this;
    let { c0: r0, c1: r1 } = rhs;
    let t1 = c0.multiply(r0); // c0 * r0
    let t2 = c1.multiply(r1); // c1 * r1
    return new Fp12(
      t1.add(t2.mulByNonresidue()), // T1 + T2 * v
      // (c0 + c1) * (r0 + r1) - (T1 + T2)
      c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2))
    );
  }
  pow(n: bigint): Fp12 {
    return powMod_FQP(this, Fp12.ONE, n);
  }
  div(rhs: Fp12 | bigint): Fp12 {
    const inv = typeof rhs === 'bigint' ? new Fp(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }
  // Sparse multiplication
  multiplyBy014(o0: Fp2, o1: Fp2, o4: Fp2) {
    let { c0, c1 } = this;
    let t0 = c0.multiplyBy01(o0, o1);
    let t1 = c1.multiplyBy1(o4);
    return new Fp12(
      t1.mulByNonresidue().add(t0), // T1 * v + T0
      // (c1 + c0) * [o0, o1+o4] - T0 - T1
      c1.add(c0).multiplyBy01(o0, o1.add(o4)).subtract(t0).subtract(t1)
    );
  }

  multiplyByFp2(rhs: Fp2): Fp12 {
    return new Fp12(this.c0.multiplyByFp2(rhs), this.c1.multiplyByFp2(rhs));
  }

  square() {
    let { c0, c1 } = this;
    let ab = c0.multiply(c1); // c0 * c1
    return new Fp12(
      // (c1 * v + c0) * (c0 + c1) - AB - AB * v
      c1.mulByNonresidue().add(c0).multiply(c0.add(c1)).subtract(ab).subtract(ab.mulByNonresidue()),
      ab.add(ab)
    ); // AB + AB
  }

  invert() {
    let { c0, c1 } = this;
    let t = c0.square().subtract(c1.square().mulByNonresidue()).invert(); // 1 / (c0² - c1² * v)
    return new Fp12(c0.multiply(t), c1.multiply(t).negate()); // ((C0 * T) * T) + (-C1 * T) * w
  }

  conjugate(): Fp12 {
    return new Fp12(this.c0, this.c1.negate());
  }

  // Raises to q**i -th power
  frobeniusMap(power: number) {
    const r0 = this.c0.frobeniusMap(power);
    const { c0, c1, c2 } = this.c1.frobeniusMap(power);
    const coeff = FP12_FROBENIUS_COEFFICIENTS[power % 12];
    return new Fp12(r0, new Fp6(c0.multiply(coeff), c1.multiply(coeff), c2.multiply(coeff)));
  }

  private Fp4Square(a: Fp2, b: Fp2): { first: Fp2; second: Fp2 } {
    const a2 = a.square();
    const b2 = b.square();
    return {
      first: b2.mulByNonresidue().add(a2), // b² * Nonresidue + a²
      second: a.add(b).square().subtract(a2).subtract(b2), // (a + b)² - a² - b²
    };
  }

  // A cyclotomic group is a subgroup of Fp^n defined by
  //   GΦₙ(p) = {α ∈ Fpⁿ : α^Φₙ(p) = 1}
  // The result of any pairing is in a cyclotomic subgroup
  // https://eprint.iacr.org/2009/565.pdf
  private cyclotomicSquare(): Fp12 {
    const { c0: c0c0, c1: c0c1, c2: c0c2 } = this.c0;
    const { c0: c1c0, c1: c1c1, c2: c1c2 } = this.c1;
    const { first: t3, second: t4 } = this.Fp4Square(c0c0, c1c1);
    const { first: t5, second: t6 } = this.Fp4Square(c1c0, c0c2);
    const { first: t7, second: t8 } = this.Fp4Square(c0c1, c1c2);
    let t9 = t8.mulByNonresidue(); // T8 * (u + 1)
    return new Fp12(
      new Fp6(
        t3.subtract(c0c0).multiply(2n).add(t3), // 2 * (T3 - c0c0)  + T3
        t5.subtract(c0c1).multiply(2n).add(t5), // 2 * (T5 - c0c1)  + T5
        t7.subtract(c0c2).multiply(2n).add(t7)
      ), // 2 * (T7 - c0c2)  + T7
      new Fp6(
        t9.add(c1c0).multiply(2n).add(t9), // 2 * (T9 + c1c0) + T9
        t4.add(c1c1).multiply(2n).add(t4), // 2 * (T4 + c1c1) + T4
        t6.add(c1c2).multiply(2n).add(t6)
      )
    ); // 2 * (T6 + c1c2) + T6
  }

  private cyclotomicExp(n: bigint) {
    let z = Fp12.ONE;
    for (let i = BLS_X_LEN - 1; i >= 0; i--) {
      z = z.cyclotomicSquare();
      if (bitGet(n, i)) z = z.multiply(this);
    }
    return z;
  }

  // https://eprint.iacr.org/2010/354.pdf
  // https://eprint.iacr.org/2009/565.pdf
  finalExponentiate() {
    const { x } = CURVE;
    // this^(q⁶) / this
    const t0 = this.frobeniusMap(6).div(this);
    // t0^(q²) * t0
    const t1 = t0.frobeniusMap(2).multiply(t0);
    const t2 = t1.cyclotomicExp(x).conjugate();
    const t3 = t1.cyclotomicSquare().conjugate().multiply(t2);
    const t4 = t3.cyclotomicExp(x).conjugate();
    const t5 = t4.cyclotomicExp(x).conjugate();
    const t6 = t5.cyclotomicExp(x).conjugate().multiply(t2.cyclotomicSquare());
    const t7 = t6.cyclotomicExp(x).conjugate();
    const t2_t5_pow_q2 = t2.multiply(t5).frobeniusMap(2);
    const t4_t1_pow_q3 = t4.multiply(t1).frobeniusMap(3);
    const t6_t1c_pow_q1 = t6.multiply(t1.conjugate()).frobeniusMap(1);
    const t7_t3c_t1 = t7.multiply(t3.conjugate()).multiply(t1);
    // (t2 * t5)^(q²) * (t4 * t1)^(q³) * (t6 * t1.conj)^(q^1) * t7 * t3.conj * t1
    return t2_t5_pow_q2.multiply(t4_t1_pow_q3).multiply(t6_t1c_pow_q1).multiply(t7_t3c_t1);
  }
  static fromBytes(b: Uint8Array): Fp12 {
    if (b.length !== Fp12.BYTES_LEN) throw new Error(`fromBytes wrong length=${b.length}`);
    return new Fp12(
      Fp6.fromBytes(b.subarray(0, Fp6.BYTES_LEN)),
      Fp6.fromBytes(b.subarray(Fp6.BYTES_LEN))
    );
  }
  toBytes(): Uint8Array {
    return concatBytes(this.c0.toBytes(), this.c1.toBytes());
  }
}

type Constructor<T extends Field<T>> = { new (...args: any[]): T } & FieldStatic<T> & {
    MAX_BITS: number;
  };
//type PointConstructor<TT extends Field<T>, T extends ProjectivePoint<TT>> = { new(...args: any[]): T };

// x=X/Z, y=Y/Z
export abstract class ProjectivePoint<T extends Field<T>> {
  private _MPRECOMPUTES: undefined | [number, this[]];

  constructor(
    public readonly x: T,
    public readonly y: T,
    public readonly z: T,
    private readonly C: Constructor<T>
  ) {}

  isZero() {
    return this.z.isZero();
  }
  createPoint<TT extends this>(x: T, y: T, z: T): TT {
    return new (<any>this.constructor)(x, y, z);
  }

  getZero(): this {
    return this.createPoint(this.C.ONE, this.C.ONE, this.C.ZERO);
  }

  // Compare one point to another.
  equals(rhs: ProjectivePoint<T>) {
    if (this.constructor !== rhs.constructor)
      throw new Error(
        `ProjectivePoint#equals: this is ${this.constructor}, but rhs is ${rhs.constructor}`
      );
    const a = this;
    const b = rhs;
    // Ax * Bz == Bx * Az
    const xe = a.x.multiply(b.z).equals(b.x.multiply(a.z));
    // Ay * Bz == By * Az
    const ye = a.y.multiply(b.z).equals(b.y.multiply(a.z));
    return xe && ye;
  }

  negate(): this {
    return this.createPoint(this.x, this.y.negate(), this.z);
  }

  toString(isAffine = true) {
    if (this.isZero()) {
      return `Point<Zero>`;
    }
    if (!isAffine) {
      return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
    }
    const [x, y] = this.toAffine();
    return `Point<x=${x}, y=${y}>`;
  }

  fromAffineTuple(xy: [T, T]): this {
    return this.createPoint(xy[0], xy[1], this.C.ONE);
  }
  // Converts Projective point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  toAffine(invZ: T = this.z.invert()): [T, T] {
    if (invZ.isZero()) throw new Error('Invalid inverted z');
    return [this.x.multiply(invZ), this.y.multiply(invZ)];
  }

  toAffineBatch(points: ProjectivePoint<T>[]): [T, T][] {
    const toInv = genInvertBatch(
      this.C,
      points.map((p) => p.z)
    );
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

  normalizeZ(points: this[]): this[] {
    return this.toAffineBatch(points).map((t) => this.fromAffineTuple(t));
  }

  // http://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-1998-cmo-2
  // Cost: 6M + 5S + 1*a + 4add + 1*2 + 1*3 + 1*4 + 3*8.
  double(): this {
    const { x, y, z } = this;
    const W = x.multiply(x).multiply(3n);
    const S = y.multiply(z);
    const SS = S.multiply(S);
    const SSS = SS.multiply(S);
    const B = x.multiply(y).multiply(S);
    const H = W.multiply(W).subtract(B.multiply(8n));
    const X3 = H.multiply(S).multiply(2n);
    // W * (4 * B - H) - 8 * y * y * S_squared
    const Y3 = W.multiply(B.multiply(4n).subtract(H)).subtract(
      y.multiply(y).multiply(8n).multiply(SS)
    );
    const Z3 = SSS.multiply(8n);
    return this.createPoint(X3, Y3, Z3);
  }

  // http://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
  // Cost: 12M + 2S + 6add + 1*2.
  add(rhs: this): this {
    if (this.constructor !== rhs.constructor)
      throw new Error(
        `ProjectivePoint#add: this is ${this.constructor}, but rhs is ${rhs.constructor}`
      );
    const p1 = this;
    const p2 = rhs;
    if (p1.isZero()) return p2;
    if (p2.isZero()) return p1;
    const X1 = p1.x;
    const Y1 = p1.y;
    const Z1 = p1.z;
    const X2 = p2.x;
    const Y2 = p2.y;
    const Z2 = p2.z;
    const U1 = Y2.multiply(Z1);
    const U2 = Y1.multiply(Z2);
    const V1 = X2.multiply(Z1);
    const V2 = X1.multiply(Z2);
    if (V1.equals(V2) && U1.equals(U2)) return this.double();
    if (V1.equals(V2)) return this.getZero();
    const U = U1.subtract(U2);
    const V = V1.subtract(V2);
    const VV = V.multiply(V);
    const VVV = VV.multiply(V);
    const V2VV = V2.multiply(VV);
    const W = Z1.multiply(Z2);
    const A = U.multiply(U).multiply(W).subtract(VVV).subtract(V2VV.multiply(2n));
    const X3 = V.multiply(A);
    const Y3 = U.multiply(V2VV.subtract(A)).subtract(VVV.multiply(U2));
    const Z3 = VVV.multiply(W);
    return this.createPoint(X3, Y3, Z3);
  }

  subtract(rhs: this): this {
    if (this.constructor !== rhs.constructor)
      throw new Error(
        `ProjectivePoint#subtract: this is ${this.constructor}, but rhs is ${rhs.constructor}`
      );
    return this.add(rhs.negate());
  }

  private validateScalar(n: bigint | number): bigint {
    if (typeof n === 'number') n = BigInt(n);
    if (typeof n !== 'bigint' || n <= 0 || n > CURVE.r) {
      throw new Error(
        `Point#multiply: invalid scalar, expected positive integer < CURVE.r. Got: ${n}`
      );
    }
    return n;
  }

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  multiplyUnsafe(scalar: bigint): this {
    let n = this.validateScalar(scalar);
    let point = this.getZero();
    let d: this = this;
    while (n > 0n) {
      if (n & 1n) point = point.add(d);
      d = d.double();
      n >>= 1n;
    }
    return point;
  }

  // Constant-time multiplication
  multiply(scalar: bigint): this {
    let n = this.validateScalar(scalar);
    let point = this.getZero();
    let fake = this.getZero();
    let d: this = this;
    let bits = Fp.ORDER;
    while (bits > 0n) {
      if (n & 1n) {
        point = point.add(d);
      } else {
        fake = fake.add(d);
      }
      d = d.double();
      n >>= 1n;
      bits >>= 1n;
    }
    return point;
  }

  // Should be not more than curve order, but I cannot find it.
  // Curve order cannot be more than Group/Field order, so let's use it.
  private maxBits() {
    return this.C.MAX_BITS;
  }

  private precomputeWindow(W: number): this[] {
    // Split scalar by W bits, last window can be smaller
    const windows = Math.ceil(this.maxBits() / W);
    // 2^(W-1), since we use wNAF, we only need W-1 bits
    const windowSize = 2 ** (W - 1);

    let points: this[] = [];
    let p: this = this;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < windowSize; i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }

  calcMultiplyPrecomputes(W: number) {
    if (this._MPRECOMPUTES) throw new Error('This point already has precomputes');
    this._MPRECOMPUTES = [W, this.normalizeZ(this.precomputeWindow(W))];
  }

  clearMultiplyPrecomputes() {
    this._MPRECOMPUTES = undefined;
  }

  private wNAF(n: bigint): [this, this] {
    let W, precomputes;
    if (this._MPRECOMPUTES) {
      [W, precomputes] = this._MPRECOMPUTES;
    } else {
      W = 1;
      precomputes = this.precomputeWindow(W);
    }

    let p = this.getZero();
    let f = this.getZero();
    // Split scalar by W bits, last window can be smaller
    const windows = Math.ceil(this.maxBits() / W);
    // 2^(W-1), since we use wNAF, we only need W-1 bits
    const windowSize = 2 ** (W - 1);
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
    const maxNumber = 2 ** W;
    const shiftBy = BigInt(W);

    for (let window = 0; window < windows; window++) {
      const offset = window * windowSize;
      // Extract W bits.
      let wbits = Number(n & mask);
      // Shift number by W bits.
      n >>= shiftBy;

      // If the bits are bigger than max size, we'll split those.
      // +224 => 256 - 32
      if (wbits > windowSize) {
        wbits -= maxNumber;
        n += 1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      if (wbits === 0) {
        f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
      } else {
        const cached = precomputes[offset + Math.abs(wbits) - 1];
        p = p.add(wbits < 0 ? cached.negate() : cached);
      }
    }
    return [p, f];
  }

  // Constant time multiplication. Uses wNAF.
  multiplyPrecomputed(scalar: bigint): this {
    return this.wNAF(this.validateScalar(scalar))[0];
  }
}

function sgn0_fp2(x: Fp2) {
  const { re: x0, im: x1 } = x.reim();
  const sign_0 = x0 % 2n;
  const zero_0 = x0 === 0n;
  const sign_1 = x1 % 2n;
  return BigInt(sign_0 || (zero_0 && sign_1));
}

function sgn0_m_eq_1(x: Fp) {
  return Boolean(x.value % 2n);
}

const P_MINUS_9_DIV_16 = (CURVE.P ** 2n - 9n) / 16n;
// Does not return a square root.
// Returns uv⁷ * (uv¹⁵)^((p² - 9) / 16) * root of unity
// if valid square root is found
function sqrt_div_fp2(u: Fp2, v: Fp2) {
  const v7 = v.pow(7n);
  const uv7 = u.multiply(v7);
  const uv15 = uv7.multiply(v7.multiply(v));
  // gamma =  uv⁷ * (uv¹⁵)^((p² - 9) / 16)
  const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
  let success = false;
  let result = gamma;
  // Constant-time routine, so we do not early-return.
  const positiveRootsOfUnity = FP2_ROOTS_OF_UNITY.slice(0, 4);
  positiveRootsOfUnity.forEach((root) => {
    // Valid if (root * gamma)² * v - u == 0
    const candidate = root.multiply(gamma);
    if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
      success = true;
      result = candidate;
    }
  });
  return { success, sqrtCandidateOrGamma: result };
}

// Optimized SWU Map - Fp2 to G2': y² = x³ + 240i * x + 1012 + 1012i
// Found in Section 4 of https://eprint.iacr.org/2019/403
// Note: it's constant-time
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-G.2.3
export function map_to_curve_simple_swu_9mod16(t: bigint[] | Fp2): [Fp2, Fp2] {
  const iso_3_a = new Fp2(new Fp(0n), new Fp(240n));
  const iso_3_b = new Fp2(new Fp(1012n), new Fp(1012n));
  const iso_3_z = new Fp2(new Fp(-2n), new Fp(-1n));
  if (Array.isArray(t)) t = Fp2.fromBigTuple(t);

  const t2 = t.pow(2n);
  const iso_3_z_t2 = iso_3_z.multiply(t2);
  const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n)); // (Z * t² + Z² * t⁴)
  let denominator = iso_3_a.multiply(ztzt).negate(); // -a(Z * t² + Z² * t⁴)
  let numerator = iso_3_b.multiply(ztzt.add(Fp2.ONE)); // b(Z * t² + Z² * t⁴ + 1)

  // Exceptional case
  if (denominator.isZero()) denominator = iso_3_z.multiply(iso_3_a);

  // v = D³
  let v = denominator.pow(3n);
  // u = N³ + a * N * D² + b * D³
  let u = numerator
    .pow(3n)
    .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
    .add(iso_3_b.multiply(v));
  // Attempt y = sqrt(u / v)
  const { success, sqrtCandidateOrGamma } = sqrt_div_fp2(u, v);
  let y;
  if (success) y = sqrtCandidateOrGamma;
  // Handle case where (u / v) is not square
  // sqrt_candidate(x1) = sqrt_candidate(x0) * t³
  const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));

  // u(x1) = Z³ * t⁶ * u(x0)
  u = iso_3_z_t2.pow(3n).multiply(u);
  let success2 = false;
  FP2_ETAs.forEach((eta) => {
    // Valid solution if (eta * sqrt_candidate(x1))² * v - u == 0
    const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
    const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
    if (temp.isZero() && !success && !success2) {
      y = etaSqrtCandidate;
      success2 = true;
    }
  });
  if (!success && !success2) throw new Error('Hash to Curve - Optimized SWU failure');
  if (success2) numerator = numerator.multiply(iso_3_z_t2);
  y = y as Fp2;
  if (sgn0_fp2(t) !== sgn0_fp2(y)) y = y.negate();
  return [numerator.div(denominator), y];
}
// Optimized SWU Map - Fp to G1
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-G.2.1
export function map_to_curve_simple_swu_3mod4(u: Fp): [Fp, Fp] {
  const A = new Fp(
    0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1dn
  );
  const B = new Fp(
    0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0n
  );
  const Z = new Fp(11n);
  const c1 = (Fp.ORDER - 3n) / 4n; // (q - 3) / 4
  // Static value so we can know that is there always root
  const c2 = Z.negate().pow(3n).sqrt()!; // sqrt((-Z) ^ 3)
  const tv1 = u.square(); // u ** 2n;
  const tv3 = Z.multiply(tv1); //
  let xDen = tv3.square().add(tv3);
  // X
  const xNum1 = xDen.add(Fp.ONE).multiply(B); // (xd + 1) * B
  const xNum2 = tv3.multiply(xNum1); // x2 = x2n / xd = Z * u^2 * x1n / xd
  xDen = A.negate().multiply(xDen); // -A * xDen
  if (xDen.isZero()) xDen = A.multiply(Z);
  let tv2 = xDen.square(); // xDen ^ 2
  const gxd = tv2.multiply(xDen); // xDen ^ 3
  tv2 = A.multiply(tv2); // A * tv2
  let gx1 = xNum1.square().add(tv2).multiply(xNum1); // x1n^3 + A * x1n * xd^2
  tv2 = B.multiply(gxd); // B * gxd
  gx1 = gx1.add(tv2); // x1n^3 + A * x1n * xd^2 + B * xd^3
  tv2 = gx1.multiply(gxd); // gx1 * gxd
  const tv4 = gxd.square().multiply(tv2); // gx1 * gxd^3
  // Y
  const y1 = tv4.pow(c1).multiply(tv2); // gx1 * gxd * (gx1 * gxd^3)^((q - 3) / 4)
  const y2 = y1.multiply(c2).multiply(tv1).multiply(u); // y1 * c2 * tv1 * u
  let xNum, yPos;
  // y1^2 * gxd == gx1
  if (y1.square().multiply(gxd).equals(gx1)) {
    xNum = xNum1;
    yPos = y1;
  } else {
    xNum = xNum2;
    yPos = y2;
  }
  const yNeg = yPos.negate();
  const y = sgn0_m_eq_1(u) == sgn0_m_eq_1(yPos) ? yPos : yNeg;
  // NOTE: we can batch inversion for hashToCurve, but it doesn't impact performance
  return [xNum.div(xDen), y];
}

function isogenyMap<T extends Field<T>>(COEFF: [T[], T[], T[], T[]], x: T, y: T): [T, T] {
  const [xNum, xDen, yNum, yDen] = COEFF.map((val) =>
    val.reduce((acc, i) => acc.multiply(x).add(i))
  );
  x = xNum.div(xDen); // xNum / xDen
  y = y.multiply(yNum.div(yDen)); // y * (yNum / yDev)
  return [x, y];
}
// 3-isogeny map from E' to E
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-E.3
export const isogenyMapG2 = (x: Fp2, y: Fp2) => isogenyMap(ISOGENY_COEFFICIENTS_G2, x, y);
// 11-isogeny map from E' to E
export const isogenyMapG1 = (x: Fp, y: Fp) => isogenyMap(ISOGENY_COEFFICIENTS_G1, x, y);

// Pre-compute coefficients for sparse multiplication
// Point addition and point double calculations is reused for coefficients
export function calcPairingPrecomputes(x: Fp2, y: Fp2) {
  // prettier-ignore
  const Qx = x, Qy = y, Qz = Fp2.ONE;
  // prettier-ignore
  let Rx = Qx, Ry = Qy, Rz = Qz;
  let ell_coeff: [Fp2, Fp2, Fp2][] = [];
  for (let i = BLS_X_LEN - 2; i >= 0; i--) {
    // Double
    let t0 = Ry.square(); // Ry²
    let t1 = Rz.square(); // Rz²
    let t2 = t1.multiply(3n).multiplyByB(); // 3 * T1 * B
    let t3 = t2.multiply(3n); // 3 * T2
    let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0); // (Ry + Rz)² - T1 - T0
    ell_coeff.push([
      t2.subtract(t0), // T2 - T0
      Rx.square().multiply(3n), // 3 * Rx²
      t4.negate(), // -T4
    ]);
    Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n); // ((T0 - T3) * Rx * Ry) / 2
    Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n)); // ((T0 + T3) / 2)² - 3 * T2²
    Rz = t0.multiply(t4); // T0 * T4
    if (bitGet(CURVE.x, i)) {
      // Addition
      let t0 = Ry.subtract(Qy.multiply(Rz)); // Ry - Qy * Rz
      let t1 = Rx.subtract(Qx.multiply(Rz)); // Rx - Qx * Rz
      ell_coeff.push([
        t0.multiply(Qx).subtract(t1.multiply(Qy)), // T0 * Qx - T1 * Qy
        t0.negate(), // -T0
        t1, // T1
      ]);
      let t2 = t1.square(); // T1²
      let t3 = t2.multiply(t1); // T2 * T1
      let t4 = t2.multiply(Rx); // T2 * Rx
      let t5 = t3.subtract(t4.multiply(2n)).add(t0.square().multiply(Rz)); // T3 - 2 * T4 + T0² * Rz
      Rx = t1.multiply(t5); // T1 * T5
      Ry = t4.subtract(t5).multiply(t0).subtract(t3.multiply(Ry)); // (T4 - T5) * T0 - T3 * Ry
      Rz = Rz.multiply(t3); // Rz * T3
    }
  }
  return ell_coeff;
}

export function millerLoop(ell: [Fp2, Fp2, Fp2][], g1: [Fp, Fp]): Fp12 {
  const Px = g1[0].value;
  const Py = g1[1].value;
  let f12 = Fp12.ONE;
  for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
    const E = ell[j];
    f12 = f12.multiplyBy014(E[0], E[1].multiply(Px), E[2].multiply(Py));
    if (bitGet(CURVE.x, i)) {
      j += 1;
      const F = ell[j];
      f12 = f12.multiplyBy014(F[0], F[1].multiply(Px), F[2].multiply(Py));
    }
    if (i !== 0) f12 = f12.square();
  }
  return f12.conjugate();
}

const ut_root = new Fp6(Fp2.ZERO, Fp2.ONE, Fp2.ZERO);
const wsq = new Fp12(ut_root, Fp6.ZERO);
const wcu = new Fp12(Fp6.ZERO, ut_root);
const [wsq_inv, wcu_inv] = genInvertBatch(Fp12, [wsq, wcu]);
// const wsq_inv = wsq.invert();
// const wcu_inv = wcu.invert();

// Ψ(P) endomorphism
export function psi(x: Fp2, y: Fp2): [Fp2, Fp2] {
  // Untwist Fp2->Fp12 && frobenius(1) && twist back
  const x2 = wsq_inv.multiplyByFp2(x).frobeniusMap(1).multiply(wsq).c0.c0;
  const y2 = wcu_inv.multiplyByFp2(y).frobeniusMap(1).multiply(wcu).c0.c0;
  return [x2, y2];
}

// Ψ²(P) endomorphism
export function psi2(x: Fp2, y: Fp2): [Fp2, Fp2] {
  return [x.multiply(PSI2_C1), y.negate()];
}

// 1 / F2(2)^((p-1)/3) in GF(p²)
const PSI2_C1 =
  0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;

// For Fp2 roots of unity.
const rv1 =
  0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const ev1 =
  0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 =
  0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 =
  0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 =
  0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;

// Finite extension field over irreducible polynominal.
// Fp(u) / (u² - β) where β = -1
const FP2_FROBENIUS_COEFFICIENTS = [
  0x1n,
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
].map((item) => new Fp(item));

// Eighth roots of unity, used for computing square roots in Fp2.
// To verify or re-calculate:
// Array(8).fill(new Fp2([1n, 1n])).map((fp2, k) => fp2.pow(Fp2.ORDER * BigInt(k) / 8n))
const FP2_ROOTS_OF_UNITY = [
  [1n, 0n],
  [rv1, -rv1],
  [0n, 1n],
  [rv1, rv1],
  [-1n, 0n],
  [-rv1, rv1],
  [0n, -1n],
  [-rv1, -rv1],
].map((pair) => Fp2.fromBigTuple(pair));
// eta values, used for computing sqrt(g(X1(t)))
const FP2_ETAs = [
  [ev1, ev2],
  [-ev2, ev1],
  [ev3, ev4],
  [-ev4, ev3],
].map((pair) => Fp2.fromBigTuple(pair));

const FP6_FROBENIUS_COEFFICIENTS_1 = [
  [0x1n, 0x0n],
  [
    0x0n,
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
  ],
  [
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
    0x0n,
  ],
  [0x0n, 0x1n],
  [
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
    0x0n,
  ],
  [
    0x0n,
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
  ],
].map((pair) => Fp2.fromBigTuple(pair));
const FP6_FROBENIUS_COEFFICIENTS_2 = [
  [0x1n, 0x0n],
  [
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
    0x0n,
  ],
  [
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
    0x0n,
  ],
  [
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
    0x0n,
  ],
  [
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
    0x0n,
  ],
  [
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
    0x0n,
  ],
].map((pair) => Fp2.fromBigTuple(pair));
const FP12_FROBENIUS_COEFFICIENTS = [
  [0x1n, 0x0n],
  [
    0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
    0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
  ],
  [
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
    0x0n,
  ],
  [
    0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
    0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
  ],
  [
    0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
    0x0n,
  ],
  [
    0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
    0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
  ],
  [
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
    0x0n,
  ],
  [
    0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
    0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
  ],
  [
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
    0x0n,
  ],
  [
    0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
    0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
  ],
  [
    0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
    0x0n,
  ],
  [
    0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
    0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
  ],
].map((n) => Fp2.fromBigTuple(n));

// Utilities for 3-isogeny map from E' to E.
type Fp2_4 = [Fp2, Fp2, Fp2, Fp2];
const xnum = [
  [
    0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
    0x0n,
  ],
  [
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
  ],
  [
    0x0n,
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
  ],
  [
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
  ],
].map((pair) => Fp2.fromBigTuple(pair)) as Fp2_4;
const xden = [
  [0x0n, 0x0n],
  [0x1n, 0x0n],
  [
    0xcn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
  ],
  [
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
  ],
].map((pair) => Fp2.fromBigTuple(pair)) as Fp2_4;
const ynum = [
  [
    0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
    0x0n,
  ],
  [
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
  ],
  [
    0x0n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
  ],
  [
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
  ],
].map((pair) => Fp2.fromBigTuple(pair)) as Fp2_4;
const yden = [
  [0x1n, 0x0n],
  [
    0x12n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
  ],
  [
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
  ],
  [
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
  ],
].map((pair) => Fp2.fromBigTuple(pair)) as Fp2_4;
const ISOGENY_COEFFICIENTS_G2: [Fp2_4, Fp2_4, Fp2_4, Fp2_4] = [xnum, xden, ynum, yden];

const ISOGENY_COEFFICIENTS_G1: [Fp[], Fp[], Fp[], Fp[]] = [
  // xNum
  [
    new Fp(
      0x06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229n
    ),
    new Fp(
      0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7bn
    ),
    new Fp(
      0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9en
    ),
    new Fp(
      0x080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317n
    ),
    new Fp(
      0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88en
    ),
    new Fp(
      0x0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84n
    ),
    new Fp(
      0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983n
    ),
    new Fp(
      0x0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9n
    ),
    new Fp(
      0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861n
    ),
    new Fp(
      0x0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0n
    ),
    new Fp(
      0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bbn
    ),
    new Fp(
      0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7n
    ),
  ],
  // xDen
  [
    new Fp(
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n
    ),
    new Fp(
      0x095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0an
    ),
    new Fp(
      0x0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641n
    ),
    new Fp(
      0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5en
    ),
    new Fp(
      0x0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3an
    ),
    new Fp(
      0x0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5n
    ),
    new Fp(
      0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21en
    ),
    new Fp(
      0x03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8n
    ),
    new Fp(
      0x0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19n
    ),
    new Fp(
      0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bffn
    ),
    new Fp(
      0x08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1cn
    ),
  ],
  // yNum
  [
    new Fp(
      0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604n
    ),
    new Fp(
      0x05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224bn
    ),
    new Fp(
      0x0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133n
    ),
    new Fp(
      0x0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8n
    ),
    new Fp(
      0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8en
    ),
    new Fp(
      0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132n
    ),
    new Fp(
      0x0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30n
    ),
    new Fp(
      0x09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587n
    ),
    new Fp(
      0x0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29n
    ),
    new Fp(
      0x04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2n
    ),
    new Fp(
      0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0n
    ),
    new Fp(
      0x08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedbn
    ),
    new Fp(
      0x01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cbn
    ),
    new Fp(
      0x00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6n
    ),
    new Fp(
      0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696n
    ),
    new Fp(
      0x090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33n
    ),
  ],
  // yDen
  [
    new Fp(
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n
    ),
    new Fp(
      0x0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8fn
    ),
    new Fp(
      0x02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7n
    ),
    new Fp(
      0x0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345ccn
    ),
    new Fp(
      0x0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092n
    ),
    new Fp(
      0x04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8n
    ),
    new Fp(
      0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55n
    ),
    new Fp(
      0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4an
    ),
    new Fp(
      0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9n
    ),
    new Fp(
      0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775cn
    ),
    new Fp(
      0x08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7acn
    ),
    new Fp(
      0x0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001dn
    ),
    new Fp(
      0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416n
    ),
    new Fp(
      0x058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2n
    ),
    new Fp(
      0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03dn
    ),
    new Fp(
      0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1n
    ),
  ],
];
