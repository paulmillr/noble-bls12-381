// To verify curve parameters, see pairing-friendly-curves spec:
// https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09
// Basic math is done over finite fields over q.
// More complicated math is done over polynominal extension fields.
// To simplify calculations in Fq12, we construct extension tower:
// Fq12 = Fq6^2 => Fq2^3
// Fq(u) / (u^2 - β) where β = -1
// Fq2(v) / (v^3 - ξ) where ξ = u + 1
// Fq6(w) / (w2 - γ) where γ = v

export const CURVE = {
  // characteristic
  P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
  // order
  r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
  // cofactor
  h: 0x396c8c005555e1568c00aaab0000aaabn,
  // generator's coordinates
  Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
  Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
  b: 4n,

  // G2
  // G^2 - 1
  P2:
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn **
      2n -
    1n,
  h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
  G2x: [
    0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
    0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
  ],
  G2y: [
    0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
    0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
  ],
  b2: [4n, 4n],
  // The BLS parameter x for BLS12-381
  x: 0xd201000000010000n,
  h_eff: 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n,
};

//export let DST_LABEL = 'BLS12381G2_XMD:SHA-256_SSWU_RO_';
export let DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const BLS_X_LEN = bitLen(CURVE.x);

type BigintTuple = [bigint, bigint];

// prettier-ignore
type BigintSix = [
  bigint, bigint, bigint,
  bigint, bigint, bigint,
];

// prettier-ignore
export type BigintTwelve = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint
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

export function powMod(a: bigint, power: bigint, m: bigint) {
  let res = 1n;
  while (power > 0n) {
    if (power & 1n) {
      res = mod(res * a, m);
    }
    power >>= 1n;
    a = mod(a * a, m);
  }
  return res;
}

function genInvertBatch<T extends Field<T>>(cls: FieldStatic<T>, nums: T[]): T[] {
  const len = nums.length;
  const scratch = new Array(len);
  let acc = cls.ONE;
  for (let i = 0; i < len; i++) {
    if (nums[i].isZero()) continue;
    scratch[i] = acc;
    acc = acc.multiply(nums[i]);
  }
  acc = acc.invert();
  for (let i = len - 1; i >= 0; i--) {
    if (nums[i].isZero()) continue;
    let tmp = acc.multiply(nums[i]);
    nums[i] = acc.multiply(scratch[i]);
    acc = tmp;
  }
  return nums;
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

// Finite field over q.
export class Fq implements Field<Fq> {
  static readonly ORDER = CURVE.P;
  static readonly MAX_BITS = bitLen(CURVE.P);
  static readonly ZERO = new Fq(0n);
  static readonly ONE = new Fq(1n);

  readonly value: bigint;
  constructor(value: bigint) {
    this.value = mod(value, Fq.ORDER);
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  equals(rhs: Fq): boolean {
    return this.value === rhs.value;
  }

  negate(): Fq {
    return new Fq(-this.value);
  }

  invert(): Fq {
    let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n];
    let a = Fq.ORDER;
    let b = this.value;
    let q;
    while (a !== 0n) {
      [q, b, a] = [b / a, a, b % a];
      [x0, x1] = [x1, x0 - q * x1];
      [y0, y1] = [y1, y0 - q * y1];
    }
    return new Fq(x0);
  }

  add(rhs: Fq): Fq {
    return new Fq(this.value + rhs.value);
  }

  square(): Fq {
    return new Fq(this.value * this.value);
  }

  pow(n: bigint): Fq {
    return new Fq(powMod(this.value, n, Fq.ORDER));
  }

  subtract(rhs: Fq): Fq {
    return new Fq(this.value - rhs.value);
  }

  multiply(rhs: Fq | bigint): Fq {
    if (rhs instanceof Fq) rhs = rhs.value;
    return new Fq(this.value * rhs);
  }

  div(rhs: Fq | bigint): Fq {
    const inv = typeof rhs === 'bigint' ? new Fq(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }

  toString() {
    const str = this.value.toString(16).padStart(96, '0');
    return str.slice(0, 2) + '.' + str.slice(-2);
  }
}

// Finite field over r.
export class Fr implements Field<Fr> {
  static readonly ORDER = CURVE.r;
  static readonly ZERO = new Fr(0n);
  static readonly ONE = new Fr(1n);

  static isValid(b: bigint): boolean {
    return b <= Fr.ORDER;
  }

  readonly value: bigint;
  constructor(value: bigint) {
    this.value = mod(value, Fr.ORDER);
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
    let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n];
    let a = Fr.ORDER;
    let b = this.value;
    let q;
    while (a !== 0n) {
      [q, b, a] = [b / a, a, b % a];
      [x0, x1] = [x1, x0 - q * x1];
      [y0, y1] = [y1, y0 - q * y1];
    }
    return new Fr(x0);
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
    const inv = typeof rhs === 'bigint' ? new Fr(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }
  legendre(): Fr {
    return this.pow((Fr.ORDER - 1n) / 2n);
  }
  // Tonelli-Shanks algorithm
  sqrt(): Fr | undefined {
    if (!this.legendre().equals(Fr.ONE)) return;
    const P = Fr.ORDER;
    let q, s, z;
    for (q = P - 1n, s = 0; q % 2n == 0n; q /= 2n, s++);
    if (s == 1) return this.pow((P + 1n) / 4n);
    for (z = 2n; z < P && new Fr(z).legendre().value != P - 1n; z++);

    let c = powMod(z, q, P);
    let r = powMod(this.value, (q + 1n) / 2n, P);
    let t = powMod(this.value, q, P);

    let t2 = 0n;
    while (mod(t - 1n, P) != 0n) {
      t2 = mod(t * t, P);
      let i;
      for (i = 1; i < s; i++) {
        if (mod(t2 - 1n, P) == 0n) break;
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

// Abstract class for a field over polynominal.
// TT - ThisType, CT - ChildType, TTT - Tuple Type
abstract class FQP<TT extends { c: TTT } & Field<TT>, CT extends Field<CT>, TTT extends CT[]>
  implements Field<TT> {
  public abstract readonly c: CT[];
  abstract init(c: TTT): TT;
  abstract multiply(rhs: TT | bigint): TT;
  abstract invert(): TT;
  abstract square(): TT;

  zip<T, RT extends T[]>(rhs: TT, mapper: (left: CT, right: CT) => T): RT {
    const c0 = this.c;
    const c1 = rhs.c;
    const res: T[] = [];
    for (let i = 0; i < c0.length; i++) {
      res.push(mapper(c0[i], c1[i]));
    }
    return res as RT;
  }
  map<T, RT extends T[]>(callbackfn: (value: CT) => T): RT {
    return this.c.map(callbackfn) as RT;
  }
  isZero(): boolean {
    return this.c.every((c) => c.isZero());
  }
  equals(rhs: TT): boolean {
    return this.zip(rhs, (left: CT, right: CT) => left.equals(right)).every((r: boolean) => r);
  }
  negate(): TT {
    return this.init(this.map((c) => c.negate()));
  }
  add(rhs: TT): TT {
    return this.init(this.zip(rhs, (left, right) => left.add(right)));
  }
  subtract(rhs: TT) {
    return this.init(this.zip(rhs, (left, right) => left.subtract(right)));
  }
  conjugate() {
    return this.init([this.c[0], this.c[1].negate()] as TTT);
  }
  private one(): TT {
    const el = this;
    let one: unknown;
    if (el instanceof Fq2) one = Fq2.ONE;
    if (el instanceof Fq6) one = Fq6.ONE;
    if (el instanceof Fq12) one = Fq12.ONE;
    return one as TT;
  }
  pow(n: bigint): TT {
    const elm = this as Field<TT>;
    const one = this.one();
    if (n === 0n) return one;
    if (n === 1n) return elm as TT;
    let p = one;
    let d: TT = elm as TT;
    while (n > 0n) {
      if (n & 1n) p = p.multiply(d);
      n >>= 1n;
      d = d.square();
    }
    return p;
  }
  div(rhs: TT | bigint): TT {
    const inv = typeof rhs === 'bigint' ? new Fq(rhs).invert().value : rhs.invert();
    return this.multiply(inv);
  }
}

// For Fq2 roots of unity.
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;

// Finite extension field over irreducible polynominal.
// Fq(u) / (u^2 - β) where β = -1
export class Fq2 extends FQP<Fq2, Fq, [Fq, Fq]> {
  static readonly ORDER = CURVE.P2;
  static readonly MAX_BITS = bitLen(CURVE.P2);
  static readonly ROOT = new Fq(-1n);
  static readonly ZERO = new Fq2([0n, 0n]);
  static readonly ONE = new Fq2([1n, 0n]);
  static readonly COFACTOR = CURVE.h2;
  // Eighth roots of unity, used for computing square roots in Fq2.
  // To verify or re-calculate:
  // Array(8).fill(new Fq2([1n, 1n])).map((fq2, k) => fq2.pow(Fq2.ORDER * BigInt(k) / 8n))
  static readonly ROOTS_OF_UNITY = [
    new Fq2([1n, 0n]),
    new Fq2([rv1, -rv1]),
    new Fq2([0n, 1n]),
    new Fq2([rv1, rv1]),
    new Fq2([-1n, 0n]),
    new Fq2([-rv1, rv1]),
    new Fq2([0n, -1n]),
    new Fq2([-rv1, -rv1]),
  ];
  // eta values, used for computing sqrt(g(X1(t)))
  static readonly ETAs = [
    new Fq2([ev1, ev2]),
    new Fq2([-ev2, ev1]),
    new Fq2([ev3, ev4]),
    new Fq2([-ev4, ev3]),
  ];
  static readonly FROBENIUS_COEFFICIENTS = [
    new Fq(
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n
    ),
    new Fq(
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan
    ),
  ];

  public readonly c: [Fq, Fq];
  constructor(coeffs: [Fq, Fq] | [bigint, bigint] | bigint[]) {
    super();
    if (coeffs.length !== 2) throw new Error(`Expected array with 2 elements`);
    coeffs.forEach((c: any, i: any) => {
      if (typeof c === 'bigint') coeffs[i] = new Fq(c);
    });
    this.c = coeffs as [Fq, Fq];
  }
  init(tuple: [Fq, Fq]) {
    return new Fq2(tuple);
  }
  toString() {
    return `Fq2(${this.c[0]} + ${this.c[1]}×i)`;
  }
  get values(): BigintTuple {
    return this.c.map((c) => c.value) as BigintTuple;
  }

  multiply(rhs: Fq2 | bigint): Fq2 {
    if (typeof rhs === 'bigint')
      return new Fq2(
        this.map<Fq, [Fq, Fq]>((c) => c.multiply(rhs))
      );
    // (a+bi)(c+di) = (ac−bd) + (ad+bc)i
    const [c0, c1] = this.c;
    const [r0, r1] = rhs.c;
    let t1 = c0.multiply(r0); // c0 * o0
    let t2 = c1.multiply(r1); // c1 * o1
    // (T1 - T2) + ((c0 + c1) * (r0 + r1) - (T1 + T2))*i
    return new Fq2([t1.subtract(t2), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2))]);
  }
  // multiply by u + 1
  mulByNonresidue() {
    const c0 = this.c[0];
    const c1 = this.c[1];
    return new Fq2([c0.subtract(c1), c0.add(c1)]);
  }

  square() {
    const c0 = this.c[0];
    const c1 = this.c[1];
    const a = c0.add(c1);
    const b = c0.subtract(c1);
    const c = c0.add(c0);
    return new Fq2([a.multiply(b), c.multiply(c1)]);
  }

  sqrt(): Fq2 | undefined {
    // TODO: Optimize this line. It's extremely slow.
    // Speeding this up would boost aggregateSignatures.
    // https://eprint.iacr.org/2012/685.pdf applicable?
    // https://github.com/zkcrypto/bls12_381/blob/080eaa74ec0e394377caa1ba302c8c121df08b07/src/fp2.rs#L250
    // https://github.com/supranational/blst/blob/aae0c7d70b799ac269ff5edf29d8191dbd357876/src/exp2.c#L1
    // Inspired by https://github.com/dalek-cryptography/curve25519-dalek/blob/17698df9d4c834204f83a3574143abacb4fc81a5/src/field.rs#L99
    const candidateSqrt = this.pow((Fq2.ORDER + 8n) / 16n);
    const check = candidateSqrt.square().div(this);
    const R = Fq2.ROOTS_OF_UNITY;
    const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
    if (!divisor) return;
    const index = R.indexOf(divisor);
    const root = R[index / 2];
    if (!root) throw new Error('Invalid root');
    const x1 = candidateSqrt.div(root);
    const x2 = x1.negate();
    const [re1, im1] = x1.values;
    const [re2, im2] = x2.values;
    if (im1 > im2 || (im1 == im2 && re1 > re2)) return x1;
    return x2;
  }

  // We wish to find the multiplicative inverse of a nonzero
  // element a + bu in Fp2. We leverage an identity
  //
  // (a + bu)(a - bu) = a^2 + b^2
  //
  // which holds because u^2 = -1. This can be rewritten as
  //
  // (a + bu)(a - bu)/(a^2 + b^2) = 1
  //
  // because a^2 + b^2 = 0 has no nonzero solutions for (a, b).
  // This gives that (a - bu)/(a^2 + b^2) is the inverse
  // of (a + bu). Importantly, this can be computing using
  // only a single inversion in Fp.
  invert() {
    const [a, b] = this.values;
    const factor = new Fq(a * a + b * b).invert();
    return new Fq2([factor.multiply(new Fq(a)), factor.multiply(new Fq(-b))]);
  }

  // Raises to q**i -th power
  frobeniusMap(power: number): Fq2 {
    return new Fq2([this.c[0], this.c[1].multiply(Fq2.FROBENIUS_COEFFICIENTS[power % 2])]);
  }
  multiplyByB() {
    let [c0, c1] = this.c;
    let t0 = c0.multiply(4n); // 4 * c0
    let t1 = c1.multiply(4n); // 4 * c1
    // (T0-T1) + (T0+T1)*i
    return new Fq2([t0.subtract(t1), t0.add(t1)]);
  }
}

// Finite extension field over irreducible polynominal.
// Fq2(v) / (v^3 - ξ) where ξ = u + 1
export class Fq6 extends FQP<Fq6, Fq2, [Fq2, Fq2, Fq2]> {
  static readonly ZERO = new Fq6([Fq2.ZERO, Fq2.ZERO, Fq2.ZERO]);
  static readonly ONE = new Fq6([Fq2.ONE, Fq2.ZERO, Fq2.ZERO]);
  static readonly FROBENIUS_COEFFICIENTS_1 = [
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
    ]),
    new Fq2([
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
    ]),
    new Fq2([
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
    ]),
  ];
  static readonly FROBENIUS_COEFFICIENTS_2 = [
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
  ];
  static fromTuple(t: BigintSix): Fq6 {
    return new Fq6([new Fq2(t.slice(0, 2)), new Fq2(t.slice(2, 4)), new Fq2(t.slice(4, 6))]);
  }

  constructor(public readonly c: [Fq2, Fq2, Fq2]) {
    super();
    if (c.length !== 3) throw new Error(`Expected array with 2 elements`);
  }
  init(triple: [Fq2, Fq2, Fq2]) {
    return new Fq6(triple);
  }
  toString() {
    return `Fq6(${this.c[0]} + ${this.c[1]} * v, ${this.c[2]} * v^2)`;
  }
  conjugate(): any {
    throw new TypeError('No conjugate on Fq6');
  }

  multiply(rhs: Fq6 | bigint) {
    if (typeof rhs === 'bigint')
      return new Fq6([this.c[0].multiply(rhs), this.c[1].multiply(rhs), this.c[2].multiply(rhs)]);
    let [c0, c1, c2] = this.c;
    const [r0, r1, r2] = rhs.c;
    let t0 = c0.multiply(r0); // c0 * o0
    let t1 = c1.multiply(r1); // c1 * o1
    let t2 = c2.multiply(r2); // c2 * o2
    return new Fq6([
      // t0 + (c1 + c2) * (r1 * r2) - (T1 + T2) * (u + 1)
      t0.add(c1.add(c2).multiply(r1.add(r2)).subtract(t1.add(t2)).mulByNonresidue()),
      // (c0 + c1) * (r0 + r1) - (T0 + T1) + T2 * (u + 1)
      c0.add(c1).multiply(r0.add(r1)).subtract(t0.add(t1)).add(t2.mulByNonresidue()),
      // T1 + (c0 + c2) * (r0 + r2) - T0 + T2
      t1.add(c0.add(c2).multiply(r0.add(r2)).subtract(t0.add(t2))),
    ]);
  }
  // Multiply by quadratic nonresidue v.
  mulByNonresidue() {
    return new Fq6([this.c[2].mulByNonresidue(), this.c[0], this.c[1]]);
  }
  // Sparse multiplication
  multiplyBy1(b1: Fq2): Fq6 {
    return new Fq6([
      this.c[2].multiply(b1).mulByNonresidue(),
      this.c[0].multiply(b1),
      this.c[1].multiply(b1),
    ]);
  }
  // Sparse multiplication
  multiplyBy01(b0: Fq2, b1: Fq2): Fq6 {
    let [c0, c1, c2] = this.c;
    let t0 = c0.multiply(b0); // c0 * b0
    let t1 = c1.multiply(b1); // c1 * b1
    return new Fq6([
      // ((c1 + c2) * b1 - T1) * (u + 1) + T0
      c1.add(c2).multiply(b1).subtract(t1).mulByNonresidue().add(t0),
      // (b0 + b1) * (c0 + c1) - T0 - T1
      b0.add(b1).multiply(c0.add(c1)).subtract(t0).subtract(t1),
      // (c0 + c2) * b0 - T0 + T1
      c0.add(c2).multiply(b0).subtract(t0).add(t1),
    ]);
  }

  multiplyByFq2(rhs: Fq2): Fq6 {
    return new Fq6(this.map((c) => c.multiply(rhs)));
  }

  square() {
    let [c0, c1, c2] = this.c;
    let t0 = c0.square(); // c0^2
    let t1 = c0.multiply(c1).multiply(2n); // 2 * c0 * c1
    let t3 = c1.multiply(c2).multiply(2n); // 2 * c1 * c2
    let t4 = c2.square(); // c2^2
    return new Fq6([
      t3.mulByNonresidue().add(t0), // T3 * (u + 1) + T0
      t4.mulByNonresidue().add(t1), // T4 * (u + 1) + T1
      // T1 + (c0 - c1 + c2)^2 + T3 - T0 - T4
      t1.add(c0.subtract(c1).add(c2).square()).add(t3).subtract(t0).subtract(t4),
    ]);
  }

  invert() {
    let [c0, c1, c2] = this.c;
    let t0 = c0.square().subtract(c2.multiply(c1).mulByNonresidue()); // c0^2 - c2 * c1 * (u + 1)
    let t1 = c2.square().mulByNonresidue().subtract(c0.multiply(c1)); // c2^2 * (u + 1) - c0 * c1
    let t2 = c1.square().subtract(c0.multiply(c2)); // c1^2 - c0 * c2
    // 1/(((c2 * T1 + c1 * T2) * v) + c0 * T0)
    let t4 = c2.multiply(t1).add(c1.multiply(t2)).mulByNonresidue().add(c0.multiply(t0)).invert();
    return new Fq6([t4.multiply(t0), t4.multiply(t1), t4.multiply(t2)]);
  }
  // Raises to q**i -th power
  frobeniusMap(power: number) {
    return new Fq6([
      this.c[0].frobeniusMap(power),
      this.c[1].frobeniusMap(power).multiply(Fq6.FROBENIUS_COEFFICIENTS_1[power % 6]),
      this.c[2].frobeniusMap(power).multiply(Fq6.FROBENIUS_COEFFICIENTS_2[power % 6]),
    ]);
  }
}

// Finite extension field over irreducible polynominal.
// Fq6(w) / (w2 - γ) where γ = v
export class Fq12 extends FQP<Fq12, Fq6, [Fq6, Fq6]> {
  static readonly ZERO = new Fq12([Fq6.ZERO, Fq6.ZERO]);
  static readonly ONE = new Fq12([Fq6.ONE, Fq6.ZERO]);
  static readonly FROBENIUS_COEFFICIENTS = [
    new Fq2([
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
      0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
    ]),
    new Fq2([
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
      0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
    ]),
    new Fq2([
      0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
      0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
    ]),
    new Fq2([
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
      0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
    ]),
    new Fq2([
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
      0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
    ]),
    new Fq2([
      0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
      0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
    ]),
    new Fq2([
      0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
      0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
    ]),
  ];
  static fromTuple(t: BigintTwelve): Fq12 {
    return new Fq12([
      Fq6.fromTuple(t.slice(0, 6) as BigintSix),
      Fq6.fromTuple(t.slice(6, 12) as BigintSix),
    ]);
  }
  constructor(public readonly c: [Fq6, Fq6]) {
    super();
    if (c.length !== 2) throw new Error(`Expected array with 2 elements`);
  }
  init(c: [Fq6, Fq6]) {
    return new Fq12(c);
  }
  toString() {
    return `Fq12(${this.c[0]} + ${this.c[1]} * w)`;
  }
  multiply(rhs: Fq12 | bigint) {
    if (typeof rhs === 'bigint')
      return new Fq12([this.c[0].multiply(rhs), this.c[1].multiply(rhs)]);
    let [c0, c1] = this.c;
    const [r0, r1] = rhs.c;
    let t1 = c0.multiply(r0); // c0 * r0
    let t2 = c1.multiply(r1); // c1 * r1
    return new Fq12([
      t1.add(t2.mulByNonresidue()), // T1 + T2 * v
      // (c0 + c1) * (r0 + r1) - (T1 + T2)
      c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)),
    ]);
  }
  // Sparse multiplication
  multiplyBy014(o0: Fq2, o1: Fq2, o4: Fq2) {
    let [c0, c1] = this.c;
    let [t0, t1] = [c0.multiplyBy01(o0, o1), c1.multiplyBy1(o4)];
    return new Fq12([
      t1.mulByNonresidue().add(t0), // T1 * v + T0
      // (c1 + c0) * [o0, o1+o4] - T0 - T1
      c1.add(c0).multiplyBy01(o0, o1.add(o4)).subtract(t0).subtract(t1),
    ]);
  }

  multiplyByFq2(rhs: Fq2): Fq12 {
    return this.init(this.map((c) => c.multiplyByFq2(rhs)));
  }

  square() {
    let [c0, c1] = this.c;
    let ab = c0.multiply(c1); // c0 * c1
    return new Fq12([
      // (c1 * v + c0) * (c0 + c1) - AB - AB * v
      c1.mulByNonresidue().add(c0).multiply(c0.add(c1)).subtract(ab).subtract(ab.mulByNonresidue()),
      ab.add(ab),
    ]); // AB + AB
  }

  invert() {
    let [c0, c1] = this.c;
    let t = c0.square().subtract(c1.square().mulByNonresidue()).invert(); // 1 / (c0^2 - c1^2 * v)
    return new Fq12([c0.multiply(t), c1.multiply(t).negate()]); // ((C0 * T) * T) + (-C1 * T) * w
  }
  // Raises to q**i -th power
  frobeniusMap(power: number) {
    const [c0, c1] = this.c;
    let r0 = c0.frobeniusMap(power);
    let [c1_0, c1_1, c1_2] = c1.frobeniusMap(power).c;
    return new Fq12([
      r0,
      new Fq6([
        c1_0.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12]),
        c1_1.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12]),
        c1_2.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12]),
      ]),
    ]);
  }

  private Fq4Square(a: Fq2, b: Fq2): [Fq2, Fq2] {
    const a2 = a.square(),
      b2 = b.square();
    return [
      b2.mulByNonresidue().add(a2), // b^2 * Nonresidue + a^2
      a.add(b).square().subtract(a2).subtract(b2), // (a + b)^2 - a^2 - b^2
    ];
  }

  // https://eprint.iacr.org/2009/565.pdf
  private cyclotomicSquare(): Fq12 {
    const [c0, c1] = this.c;
    const [c0c0, c0c1, c0c2] = c0.c;
    const [c1c0, c1c1, c1c2] = c1.c;
    let [t3, t4] = this.Fq4Square(c0c0, c1c1);
    let [t5, t6] = this.Fq4Square(c1c0, c0c2);
    let [t7, t8] = this.Fq4Square(c0c1, c1c2);
    let t9 = t8.mulByNonresidue(); // T8 * (u + 1)
    return new Fq12([
      new Fq6([
        t3.subtract(c0c0).multiply(2n).add(t3), // 2 * (T3 - c0c0)  + T3
        t5.subtract(c0c1).multiply(2n).add(t5), // 2 * (T5 - c0c1)  + T5
        t7.subtract(c0c2).multiply(2n).add(t7),
      ]), // 2 * (T7 - c0c2)  + T7
      new Fq6([
        t9.add(c1c0).multiply(2n).add(t9), // 2 * (T9 + c1c0) + T9
        t4.add(c1c1).multiply(2n).add(t4), // 2 * (T4 + c1c1) + T4
        t6.add(c1c2).multiply(2n).add(t6),
      ]),
    ]); // 2 * (T6 + c1c2) + T6
  }

  private cyclotomicExp(n: bigint) {
    let z = Fq12.ONE;
    for (let i = BLS_X_LEN - 1; i >= 0; i--) {
      z = z.cyclotomicSquare();
      if (bitGet(n, i)) z = z.multiply(this);
    }
    return z;
  }

  // https://eprint.iacr.org/2010/354.pdf
  // https://eprint.iacr.org/2009/565.pdf
  finalExponentiate() {
    // this^(q^6) / this
    let t0 = this.frobeniusMap(6).div(this);
    // t0^(q^2) * t0
    let t1 = t0.frobeniusMap(2).multiply(t0);
    let t2 = t1.cyclotomicExp(CURVE.x).conjugate();
    let t3 = t1.cyclotomicSquare().conjugate().multiply(t2);
    let t4 = t3.cyclotomicExp(CURVE.x).conjugate();
    let t5 = t4.cyclotomicExp(CURVE.x).conjugate();
    let t6 = t5.cyclotomicExp(CURVE.x).conjugate().multiply(t2.cyclotomicSquare());
    // (t2 * t5)^(q^2) * (t4 * t1)^(q^3) * (t6 * (t1.conj))^(q^1) * (t6^X).conj * t3.conj * t1
    return t2
      .multiply(t5)
      .frobeniusMap(2)
      .multiply(t4.multiply(t1).frobeniusMap(3))
      .multiply(t6.multiply(t1.conjugate()).frobeniusMap(1))
      .multiply(t6.cyclotomicExp(CURVE.x).conjugate())
      .multiply(t3.conjugate())
      .multiply(t1);
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
  getPoint<TT extends this>(x: T, y: T, z: T): TT {
    return new (<any>this.constructor)(x, y, z);
  }

  getZero(): this {
    return this.getPoint(this.C.ONE, this.C.ONE, this.C.ZERO);
  }

  // Compare one point to another.
  equals(rhs: ProjectivePoint<T>) {
    if (this.constructor != rhs.constructor)
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
    return this.getPoint(this.x, this.y.negate(), this.z);
  }

  toString(isAffine = true) {
    if (!isAffine) {
      return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
    }
    const [x, y] = this.toAffine();
    return `Point<x=${x}, y=${y}>`;
  }

  fromAffineTuple(xy: [T, T]): this {
    return this.getPoint(xy[0], xy[1], this.C.ONE);
  }
  // Converts Projective point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  toAffine(invZ: T = this.z.invert()): [T, T] {
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
    return this.getPoint(X3, Y3, Z3);
  }

  // http://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
  // Cost: 12M + 2S + 6add + 1*2.
  add(rhs: this): this {
    if (this.constructor != rhs.constructor)
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
    return this.getPoint(X3, Y3, Z3);
  }

  subtract(rhs: this): this {
    if (this.constructor != rhs.constructor)
      throw new Error(
        `ProjectivePoint#subtract: this is ${this.constructor}, but rhs is ${rhs.constructor}`
      );
    return this.add(rhs.negate());
  }
  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  multiplyUnsafe(scalar: number | bigint | Fq): this {
    let n = scalar;
    if (n instanceof Fq) n = n.value;
    if (typeof n === 'number') n = BigInt(n);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    let p = this.getZero();
    let d: this = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
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

    let [p, f] = [this.getZero(), this.getZero()];
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
  multiply(scalar: number | bigint | Fq): this {
    let n = scalar;
    if (n instanceof Fq) n = n.value;
    if (typeof n === 'number') n = BigInt(n);
    if (n <= 0)
      throw new Error('ProjectivePoint#multiply: invalid scalar, expected positive integer');
    if (bitLen(n) > this.maxBits())
      throw new Error(
        "ProjectivePoint#multiply: scalar has more bits than maxBits, shoulnd't happen"
      );
    return this.wNAF(n)[0];
  }
}

function sgn0(x: Fq2) {
  const [x0, x1] = x.values;
  const sign_0 = x0 % 2n;
  const zero_0 = x0 === 0n;
  const sign_1 = x1 % 2n;
  return BigInt(sign_0 || (zero_0 && sign_1));
}

const P_MINUS_9_DIV_16 = (CURVE.P ** 2n - 9n) / 16n;
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
export function map_to_curve_SSWU_G2(t: bigint[] | Fq2): [Fq2, Fq2, Fq2] {
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

// 3-isogeny map from E' to E
// Converts from Jacobi (xyz) to Projective (xyz) coordinates.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#appendix-C.3
export function isogenyMapG2(xyz: [Fq2, Fq2, Fq2]): [Fq2, Fq2, Fq2] {
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
  return [x2, y2, z2];
}

type EllCoefficients = [Fq2, Fq2, Fq2];

// Pre-compute coefficients for sparse multiplication
// Point addition and point double calculations is reused for coefficients
export function calcPairingPrecomputes(x: Fq2, y: Fq2) {
  //const [x, y] = this.toAffine();
  const [Qx, Qy, Qz] = [x, y, Fq2.ONE];
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
    if (bitGet(CURVE.x, i)) {
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

export function millerLoop(ell: EllCoefficients[], g1: [Fq, Fq]): Fq12 {
  let f12 = Fq12.ONE;
  const [x, y] = g1;
  const [Px, Py] = [x as Fq, y as Fq];
  for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
    f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
    if (bitGet(CURVE.x, i)) {
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

const ut_root = new Fq6([Fq2.ZERO, Fq2.ONE, Fq2.ZERO]);
const wsq = new Fq12([ut_root, Fq6.ZERO]);
const wsq_inv = wsq.invert();
const wcu = new Fq12([Fq6.ZERO, ut_root]);
const wcu_inv = wcu.invert();

export function psi(x: Fq2, y: Fq2): [Fq2, Fq2] {
  //const [x, y] = P.toAffine();
  // Untwist Fq2->Fq12 && frobenius(1) && twist back
  const x2 = wsq_inv.multiplyByFq2(x).frobeniusMap(1).multiply(wsq).c[0].c[0];
  const y2 = wcu_inv.multiplyByFq2(y).frobeniusMap(1).multiply(wcu).c[0].c[0];
  return [x2, y2];
}

// 1 / F2(2)^((p - 1) / 3) in GF(p^2)
const PSI2_C1 = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
export function psi2(x: Fq2, y: Fq2): [Fq2, Fq2] {
  return [x.multiply(PSI2_C1), y.negate()];
}

// Utilities for 3-isogeny map from E' to E.
type Numerators = [Fq2, Fq2, Fq2, Fq2];
const xnum: Numerators = [
  new Fq2([
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
  ]),
  new Fq2([
    0x0n,
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
  ]),
  new Fq2([
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
  ]),
  new Fq2([
    0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
    0x0n,
  ]),
];
const xden: Numerators = [
  new Fq2([
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
  ]),
  new Fq2([
    0xcn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
  ]),
  Fq2.ONE,
  Fq2.ZERO,
];
const ynum: Numerators = [
  new Fq2([
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
  ]),
  new Fq2([
    0x0n,
    0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
  ]),
  new Fq2([
    0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
    0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
  ]),
  new Fq2([
    0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
    0x0n,
  ]),
];
const yden: Numerators = [
  new Fq2([
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
  ]),
  new Fq2([
    0x0n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
  ]),
  new Fq2([
    0x12n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
  ]),
  new Fq2([0x1n, 0x0n]),
];
export const isogenyCoefficients = [xnum, xden, ynum, yden];
