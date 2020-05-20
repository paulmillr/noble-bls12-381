// Group
// Fp: (x, y)
// Fp2: (x1, x2), (y1, y2)
// Fp12

const {getTime} = require('micro-bmark');

export const CURVE = {
  // a characteristic
  P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
  // an order
  r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
  // a cofactor
  h: 0x396c8c005555e1568c00aaab0000aaabn,
  Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
  Gy: 0x8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,

  // G2
  // G^2 - 1
  P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn ** 2n - 1n,
  h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
  G2x: [
    0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
    0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
  ],
  G2y: [
    0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
    0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
  ],
};
const P = CURVE.P;
const DST_LABEL = 'BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN';

type Bytes = Uint8Array | string;
type Hash = Bytes;
type PrivateKey = Bytes | bigint | number;
type Domain = PrivateKey;
type PublicKey = Bytes;
type Signature = Bytes;
type BigintTuple = [bigint, bigint];
// prettier-ignore
export type BigintTwelve = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint
];
type Numerators = [
  Field<BigintTuple>,
  Field<BigintTuple>,
  Field<BigintTuple>,
  Field<BigintTuple>
]
type XDenominators = [
  Field<BigintTuple>,
  Field<BigintTuple>,
  Field<BigintTuple>
]

type ReturnType<T extends Function> = T extends (...args: any[]) => infer R ? R : any;
type IncludedTypes<Base, Type> = {
  [Key in keyof Base]: Base[Key] extends Type ? Key : never;
};
type AllowedNames<Base, Type> = keyof IncludedTypes<Base, Type>;

// Finite field
interface Field<T> {
  readonly value: T;
  isEmpty(): boolean;
  equals(otherValue: Field<T> | T): boolean;
  add(otherValue: Field<T> | T): Field<T>;
  multiply(otherValue: Field<T> | T | bigint): Field<T>;
  div(otherValue: Field<T> | T | bigint): Field<T>;
  square(): Field<T>;
  subtract(otherValue: Field<T> | T): Field<T>;
  negate(): Field<T>;
  invert(): Field<T>;
  pow(n: bigint): Field<T>;
}

function fpToString(num: bigint) {
  const str = num.toString(16).padStart(96, '0');
  return str.slice(0, 4) + '...' + str.slice(-4);
}

// Finite field over P.
export class Fp implements Field<bigint> {
  static readonly ORDER = CURVE.P;
  static readonly ZERO = new Fp(0n);
  static readonly ONE = new Fp(1n);

  private _value: bigint;
  public get value() {
    return this._value;
  }
  constructor(value: bigint) {
    this._value = mod(value, Fp.ORDER);
  }

  normalize(v: Fp | bigint): Fp {
    return v instanceof Fp ? v : new Fp(v);
  }

  isEmpty() {
    return this._value === 0n;
  }

  equals(other: Fp) {
    return this._value === other._value;
  }

  negate() {
    return new Fp(-this._value);
  }

  invert() {
    return new Fp(invert(this._value, Fp.ORDER));
  }

  add(other: Fp) {
    return new Fp(this._value + other.value);
  }

  square() {
    return new Fp(this._value * this._value);
  }

  pow(n: bigint) {
    return new Fp(powMod(this._value, n, Fp.ORDER));
  }

  subtract(other: Fp) {
    return new Fp(this._value - other._value);
  }

  multiply(other: Fp) {
    return new Fp(this._value * other._value);
  }

  div(other: Fp) {
    return this.multiply(other.invert());
  }

  toString() {
    return fpToString(this.value);
  }
}

const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
// Finite extension field over irreducible degree-1 polynominal.
// Fq(u)/(u2 − β) where β = −1
export class Fp2 implements Field<BigintTuple> {
  static ORDER = CURVE.P2;
  static DIV_ORDER = (Fp2.ORDER + 8n) / 16n;
  static ROOT = new Fp(-1n);
  static readonly ZERO = new Fp2(0n, 0n);
  static readonly ONE = new Fp2(1n, 0n);
  private static EIGHTH_ROOTS_OF_UNITY = [
    new Fp2(1n, 0n),
    new Fp2(0n, 1n),
    new Fp2(rv1, rv1),
    new Fp2(rv1, Fp2.ORDER - rv1)
  ];
  public static COFACTOR = CURVE.h2;

  public real: Fp;
  public imag: Fp;

  public get value(): BigintTuple {
    return [this.real.value, this.imag.value];
  }

  constructor(real: Fp | bigint, imag: Fp | bigint) {
    this.real = real instanceof Fp ? real : new Fp(real);
    this.imag = imag instanceof Fp ? imag : new Fp(imag);
  }

  toString() {
    const c1 = this.real.toString();
    const c2 = this.imag.toString();
    return `(${c1} + ${c2}×i)`
  }

  isEmpty() {
    return this.real.isEmpty() && this.imag.isEmpty();
  }

  equals(rhs: Fp2) {
    return this.real.equals(rhs.real) && this.imag.equals(rhs.imag);
  }

  negate() {
    return new Fp2(this.real.negate(), this.imag.negate());
  }

  add(rhs: Fp2) {
    return new Fp2(this.real.add(rhs.real), this.imag.add(rhs.imag));
  }

  subtract(rhs: Fp2) {
    return new Fp2(
      this.real.subtract(rhs.real),
      this.imag.subtract(rhs.imag)
    );
  }

  multiply(rhs: Fp2 | bigint) {
    if (typeof rhs === 'bigint') {
      return new Fp2(this.real.multiply(new Fp(rhs)), this.imag.multiply(new Fp(rhs)));
    }
    // (a+bi)(c+di) = (ac−bd) + (ad+bc)i
    if (this.constructor !== rhs.constructor) throw new TypeError('Types do not match');
    const a1 = [this.real, this.imag];
    const b1 = [rhs.real, rhs.imag];
    const c1 = [Fp.ZERO, Fp.ZERO];
    const embedding = 2;
    // console.log('start', this.toString());

    for (let i = 0; i < embedding; i++) {
      const x = a1[i];
      for (let j = 0; j < embedding; j++) {
        const y = b1[j];
        // console.log('xy', x.toString(), y.toString());

        if (!x.isEmpty() && !y.isEmpty()) {
          const degree = i + j;
          const md = degree % embedding;
          // console.log('xy', md, i, j, x.toString(), y.toString());
          let xy = x.multiply(y);
          const root = Fp2.ROOT;
          if (degree >= embedding) xy = xy.multiply(root);
          c1[md] = c1[md].add(xy);
        }
      }
    }
    const [real, imag] = c1;
    // const a = this.real;
    // const b = this.imag;
    // const c = other.real;
    // const d = other.imag;
    // const real = a.multiply(c).subtract(b.multiply(d).multiply())
    // const imag = a.multiply(d).add(b.multiply(c));
    return new Fp2(real, imag);
  }

  // Multiply a + bu by u + 1, getting
  // au + a + bu^2 + bu
  // and because u^2 = -1, we get
  // (a - b) + (a + b)u
  mulByNonresidue() {
    return new Fp2(
      this.real.subtract(this.imag),
      this.real.add(this.imag)
    );
  }

  // Complex squaring:
  //
  // v0  = c0 * c1
  // c0' = (c0 + c1) * (c0 + β*c1) - v0 - β * v0
  // c1' = 2 * v0
  //
  // In BLS12-381's Fp2, our β is -1 so we
  // can modify this formula:
  //
  // c0' = (c0 + c1) * (c0 - c1)
  // c1' = 2 * c0 * c1
  square() {
    const a = this.real.add(this.imag);
    const b = this.real.subtract(this.imag);
    const c = this.real.add(this.real);
    return new Fp2(a.multiply(b), c.multiply(this.imag));
  }

  sqrt() {
    const candidateSqrt = this.pow(Fp2.DIV_ORDER);
    const check = candidateSqrt.square().div(this);
    const rootIndex = Fp2.EIGHTH_ROOTS_OF_UNITY.findIndex((a) => a.equals(check));
    if (rootIndex === -1 || (rootIndex & 1) === 1) {
      return null;
    }
    const x1 = candidateSqrt.div(Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]);
    const x2 = x1.negate();
    const isImageGreater = x1.imag.value > x2.imag.value;
    const isReconstructedGreater =
      x1.imag.equals(x2.imag) && x1.real.value > x2.real.value;
    return isImageGreater || isReconstructedGreater ? x1 : x2;
  }

  pow(n: bigint): Fp2 {
    if (n === 0n) return Fp2.ONE;
    if (n === 1n) return this;
    let result = new Fp2(1n, 0n);
    let value: Fp2 = this;
    while (n > 0n) {
      if ((n & 1n) === 1n) {
        result = result.multiply(value);
      }
      n >>= 1n;
      value = value.square();
    }
    return result;
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
    const t = this.real.square().add(this.imag.square()).invert();
    return new Fp2(this.real.multiply(t), this.imag.multiply(t.negate()));
  }

  div(otherValue: Fp2) {
    if (typeof otherValue === 'bigint') {
      return new Fp2(this.real.div(otherValue), this.imag.div(otherValue));
    }
    return this.multiply(otherValue.invert());
  }
}

// prettier-ignore
const FP12_DEFAULT: BigintTwelve = [
  0n, 1n, 0n, 1n,
  0n, 1n, 0n, 1n,
  0n, 1n, 0n, 1n
];
type Fp12Like = Fp12 | BigintTwelve;
type FpTwelve = [Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp];
//Finite extension field.
// This represents an element c0 + c1 * w of Fp12 = Fp6 / w^2 - v.
export class Fp12 implements Field<BigintTwelve> {
  static readonly ZERO = new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  // static ZERO() {
  //   return new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  // }
  static readonly ONE = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  private coefficients: FpTwelve = FP12_DEFAULT.map((a) => new Fp(a)) as FpTwelve;
  // prettier-ignore
  private static readonly MODULE_COEFFICIENTS: BigintTwelve = [
    2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
  ];
  private static readonly ENTRY_COEFFICIENTS: Array<[number, bigint]> = [
    [0, 2n],
    [6, -2n],
  ];

  public get value() {
    return this.coefficients.map((c) => c.value) as BigintTwelve;
  }

  constructor();
  // prettier-ignore
  constructor(
    c0: Fp, c1: Fp, c2: Fp, c3: Fp,
    c4: Fp, c5: Fp, c6: Fp, c7: Fp,
    c8: Fp, c9: Fp, c10: Fp, c11: Fp
  );
  // prettier-ignore
  constructor(
    c0: bigint, c1: bigint, c2: bigint, c3: bigint,
    c4: bigint, c5: bigint, c6: bigint, c7: bigint,
    c8: bigint, c9: bigint, c10: bigint, c11: bigint
  );
  constructor(...args: [] | BigintTwelve | FpTwelve) {
    args = args.length === 0 ? FP12_DEFAULT : (args.slice(0, 12) as BigintTwelve);
    // @ts-ignore stupid TS
    // prettier-ignore
    this.coefficients = args[0] instanceof Fp ? args : (args.map(a => new Fp(a)) as FpTwelve);
  }

  public normalize(v: Fp12Like | bigint) {
    if (typeof v === 'bigint') {
      return v;
    }
    return v instanceof Fp12 ? v : new Fp12(...v);
  }

  isEmpty() {
    return this.coefficients.every((a) => a.isEmpty());
  }

  equals(rhs: Fp12Like) {
    return this.coefficients.every((a, i) => a.equals((rhs as Fp12).coefficients[i]));
  }

  negate() {
    return new Fp12(...(this.coefficients.map((a) => a.negate()) as FpTwelve));
  }

  add(rhs: Fp12Like) {
    return new Fp12(
      ...(this.coefficients.map((a, i) => a.add((rhs as Fp12).coefficients[i])) as FpTwelve)
    );
  }

  subtract(rhs: Fp12Like) {
    return new Fp12(
      ...(this.coefficients.map((a, i) => a.subtract((rhs as Fp12).coefficients[i])) as FpTwelve)
    );
  }

  multiply(otherValue: Fp12Like | bigint) {
    if (typeof otherValue === 'bigint') {
      return new Fp12(...(this.coefficients.map((a) => a.multiply(new Fp(otherValue))) as FpTwelve));
    }
    const LENGTH = this.coefficients.length;

    const filler = Array(LENGTH * 2 - 1)
      .fill(null)
      .map(() => new Fp(0n));
    for (let i = 0; i < LENGTH; i++) {
      for (let j = 0; j < LENGTH; j++) {
        filler[i + j] = filler[i + j].add(
          this.coefficients[i].multiply((otherValue as Fp12).coefficients[j])
        );
      }
    }
    for (let exp = LENGTH - 2; exp >= 0; exp--) {
      const top = filler.pop();
      if (top === undefined) {
        break;
      }
      for (const [i, value] of Fp12.ENTRY_COEFFICIENTS) {
        filler[exp + i] = filler[exp + i].subtract(top.multiply(new Fp(value)));
      }
    }
    return new Fp12(...(filler as FpTwelve));
  }

  square() {
    return this.multiply(this);
  }

  pow(n: bigint): Fp12 {
    if (n === 1n) {
      return this;
    }
    let result = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    let value: Fp12 = this;
    while (n > 0n) {
      if ((n & 1n) === 1n) {
        result = result.multiply(value);
      }
      n >>= 1n;
      value = value.square();
    }
    return result;
  }

  private degree(nums: bigint[]) {
    let degree = nums.length - 1;
    while (nums[degree] === 0n && degree !== 0) {
      degree--;
    }
    return degree;
  }

  private primeNumberInvariant(num: bigint) {
    return new Fp(num).invert().value;
  }

  private optimizedRoundedDiv(coefficients: bigint[], others: bigint[]) {
    const tmp = [...coefficients];
    const degreeThis = this.degree(tmp);
    const degreeOthers = this.degree(others);
    const zeros = Array.from(tmp).fill(0n);
    const edgeInvariant = this.primeNumberInvariant(others[degreeOthers]);
    for (let i = degreeThis - degreeOthers; i >= 0; i--) {
      zeros[i] = zeros[i] + tmp[degreeOthers + i] * edgeInvariant;
      for (let c = 0; c < degreeOthers; c++) {
        tmp[c + i] = tmp[c + i] - zeros[c];
      }
    }
    return new Fp12(...(zeros.slice(0, this.degree(zeros) + 1) as BigintTwelve));
  }

  invert(): Fp12 {
    const LENGTH = this.coefficients.length;
    let lm = [...Fp12.ONE.coefficients.map((a) => a.value), 0n];
    let hm = [...Fp12.ZERO.coefficients.map((a) => a.value), 0n];
    let low = [...this.coefficients.map((a) => a.value), 0n];
    let high = [...Fp12.MODULE_COEFFICIENTS, 1n];
    while (this.degree(low) !== 0) {
      const { coefficients } = this.optimizedRoundedDiv(high, low);
      const zeros = Array(LENGTH + 1 - coefficients.length)
        .fill(null)
        .map(() => new Fp(0n));
      const roundedDiv = coefficients.concat(zeros);
      let nm = [...hm];
      let nw = [...high];
      for (let i = 0; i <= LENGTH; i++) {
        for (let j = 0; j <= LENGTH - i; j++) {
          nm[i + j] -= lm[i] * roundedDiv[j].value;
          nw[i + j] -= low[i] * roundedDiv[j].value;
        }
      }
      nm = nm.map((a) => new Fp(a).value);
      nw = nw.map((a) => new Fp(a).value);
      hm = lm;
      lm = nm;
      high = low;
      low = nw;
    }
    const result = new Fp12(...(lm as BigintTwelve));
    return result.div(low[0]);
  }

  div(otherValue: Fp12 | bigint) {
    if (typeof otherValue === 'bigint') {
      return new Fp12(...(this.coefficients.map((a) => a.div(new Fp(otherValue))) as FpTwelve));
    }
    return this.multiply(otherValue.invert());
  }
}

type Constructor<T> = { new (...args: any[]): Field<T> } & {ZERO: Field<T>; ONE: Field<T>;};
type GroupCoordinats<T> = { x: Field<T>; y: Field<T>; z: Field<T> };
// type Constructorzz<T> = Function & T & { prototype: T }
// type Constructor<T extends {} = {}> = new (...args: any[]) => T;

export class Point<T> {
  // "Twist" a point in E(Fp2) into a point in E(Fp12)
  public static get W() {
    return new Fp12(0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  }
  public static get W_SQUARE() {
    return new Fp12(0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  }
  public static get W_CUBE() {
    return new Fp12(0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  }

  constructor(
    public x: Field<T>,
    public y: Field<T>,
    public z: Field<T>,
    public C: Constructor<T>
  ) {}

  isEmpty() {
    return this.x.isEmpty() && this.y.isEmpty() && this.z.equals(this.C.ONE);
  }

  // Fast subgroup checks via Bowe19
  isOnCurve(b: Field<T>) {
    if (this.isEmpty()) {
      return true;
    }
    const squaredY = this.y.square();
    const cubedX = this.x.pow(3n);
    const z6 = this.z.pow(6n);
    const infty = this.x.isEmpty() && !this.y.isEmpty() && this.z.isEmpty();
    const match = squaredY.equals(b.multiply(z6).add(cubedX));
    return infty || match;
    // Check that a point is on the curve defined by y**2 * z - x**3 == b * z**3
    // const lefSide = this.y.square().multiply(this.z).subtract(this.x.pow(3n));
    // const rightSide = b.multiply(this.z.pow(3n));
    // return lefSide.equals(rightSide);
  }

  equals(other: Point<T>) {
    // x1 * z2 == x2 * z1 and y1 * z2 == y2 * z1
    return (
      this.x.multiply(other.z).equals(other.x.multiply(this.z)) &&
      this.y.multiply(other.z).equals(other.y.multiply(this.z))
    );
  }

  negative() {
    return new Point(this.x, this.y.negate(), this.z, this.C);
  }

  toString() {
    const [x, y] = this.toAffine();
    return `Point<x=${x}, y=${y}>`
  }

  toAffine() {
    // return [this.x.div(this.z), this.y.div(this.z)];
    const zInv = this.z.pow(3n).invert();
    return [this.x.multiply(this.z).multiply(zInv), this.y.multiply(zInv)];
  }

  double() {
    if (this.isEmpty()) return this;
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const A = X1.square();
    const B = Y1.square();
    const C = B.square();
    const D = X1.add(B).square().subtract(A).subtract(C).multiply(2n);
    const E = A.multiply(3n);
    const F = E.square();
    const X3 = F.subtract(D.multiply(2n));
    const Y3 = E.multiply((D.subtract(X3)).subtract(C.multiply(8n)));
    const Z3 = Y1.multiply(Z1).multiply(2n);
    if (Z3.isEmpty()) return new Point(this.C.ZERO, this.C.ONE, this.C.ZERO, this.C);
    return new Point(X3, Y3, Z3, this.C);
  }

  // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-1998-cmo-2
  add(other: Point<T>): Point<T> {
    if (!(other instanceof Point)) throw new TypeError('Point#add: expected Point');
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const X2 = other.x;
    const Y2 = other.y;
    const Z2 = other.z;
    if (Z2.isEmpty()) return this;
    if (Z1.isEmpty()) return other;
    const Z1Z1 = Z1.pow(2n);
    const Z2Z2 = Z2.pow(2n);
    const U1 = X1.multiply(Z2Z2);
    const U2 = X2.multiply(Z1Z1);
    const S1 = Y1.multiply(Z2).multiply(Z2Z2);
    const S2 = Y2.multiply(Z1).multiply(Z1Z1);
    const H = U2.subtract(U1);
    const rr = S2.subtract(S1).multiply(2n);
    // H = 0 meaning it's the same point.
    if (H.isEmpty()) {
      if (rr.isEmpty()) {
        //console.log('dbl');
        return this.double();
      } else {
        throw new Error()
        return new Point(this.C.ZERO, this.C.ZERO, this.C.ONE, this.C);
      }
    }
    const I = H.multiply(2n).pow(2n);
    const J = H.multiply(I);
    const V = U1.multiply(I);
    const X3 = rr.pow(2n).subtract(J).subtract(V.multiply(2n));
    const Y3 = rr.multiply(V.subtract(X3)).subtract(S1.multiply(J).multiply(2n));
    const Z3 = Z1.multiply(Z2).multiply(H).multiply(2n);
    // console.log(`xxx ${rr.pow(2n)} ${J.subtract(V.multiply(2n))}`);
    // console.log(`rrjv, ${rr} ${J} ${V}`);
    // console.log(`xyz, ${X3} ${Y3} ${Z3}`);
    return new Point(X3, Y3, Z3, this.C);
  }

  subtract(other: Point<T>) {
    return this.add(other.negative());
  }

  multiply(n: number | bigint) {
    n = BigInt(n);
    this.C.prototype
    let result = new Point(this.C.ONE, this.C.ONE, this.C.ZERO, this.C);
    let point = this as Point<T>;
    while (n > 0n) {
      if ((n & 1n) === 1n) {
        result = result.add(point);
      }
      point = point.double();
      n >>= 1n;
    }
    return result;
  }

  // Field isomorphism from z[p] / x**2 to z[p] / x**2 - 2*x + 2
  twist() {
    // Prevent twisting of non-multidimensional type
    if (!Array.isArray(this.x.value)) {
      return new Point(new Fp12(), new Fp12(), new Fp12(), Fp12);
    }
    // @ts-ignore stupid TS
    const { x, y, z }: GroupCoordinats<BigintTuple | BigintTwelve> = this;
    const [cx1, cx2] = [x.value[0] - x.value[1], x.value[1]];
    const [cy1, cy2] = [y.value[0] - y.value[1], y.value[1]];
    const [cz1, cz2] = [z.value[0] - z.value[1], z.value[1]];
    const newX = new Fp12(cx1, 0n, 0n, 0n, 0n, 0n, cx2, 0n, 0n, 0n, 0n, 0n);
    const newY = new Fp12(cy1, 0n, 0n, 0n, 0n, 0n, cy2, 0n, 0n, 0n, 0n, 0n);
    const newZ = new Fp12(cz1, 0n, 0n, 0n, 0n, 0n, cz2, 0n, 0n, 0n, 0n, 0n);
    return new Point(newX.div(Point.W_SQUARE), newY.div(Point.W_CUBE), newZ, Fp12);
  }
}

  // Isogeny map evaluation specified by map_coeffs
  // map_coeffs should be specified as (xnum, xden, ynum, yden)
  // This function evaluates the isogeny over Jacobian projective coordinates.
  // For details, see Section 4.3 of
  // Wahby and Boneh, "Fast and simple constant-time hashing to the BLS12-381 elliptic curve."
  // ePrint # 2019/403, https://ia.cr/2019/403.
function evalIsogeny(p: Point<BigintTuple>, coefficients: [Numerators, XDenominators, Numerators, Numerators]) {
    const {x, y, z} = p;
    const vals = new Array(4);

    // precompute the required powers of Z^2
    const maxOrd = Math.max(...coefficients.map(a => a.length));
    const zPowers = new Array(maxOrd);
    zPowers[0] = z.pow(0n);
    zPowers[1] = z.pow(2n);
    for (let i = 2; i < maxOrd; i++) {
      zPowers[i] = zPowers[i - 1].multiply(zPowers[1]);
    }
    for (let i = 0; i < coefficients.length; i++) {
      const coeff = Array.from(coefficients[i]).reverse();
      const coeffsZ = coeff.map((c, i) => c.multiply(zPowers[i]));
      let tmp = coeffsZ[0];
      for (let j = 1; j < coeffsZ.length; j++) {
        tmp = tmp.multiply(x).add(coeffsZ[j]);
      }
      vals[i] = tmp;
    }

    vals[1] = vals[1].multiply(zPowers[1]);
    vals[2] = vals[2].multiply(y);
    vals[3] = vals[3].multiply(z.pow(3n));

    const z2 = vals[1].multiply(vals[3]);
    const x2 = vals[0].multiply(vals[3]).multiply(z2);
    const y2 = vals[2].multiply(vals[1]).multiply(z2.square());

    return new Point(x2, y2, z2, p.C);
  }

// https://eprint.iacr.org/2019/403.pdf
// 2.1 The BLS12-381 elliptic curve
// q =  z**4 − z**2 + 1
// p = z + (z**4 − z**2 + 1) * (z − 1)**2 / 3
function finalExponentiate(p: Field<BigintTwelve>) {
  return p.pow((CURVE.P ** 12n - 1n) / CURVE.r);
}

// Curve is y**2 = x**3 + 4
export const B = new Fp(4n);
// Twisted curve over Fp2
export const B2 = new Fp2(4n, 4n);
// Extension curve over Fp12; same b value as over Fp
export const B12 = new Fp12(4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);

const Z1 = new Point(new Fp(1n), new Fp(1n), new Fp(0n), Fp);
const Z2 = new Point(new Fp2(1n, 0n), new Fp2(1n, 0n), new Fp2(0n, 0n), Fp2);

const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
const P_ORDER_X_9 = (P ** 2n - 9n) / 16n;

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

async function sha256(message: Uint8Array): Promise<Uint8Array> {
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
}

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

function mod(a: bigint, b: bigint) {
  const res = a % b;
  return res >= 0n ? res : b + res;
}

function powMod(a: bigint, power: bigint, m: bigint) {
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

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
function egcd(a: bigint, b: bigint) {
  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a !== 0n) {
    let q = b / a;
    let r = b % a;
    let m = x - u * q;
    let n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  let gcd = b;
  return [gcd, x, y];
}

function invert(number: bigint, modulo: bigint) {
  if (number === 0n || modulo <= 0n) {
    throw new Error('invert: expected positive integers');
  }
  let [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('invert: does not exist');
  }
  return mod(x, modulo);
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

function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}

async function expand_message_xmd(msg: Uint8Array, DST: Uint8Array, len_in_bytes: number): Promise<Uint8Array> {
  const H = sha256;
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
    const args = [
      strxor(b_0, b[i - 1]),
      i2osp(i + 1, 1),
      DST_prime
    ];
    b[i] = await H(concatTypedArrays(...args));
  }
  const pseudo_random_bytes = concatTypedArrays(...b);
  return pseudo_random_bytes.slice(0, len_in_bytes);
}

const toHex = (n: Uint8Array | (string | number | bigint)[] | bigint) => {
  if (typeof n === 'bigint') return n.toString(16);
  if (n instanceof Uint8Array) n = Array.from(n);
  return n.map((item: string | number | bigint) => {
    return typeof item === 'string' ? item : item.toString(16)
  }).join('');
}

export async function hash_to_field(msg: Uint8Array, count: number): Promise<bigint[][]> {
  const m = 2; // degree, 1 for Fp, 2 for Fp2
  const L = 64; // 64 for sha2, shake, sha3, blake
  const len_in_bytes = count * m * L;
  const DST = stringToBytes(DST_LABEL);
  const pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes);
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const e = new Array(m);
    for (let j = 0; j < m; j++) {
      const elm_offset = L * (j + i * m)
      const tv = pseudo_random_bytes.slice(elm_offset, elm_offset + L);
      e[j] = mod(os2ip(tv), CURVE.P);
    }
    u[i] = e;
  }
  return u;
}

export async function thash_to_curve(msg: Uint8Array): Promise<Point<BigintTuple>> {
  const [tuple1, tuple2] = await hash_to_field(msg, 2);
  const t1 = new Fp2(tuple1[0], tuple1[1]);
  const t2 = new Fp2(tuple2[0], tuple2[1]);
  return opt_swu2_map(t1, t2);
}
//   const u = await hash_to_field(msg, 2);
//   const Q0 = map_to_curve(u[0]);
//   const Q1 = map_to_curve(u[1]);
//   const R = Q0.add(Q1);
//   const P = clear_cofactor(R);
//   return P

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
  return sign === 0n ? 1n : sign;
}

const Ell2p_a = new Fp2(0n, 240n);
const Ell2p_b = new Fp2(1012n, 1012n);
const xi_2 = new Fp2(-2n, -1n);
// roots of unity, used for computing square roots in Fp2
//const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const rootsOfUnity = [
  new Fp2(1n, 0n),
  new Fp2(0n, 1n),
  new Fp2(rv1, rv1),
  new Fp2(rv1, -rv1)
];
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n
const etas = [
  new Fp2(ev1, ev2),
  new Fp2(-ev2, ev1),
  new Fp2(ev3, ev4),
  new Fp2(-ev4, ev3)
];

function osswu2_help(t: Fp2) {
  console.log('osswu2_help', t.toString());
  // first, compute X0(t), detecting and handling exceptional case
  const denominator = xi_2.square()
    .multiply(t.pow(4n))
    .add(xi_2.multiply(t.square()));
  const x0_num = Ell2p_b.multiply(denominator.add(Fp2.ONE));
  const tmp = Ell2p_a.negate().multiply(denominator);
  const x0_den = tmp.equals(Fp2.ZERO) ? Ell2p_a.multiply(xi_2) : tmp;

  console.log('x0_den', denominator.toString(), x0_den.toString());

  // compute num and den of g(X0(t))
  const gx0_den = x0_den.pow(3n);
  const gx0_num = Ell2p_b.multiply(gx0_den)
    .add(Ell2p_a.multiply(x0_num).multiply(x0_den.square()))
    .add(x0_num.pow(3n));

  // try taking sqrt of g(X0(t))
  // this uses the trick for combining division and sqrt from Section 5 of
  // Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures."
  // J Crypt Eng 2(2):77--89, Sept. 2012. http://ed25519.cr.yp.to/ed25519-20110926.pdf
  let tmp1 = gx0_den.pow(7n);
  let tmp2 = gx0_num.multiply(tmp1);
  tmp1 = tmp1.multiply(tmp2).multiply(gx0_den);
  let sqrt_candidate = tmp2.multiply(tmp1.pow(P_ORDER_X_9));

  //console.log('sqrt_candidate', sqrt_candidate.toString());

  // check if g(X0(t)) is square and return the sqrt if so
  for (const root of rootsOfUnity) {
    let y0 = sqrt_candidate.multiply(root);
    if (y0.square().multiply(gx0_den).equals(gx0_num)) {
      y0 = y0.multiply(sign0(y0) * sign0(t));
      //console.log('sqrt 1', y0.toString(), t.toString(), sign0(y0), sign0(t));
      return new Point<BigintTuple>(
        x0_num.multiply(x0_den),
        y0.multiply(x0_den.pow(3n)),
        x0_den,
        Fp2
      );
    }
  }

  // if we've gotten here, then g(X0(t)) is not square. convert srqt_candidate to sqrt(g(X1(t)))
  const x1_num = xi_2.multiply(t.square()).multiply(x0_num);
  const x1_den = x0_den;
  const gx1_num = xi_2.pow(3n)
    .multiply(t.pow(6n))
    .multiply(gx0_num);
  const gx1_den = gx0_den;
  sqrt_candidate = sqrt_candidate.multiply(t.pow(3n));

  for (const eta of etas) {
    const y1 = sqrt_candidate.multiply(eta);
    const candidate = y1.square().multiply(gx1_den);
    if (candidate.equals(gx1_num)) {
      // found sqrt(g(X1(t))). force sign of y to equal sign of t
      const y = y1.multiply(sign0(y1) * sign0(t));
      console.log('sqrt 2');

      return new Point(
        x1_num.multiply(x1_den),
        y.multiply(x1_den.pow(3n)),
        x1_den,
        Fp2
      );
    }
  }

  throw new Error("osswu2help failed for unknown reasons!");
}

// 3-Isogeny from Ell2' to Ell2
// coefficients for the 3-isogeny map from Ell2' to Ell2

const xnum: Numerators = [
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

const xden: XDenominators = [
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
const ynum: Numerators = [
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
const yden: Numerators = [
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
  //console.log('preiso', p.toString());
  return evalIsogeny(p, [xnum, xden, ynum, yden]);
}

function frobenius(x: Fp2): Fp2 {
  return new Fp2(x.real, x.imag.negate());
}

function psi(xn: Fp2, xd: Fp2, yn: Fp2, yd: Fp2) {
  const c1 = Fp2.ONE.pow((CURVE.P - 1n) / 3n).invert();
  const c2 = Fp2.ONE.pow((CURVE.P - 1n) / 2n).invert();
  const P = isogenyPoint;
  const qxn = c1.multiply(frobenius(xn));
  const qxd = frobenius(xd);
  const qyn = c2.multiply(frobenius(yn));
  const qyd = frobenius(yd);
  return [qxn, qxd, qyn, qyd];
}

function clear_cofactor_bls12381_g2(point: Point<BigintTuple>) {
  const c1 = new Fp(-15132376222941642752n).value;
  const P = point;
  const t1 = P.multiply(c1);
  let t2 = psi(P);
  let t3 = P.multiply(2);
  t3 = psi(psi(t3));
  t3 = t3.subtract(t2);
  t2 = t1.add(t2);
  t2 = t2.multiply(c1);
  t3 = t3.add(t2);
  t3 = t3.subtract(t1);
  const Q = t3.subtract(P);
  return Q;
}

// map from Fp2 element(s) to point in G2 subgroup of Ell2
function opt_swu2_map(u1: Fp2, u2?: Fp2) {
  console.log('opt_swu2_map');
  console.log('u1=', u1.toString());
  console.log('u2=', u2?.toString());

  let point = osswu2_help(u1);
  if (u2 instanceof Fp2) {
    const point2 = osswu2_help(u2);
    console.log('preiso', point.toString(), point2.toString());
    point = point.add(point2);
    console.log('preiso2', point.toString());
  }
  const iso = computeIsogeny3(point);
  console.log(`iso ${iso}`);

  return clear_cofactor_bls12381_g2(iso);
}

const POW_SUM = POW_2_383 + POW_2_382;

function compressG1(point: Point<bigint>) {
  if (point.equals(Z1)) {
    return POW_SUM;
  }
  const [x, y] = point.toAffine() as [Fp, Fp];
  const flag = (y.value * 2n) / P;
  return x.value + flag * POW_2_381 + POW_2_383;
}

const PART_OF_P = (CURVE.P + 1n) / 4n;

function decompressG1(compressedValue: bigint) {
  const bflag = (compressedValue % POW_2_383) / POW_2_382;
  if (bflag === 1n) {
    return Z1;
  }
  const x = compressedValue % POW_2_381;
  const fullY = (x ** 3n + B.value) % P;
  let y = powMod(fullY, PART_OF_P, P);
  if (powMod(y, 2n, P) !== fullY) {
    throw new Error('The given point is not on G1: y**2 = x**3 + b');
  }
  const aflag = (compressedValue % POW_2_382) / POW_2_381;
  if ((y * 2n) / P !== aflag) {
    y = P - y;
  }
  return new Point(new Fp(x), new Fp(y), new Fp(1n), Fp);
}

function compressG2(point: Point<BigintTuple>) {
  if (point.equals(Z2)) {
    return [POW_2_383 + POW_2_382, 0n];
  }
  if (!point.isOnCurve(B2)) {
    throw new Error('The given point is not on the twisted curve over FQ**2');
  }
  const [[x0, x1], [y0, y1]] = point.toAffine().map((a) => a.value);
  const producer = y1 > 0 ? y1 : y0;
  const aflag1 = (producer * 2n) / P;
  const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
  const z2 = x0;
  return [z1, z2];
}

function decompressG2([z1, z2]: BigintTuple) {
  const bflag1 = (z1 % POW_2_383) / POW_2_382;
  if (bflag1 === 1n) {
    return Z2;
  }
  const x = new Fp2(z2, z1 % POW_2_381);
  let y = x.pow(3n).add(B2).sqrt();
  if (y === null) {
    throw new Error('Failed to find a modular squareroot');
  }
  const [y0, y1] = y.value;
  const aflag1 = (z1 % POW_2_382) / POW_2_381;
  const isGreaterCoefficient = y1 > 0 && (y1 * 2n) / P !== aflag1;
  const isZeroCoefficient = y1 === 0n && (y0 * 2n) / P !== aflag1;
  if (isGreaterCoefficient || isZeroCoefficient) {
    y = y.multiply(-1n);
  }
  const point = new Point(x, y, Fp2.ONE, Fp2);
  if (!point.isOnCurve(B2)) {
    throw new Error('The given point is not on the twisted curve over Fp2');
  }
  return point;
}

function publicKeyFromG1(point: Point<bigint>) {
  return toBytesBE(compressG1(point), PUBLIC_KEY_LENGTH);
}

function publicKeyToG1(publicKey: Bytes) {
  return decompressG1(fromBytesBE(publicKey));
}

function signatureFromG2(point: Point<BigintTuple>) {
  const [z1, z2] = compressG2(point);
  return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
}

export function signatureToG2(signature: Bytes) {
  const halfSignature = signature.length / 2;
  const z1 = fromBytesBE(signature.slice(0, halfSignature));
  const z2 = fromBytesBE(signature.slice(halfSignature));
  return decompressG2([z1, z2]);
}

export async function hashToG2(hash: Hash, domain: Bytes): Promise<Point<BigintTuple>> {
  // @ts-ignore
  return new Uint8Array([hash as number, domain as number]);
}

// ## Fixed Generators
// Although any generator produced by hashing to $\mathbb{G}_1$ or $\mathbb{G}_2$ is
// safe to use in a cryptographic protocol, we specify some simple, fixed generators.
//
// In order to derive these generators, we select the lexicographically smallest
// valid $x$-coordinate and the lexicographically smallest corresponding $y$-coordinate,
// and then scale the resulting point by the cofactor, such that the result is not the
// identity. This results in the following fixed generators:

// Generator for curve over Fp
export const G1 = new Point(new Fp(CURVE.Gx), new Fp(CURVE.Gy), Fp.ONE, Fp);

// Generator for twisted curve over Fp2
export const G2 = new Point(
  new Fp2(CURVE.G2x[0], CURVE.G2x[1]),
  new Fp2(CURVE.G2y[0], CURVE.G2y[1]),
  Fp2.ONE,
  Fp2
);
// Create a function representing the line between P1 and P2, and evaluate it at T
// and evaluate it at T. Returns a numerator and a denominator
// to avoid unneeded divisions
function createLineBetween<T>(p1: Point<T>, p2: Point<T>, n: Point<T>) {
  let mNumerator = p2.y.multiply(p1.z).subtract(p1.y.multiply(p2.z));
  let mDenominator = p2.x.multiply(p1.z).subtract(p1.x.multiply(p2.z));
  if (!mNumerator.isEmpty() && mDenominator.isEmpty()) {
    return [n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)), p1.z.multiply(n.z)];
  } else if (mNumerator.isEmpty()) {
    mNumerator = p1.x.square().multiply(3n);
    mDenominator = p1.y.multiply(p1.z).multiply(2n);
  }
  const numeratorLine = mNumerator.multiply(n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)));
  const denominatorLine = mDenominator.multiply(n.y.multiply(p1.z).subtract(p1.y.multiply(n.z)));
  const z = mDenominator.multiply(n.z).multiply(p1.z);
  return [numeratorLine.subtract(denominatorLine), z];
}

function castPointToFp12(pt: Point<bigint>): Point<BigintTwelve> {
  if (pt.isEmpty()) {
    return new Point(new Fp12(), new Fp12(), new Fp12(), Fp12);
  }
  return new Point(
    new Fp12((pt.x as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    new Fp12((pt.y as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    new Fp12((pt.z as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    Fp12
  );
}

// prettier-ignore
const PSEUDO_BINARY_ENCODING = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];

// Main miller loop
function millerLoop(
  Q: Point<BigintTwelve>,
  P: Point<BigintTwelve>,
  withFinalExponent: boolean = false
) {
  // prettier-ignore
  const one: Field<BigintTwelve> = new Fp12(
    1n, 0n, 0n, 0n,
    0n, 0n, 0n, 0n,
    0n, 0n, 0n, 0n
  );
  if (Q.isEmpty() || P.isEmpty()) {
    return one;
  }
  let R = Q;
  let fNumerator = one;
  let fDenominator = one;
  for (let i = PSEUDO_BINARY_ENCODING.length - 2; i >= 0n; i--) {
    const [n, d] = createLineBetween(R, R, P);
    fNumerator = fNumerator.square().multiply(n);
    fDenominator = fDenominator.square().multiply(d);
    R = R.double();
    if (PSEUDO_BINARY_ENCODING[i] === 1) {
      const [n, d] = createLineBetween(R, Q, P);
      fNumerator = fNumerator.multiply(n);
      fDenominator = fDenominator.multiply(d);
      R = R.add(Q);
    }
  }
  const f = fNumerator.div(fDenominator);
  return withFinalExponent ? finalExponentiate(f) : f;
}

export function pairing(
  Q: Point<BigintTuple>,
  P: Point<bigint>,
  withFinalExponent: boolean = true
) {
  if (!Q.isOnCurve(B2)) throw new Error("Point 1 is not on curve");
  if (!P.isOnCurve(B)) throw new Error("Point 2 is not on curve");
  return millerLoop(Q.twist(), castPointToFp12(P), withFinalExponent);
}

export function getPublicKey(privateKey: PrivateKey) {
  privateKey = toBigInt(privateKey);
  return publicKeyFromG1(G1.multiply(privateKey));
}

const DOMAIN_LENGTH = 8;

export async function sign(message: Hash, privateKey: PrivateKey, domain: Domain) {
  domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  privateKey = toBigInt(privateKey);
  const messageValue = await hashToG2(message, domain);
  // @ts-ignore
  const signature = messageValue.multiply(privateKey);
  return signatureFromG2(signature);
}

export async function verify(
  message: Hash,
  publicKey: PublicKey,
  signature: Signature,
  domain: Domain
) {
  domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  const publicKeyPoint = publicKeyToG1(publicKey).negative();
  const signaturePoint = signatureToG2(signature);
  try {
    const signaturePairing = pairing(signaturePoint, G1);
    // @ts-ignore
    const hashPairing = pairing(await hashToG2(message, domain), publicKeyPoint);
    const finalExponent = finalExponentiate(signaturePairing.multiply(hashPairing));
    return finalExponent.equals(Fp12.ONE);
  } catch {
    return false;
  }
}

export function aggregatePublicKeys(publicKeys: PublicKey[]) {
  if (publicKeys.length === 0) throw new Error('Expected non-empty array');
  const aggregatedPublicKey = publicKeys.reduce(
    (sum, publicKey) => sum.add(publicKeyToG1(publicKey)),
    Z1
  );
  return publicKeyFromG1(aggregatedPublicKey);
}

export function aggregateSignatures(signatures: Signature[]) {
  if (signatures.length === 0) throw new Error('Expected non-empty array');
  const aggregatedSignature = signatures.reduce(
    (sum, signature) => sum.add(signatureToG2(signature)),
    Z2
  );
  return signatureFromG2(aggregatedSignature);
}

export async function verifyBatch(
  messages: Hash[],
  publicKeys: PublicKey[],
  signature: Signature,
  domain: Domain
) {
  domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  if (messages.length === 0) throw new Error('Expected non-empty messages array');
  if (publicKeys.length !== messages.length) throw new Error('Pubkey count should equal msg count');
  try {
    let producer = Fp12.ONE;
    for (const message of new Set(messages)) {
      const groupPublicKey = messages.reduce(
        (groupPublicKey, m, i) =>
          m !== message ? groupPublicKey : groupPublicKey.add(publicKeyToG1(publicKeys[i])),
        Z1
      );
      producer = producer.multiply(
        pairing(await hashToG2(message, domain), groupPublicKey) as Fp12
      );
    }
    producer = producer.multiply(pairing(signatureToG2(signature), G1.negative()) as Fp12);
    const finalExponent = finalExponentiate(producer);
    return finalExponent.equals(Fp12.ONE);
  } catch {
    return false;
  }
}
