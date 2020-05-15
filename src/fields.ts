// Group
// Fp: (x, y)
// Fp2: (x1, x2), (y1, y2)
// Fp12

type ArgumentTypes<F extends Function> = F extends (...args: infer A) => any
  ? A
  : never;
type ReturnType<T extends Function> = T extends (...args: any[]) => infer R
  ? R
  : any;
type IncludedTypes<Base, Type> = {
  [Key in keyof Base]: Base[Key] extends Type ? Key : never
};
type AllowedNames<Base, Type> = keyof IncludedTypes<Base, Type>;

export interface Group<T> {
  readonly one: Group<T>;
  readonly zero: Group<T>;
  readonly value: T;
  normalize(v: Group<T> | T | bigint): bigint | Group<T>;
  isEmpty(): boolean;
  equals(otherValue: Group<T> | T): boolean;
  add(otherValue: Group<T> | T): Group<T>;
  multiply(otherValue: Group<T> | T | bigint): Group<T>;
  div(otherValue: Group<T> | T | bigint): Group<T>;
  square(): Group<T>;
  subtract(otherValue: Group<T> | T): Group<T>;
  negative(): Group<T>;
  invert(): Group<T>;
  pow(n: bigint): Group<T>;
}

export function normalized<
  T,
  G extends Group<T>,
  M extends AllowedNames<G, Function>
>(
  target: G,
  propertyKey: M,
  descriptor: PropertyDescriptor
): PropertyDescriptor {
  type GroupMethod = G[M] & Function;
  const propertyValue: G[M] | GroupMethod = target[propertyKey];
  if (typeof propertyValue !== "function") {
    return descriptor;
  }
  const previousImplementation: GroupMethod = propertyValue;
  descriptor.value = function(arg: G | T | bigint): ReturnType<GroupMethod> {
    const modifiedArgument = target.normalize(arg);
    return previousImplementation.call(this, modifiedArgument);
  };
  return descriptor;
}

export type BigintTuple = [bigint, bigint];

export class Fp implements Group<bigint> {
  static ORDER = 1n;
  private _value: bigint = 0n;

  public get value() {
    return this._value;
  }

  public get zero() {
    return new Fp(0n);
  }
  public get one() {
    return new Fp(1n);
  }

  constructor(value: bigint = 0n) {
    this._value = this.mod(value, Fp.ORDER);
  }

  private mod(a: bigint, b: bigint) {
    const result = a % b;
    return result >= 0n ? result : b + result;
  }

  normalize(v: Fp | bigint): Fp {
    return v instanceof Fp ? v : new Fp(v);
  }

  isEmpty() {
    return this._value === 0n;
  }

  @normalized equals(other: Fp) {
    return this._value === other._value;
  }

  negative() {
    return new Fp(-this._value);
  }

  invert() {
    const v = this._value;
    let lm = 1n;
    let hm = 0n;
    let low = v;
    let high = Fp.ORDER;
    let ratio = 0n;
    let nm = v;
    let enew = 0n;
    while (low > 1n) {
      ratio = high / low;
      nm = hm - lm * ratio;
      enew = high - low * ratio;
      hm = lm;
      lm = nm;
      high = low;
      low = enew;
    }
    return new Fp(nm);
  }

  @normalized add(other: Fp | bigint) {
    return new Fp((other as Fp)._value + this._value);
  }

  square() {
    return new Fp(this._value * this._value);
  }

  pow(n: bigint) {
    let result = 1n;
    let value = this._value;
    while (n > 0) {
      if ((n & 1n) === 1n) {
        result = this.mod(result * value, Fp.ORDER);
      }
      n >>= 1n;
      value = this.mod(value * value, Fp.ORDER);
    }
    return new Fp(result);
  }

  @normalized subtract(other: Fp | bigint) {
    return new Fp(this._value - (other as Fp)._value);
  }

  @normalized multiply(other: Fp | bigint) {
    return new Fp((other as Fp)._value * this._value);
  }

  @normalized div(other: Fp | bigint) {
    return this.multiply((other as Fp).invert());
  }
}

export class Fp2 implements Group<BigintTuple> {
  private static _order = 1n;
  private static DIV_ORDER = 1n;
  private static EIGHTH_ROOTS_OF_UNITY = Array(8)
    .fill(null)
    .map(() => new Fp2());
  public static COFACTOR = 1n;

  static set ORDER(order) {
    this._order = order;
    this.DIV_ORDER = (order + 8n) / 16n;
    const one = new Fp2(1n, 1n);
    const orderEightPart = order / 8n;
    const roots = Array(8)
      .fill(null)
      .map((_, i) => one.pow(BigInt(i) * orderEightPart));
    this.EIGHTH_ROOTS_OF_UNITY = roots;
  }

  static get ORDER() {
    return this._order;
  }

  private coeficient1 = new Fp(0n);
  private coeficient2 = new Fp(0n);

  public get value(): BigintTuple {
    return [this.coeficient1.value, this.coeficient2.value];
  }

  public get zero() {
    return new Fp2(0n, 0n);
  }

  public get one() {
    return new Fp2(1n, 0n);
  }

  constructor(coef1: Fp | bigint = 0n, coef2: Fp | bigint = 0n) {
    this.coeficient1 = coef1 instanceof Fp ? coef1 : new Fp(coef1);
    this.coeficient2 = coef2 instanceof Fp ? coef2 : new Fp(coef2);
  }

  normalize(v: Fp2 | BigintTuple | bigint): bigint | Fp2 {
    if (typeof v === "bigint") {
      return v;
    }
    return v instanceof Fp2 ? v : new Fp2(...v);
  }

  isEmpty() {
    return this.coeficient1.isEmpty() && this.coeficient2.isEmpty();
  }

  @normalized
  equals(rhs: Fp2) {
    return (
      this.coeficient1.equals(rhs.coeficient1) &&
      this.coeficient2.equals(rhs.coeficient2)
    );
  }

  negative() {
    return new Fp2(this.coeficient1.negative(), this.coeficient2.negative());
  }

  @normalized
  add(rhs: Fp2) {
    return new Fp2(
      this.coeficient1.add(rhs.coeficient1),
      this.coeficient2.add(rhs.coeficient2)
    );
  }

  @normalized
  subtract(rhs: Fp2) {
    return new Fp2(
      this.coeficient1.subtract(rhs.coeficient1),
      this.coeficient2.subtract(rhs.coeficient2)
    );
  }

  // Karatsuba multiplication:
  // In BLS12-381's Fp2, our beta is -1 so we
  // can modify this formula. (Also, since we always
  // subtract v1, we can compute v1 = -a1 * b1.)
  @normalized
  multiply(otherValue: Fp2 | bigint) {
    if (typeof otherValue === "bigint") {
      return new Fp2(
        this.coeficient1.multiply(otherValue),
        this.coeficient2.multiply(otherValue)
      );
    }
    // v0  = a0 * b0
    const v0 = this.coeficient1.multiply(otherValue.coeficient1);
    // v1  = (-a1) * b1
    const v1 = this.coeficient2.negative().multiply(otherValue.coeficient2);
    // c0 = v0 + v1
    const c0 = v0.add(v1);
    // c1 = (a0 + a1) * (b0 + b1) - v0 + v1
    const c1 = this.coeficient1
      .add(this.coeficient2)
      .multiply(otherValue.coeficient1.add(otherValue.coeficient2))
      .subtract(v0)
      .add(v1);
    return new Fp2(c0, c1);
  }

  // Multiply a + bu by u + 1, getting
  // au + a + bu^2 + bu
  // and because u^2 = -1, we get
  // (a - b) + (a + b)u
  mulByNonresidue() {
    return new Fp2(
      this.coeficient1.subtract(this.coeficient2),
      this.coeficient1.add(this.coeficient2)
    );
  }

  square() {
    // Complex squaring:
    //
    // v0  = c0 * c1
    // c0' = (c0 + c1) * (c0 + beta*c1) - v0 - beta * v0
    // c1' = 2 * v0
    //
    // In BLS12-381's Fp2, our beta is -1 so we
    // can modify this formula:
    //
    // c0' = (c0 + c1) * (c0 - c1)
    // c1' = 2 * c0 * c1
    const a = this.coeficient1.add(this.coeficient2);
    const b = this.coeficient1.subtract(this.coeficient2);
    const c = this.coeficient1.add(this.coeficient1);
    return new Fp2(a.multiply(b), c.multiply(this.coeficient2));
  }

  modularSquereRoot() {
    const candidateSquareroot = this.pow(Fp2.DIV_ORDER);
    const check = candidateSquareroot.square().div(this);
    const rootIndex = Fp2.EIGHTH_ROOTS_OF_UNITY.findIndex(a => a.equals(check));
    if (rootIndex === -1 || (rootIndex & 1) === 1) {
      return null;
    }
    const x1 = candidateSquareroot.div(
      Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]
    );
    const x2 = x1.negative();
    const isImageGreater = x1.coeficient2.value > x2.coeficient2.value;
    const isReconstructedGreater =
      x1.coeficient2.equals(x2.coeficient2) &&
      x1.coeficient1.value > x2.coeficient1.value;
    return isImageGreater || isReconstructedGreater ? x1 : x2;
  }

  pow(n: bigint) {
    if (n === 1n) {
      return this;
    }
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

  invert() {
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
    const t = this.coeficient1
      .square()
      .add(this.coeficient2.square())
      .invert();
    return new Fp2(
      this.coeficient1.multiply(t),
      this.coeficient2.multiply(t.negative())
    );
  }

  @normalized
  div(otherValue: Fp2 | bigint) {
    if (typeof otherValue === "bigint") {
      return new Fp2(
        this.coeficient1.div(otherValue),
        this.coeficient2.div(otherValue)
      );
    }
    return this.multiply(otherValue.invert());
  }
}

// prettier-ignore
export type BigintTwelve = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint
];

type Fp12Like = Fp12 | BigintTwelve;

export type FpTwelve = [Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp];

// prettier-ignore
const FP12_DEFAULT: BigintTwelve = [
  0n, 1n, 0n, 1n,
  0n, 1n, 0n, 1n,
  0n, 1n, 0n, 1n
];

/// This represents an element c0 + c1 * w of Fp12 = Fp6 / w^2 - v.
export class Fp12 implements Group<BigintTwelve> {
  private coefficients: FpTwelve = FP12_DEFAULT.map(a => new Fp(a)) as FpTwelve;
  // prettier-ignore
  private static readonly MODULE_COEFFICIENTS: BigintTwelve = [
    2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
  ];
  private static readonly ENTRY_COEFFICIENTS: Array<[number, bigint]> = [
    [0, 2n],
    [6, -2n]
  ];

  public get value() {
    return this.coefficients.map(c => c.value) as BigintTwelve;
  }

  public get zero() {
    return new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
  }
  public get one() {
    return new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
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
    args =
      args.length === 0 ? FP12_DEFAULT : (args.slice(0, 12) as BigintTwelve);
    // @ts-ignore stupid TS
    // prettier-ignore
    this.coefficients = args[0] instanceof Fp ? args : (args.map(a => new Fp(a)) as FpTwelve);
  }

  public normalize(v: Fp12Like | bigint) {
    if (typeof v === "bigint") {
      return v;
    }
    return v instanceof Fp12 ? v : new Fp12(...v);
  }

  isEmpty() {
    return this.coefficients.every(a => a.isEmpty());
  }

  @normalized
  equals(rhs: Fp12Like) {
    return this.coefficients.every((a, i) =>
      a.equals((rhs as Fp12).coefficients[i])
    );
  }

  negative() {
    return new Fp12(...(this.coefficients.map(a => a.negative()) as FpTwelve));
  }

  @normalized
  add(rhs: Fp12Like) {
    return new Fp12(
      ...(this.coefficients.map((a, i) =>
        a.add((rhs as Fp12).coefficients[i])
      ) as FpTwelve)
    );
  }

  @normalized
  subtract(rhs: Fp12Like) {
    return new Fp12(
      ...(this.coefficients.map((a, i) =>
        a.subtract((rhs as Fp12).coefficients[i])
      ) as FpTwelve)
    );
  }

  @normalized
  multiply(otherValue: Fp12Like | bigint) {
    if (typeof otherValue === "bigint") {
      return new Fp12(
        ...(this.coefficients.map(a => a.multiply(otherValue)) as FpTwelve)
      );
    }
    const LENGTH = this.coefficients.length;

    const filler = Array(LENGTH * 2 - 1)
      .fill(null)
      .map(() => new Fp());
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
        filler[exp + i] = filler[exp + i].subtract(top.multiply(value));
      }
    }
    return new Fp12(...(filler as FpTwelve));
  }

  square() {
    return this.multiply(this);
  }

  pow(n: bigint) {
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
    return new Fp12(
      ...(zeros.slice(0, this.degree(zeros) + 1) as BigintTwelve)
    );
  }

  invert(): Fp12 {
    const LENGTH = this.coefficients.length;
    let lm = [...this.one.coefficients.map(a => a.value), 0n];
    let hm = [...this.zero.coefficients.map(a => a.value), 0n];
    let low = [...this.coefficients.map(a => a.value), 0n];
    let high = [...Fp12.MODULE_COEFFICIENTS, 1n];
    while (this.degree(low) !== 0) {
      const { coefficients } = this.optimizedRoundedDiv(high, low);
      const zeros = Array(LENGTH + 1 - coefficients.length)
        .fill(null)
        .map(() => new Fp());
      const roundedDiv = coefficients.concat(zeros);
      let nm = [...hm];
      let nw = [...high];
      for (let i = 0; i <= LENGTH; i++) {
        for (let j = 0; j <= LENGTH - i; j++) {
          nm[i + j] -= lm[i] * roundedDiv[j].value;
          nw[i + j] -= low[i] * roundedDiv[j].value;
        }
      }
      nm = nm.map(a => new Fp(a).value);
      nw = nw.map(a => new Fp(a).value);
      hm = lm;
      lm = nm;
      high = low;
      low = nw;
    }
    const result = new Fp12(...(lm as BigintTwelve));
    return result.div(low[0]);
  }

  @normalized
  div(otherValue: Fp12 | bigint) {
    if (typeof otherValue === "bigint") {
      return new Fp12(
        ...(this.coefficients.map(a => a.div(otherValue)) as FpTwelve)
      );
    }
    return this.multiply(otherValue.invert());
  }
}


type Constructor<T> = { new (...args: any[]): Group<T> };
type GroupCoordinats<T> = { x: Group<T>; y: Group<T>; z: Group<T> };

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
    public x: Group<T>,
    public y: Group<T>,
    public z: Group<T>,
    private C: Constructor<T>
  ) {}

  isEmpty() {
    return this.x.isEmpty() && this.y.isEmpty() && this.z.isEmpty();
  }

  isOnCurve(b: Group<T>) {
    if (this.isEmpty()) {
      return true;
    }
    // Check that a point is on the curve defined by y**2 * z - x**3 == b * z**3
    const lefSide = this.y
      .square()
      .multiply(this.z)
      .subtract(this.x.pow(3n));
    const rightSide = b.multiply(this.z.pow(3n));
    return lefSide.equals(rightSide);
  }

  equals(other: Point<T>) {
    // x1 * z2 == x2 * z1 and y1 * z2 == y2 * z1
    return (
      this.x.multiply(other.z).equals(other.x.multiply(this.z)) &&
      this.y.multiply(other.z).equals(other.y.multiply(this.z))
    );
  }

  negative() {
    return new Point(this.x, this.y.negative(), this.z, this.C);
  }

  to2D() {
    return [this.x.div(this.z), this.y.div(this.z)];
  }

  double() {
    if (this.isEmpty()) {
      return this;
    }
    // W = 3 * x * x
    const W = this.x.square().multiply(3n);
    // S = y * z
    const S = this.y.multiply(this.z);
    // B = x * y * S
    const B = this.x.multiply(this.y).multiply(S);
    // H = W * W - 8 * B
    const H = W.square().subtract(B.multiply(8n));
    // x = 2 * H * S:
    const newX = H.multiply(S).multiply(2n);
    const tmp = this.y
      .square()
      .multiply(S.square())
      .multiply(8n);
    // y = W * (4 * B - H) - 8 * y**2 * s**2
    const newY = W.multiply(B.multiply(4n).subtract(H)).subtract(tmp);
    // z = 8 * S**3
    const newZ = S.pow(3n).multiply(8n);
    return new Point(newX, newY, newZ, this.C);
  }

  add(other: Point<T>) {
    if (other.z.isEmpty()) {
      return this;
    }
    if (this.z.isEmpty()) {
      return other;
    }
    const u1 = other.y.multiply(this.z);
    const u2 = this.y.multiply(other.z);
    const v1 = other.x.multiply(this.z);
    const v2 = this.x.multiply(other.z);
    if (v1.equals(v2) && u1.equals(u2)) {
      return this.double();
    }
    if (v1.equals(v2)) {
      return new Point(this.x.one, this.y.one, this.z.zero, this.C);
    }
    const u = u1.subtract(u2);
    const v = v1.subtract(v2);
    const V_CUBE = v.pow(3n);
    const SQUERED_V_MUL_V2 = v.square().multiply(v2);
    const W = this.z.multiply(other.z);
    // u**2 * W - v**3 - 2 * v**2 * v2
    const A = u
      .square()
      .multiply(W)
      .subtract(v.pow(3n))
      .subtract(SQUERED_V_MUL_V2.multiply(2n));
    const newX = v.multiply(A);
    // y = u * (v**2 * v2 - A) - v**3 * u2
    const newY = u
      .multiply(SQUERED_V_MUL_V2.subtract(A))
      .subtract(V_CUBE.multiply(u2));
    const newZ = V_CUBE.multiply(W);
    return new Point(newX, newY, newZ, this.C);
  }

  subtract(other: Point<T>) {
    return this.add(other.negative());
  }

  multiply(n: number | bigint) {
    n = BigInt(n);
    let result = new Point(this.x.one, this.y.one, this.z.zero, this.C);
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
    return new Point(
      newX.div(Point.W_SQUARE),
      newY.div(Point.W_CUBE),
      newZ,
      Fp12
    );
  }
}
