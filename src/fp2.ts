import { Fp } from "./fp";
import { Group, normalized } from "./group";

export type BigintTuple = [bigint, bigint];

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
