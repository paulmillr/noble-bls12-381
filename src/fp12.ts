import { Fp } from "./fp";
import { Group, normalized } from "./group";

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
