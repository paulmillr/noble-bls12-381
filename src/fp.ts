import { Group, normalized } from "./group";

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
