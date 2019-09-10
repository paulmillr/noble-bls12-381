import { Fp } from "./fp";
import { Group } from "./group";
import { Fp2, BigintTuple } from "./fp2";
import { Fp12, BigintTwelve } from "./fp12";

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

  // Fast subgroup checks via Bowe19
  isOnCurve(b: Group<T>) {
    if (this.isEmpty()) {
      return true;
    }
    const squaredY = this.y.square();
    const cubedX = this.x.pow(3n);
    const z6 = this.z.pow(6n);
    return squaredY.equals(b.multiply(z6).add(cubedX));
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
    const zInv = this.z.pow(3n).invert();
    return [this.x.multiply(this.z).multiply(zInv), this.y.multiply(zInv)];
  }

  // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
  double() {
    if (this.isEmpty()) {
      return this;
    }
    const squaredX = this.x.square();
    const squaredY = this.y.square();
    const C = squaredX.square();
    const D = this.x
      .add(squaredY)
      .square()
      .subtract(squaredX)
      .subtract(C);
    const E = squaredX.multiply(3n);
    const F = E.square();
    const newX = F.subtract(D.multiply(2n));
    const newY = D.subtract(newX)
      .multiply(E)
      .subtract(C.multiply(8n));
    const newZ = this.y.multiply(this.z).multiply(2n);
    return newZ.isEmpty()
      ? new Point(this.x.zero, this.y.one, this.z.zero, this.C)
      : new Point(newX, newY, newZ, this.C);
  }

  // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
  add(other: Point<T>) {
    if (other.z.isEmpty()) {
      return this;
    }
    if (this.z.isEmpty()) {
      return other;
    }
    const thisZ2 = this.z.square();
    const otherZ2 = other.z.square();
    const u1 = this.x.multiply(otherZ2);
    const u2 = other.x.multiply(thisZ2);
    const s1 = this.y.multiply(other.z).multiply(otherZ2);
    const s2 = other.y.multiply(this.z).multiply(thisZ2);
    if (u1.equals(u2) && s1.equals(s2)) {
      return this.double();
    }
    const H = u2.subtract(u1);
    const I = H.multiply(2n).square();
    const J = H.multiply(I);
    const R = s2.subtract(s1).multiply(2n);
    const V = u1.multiply(I);

    const x = R.square()
      .subtract(J)
      .subtract(V.multiply(2n));
    const y = R.multiply(V.subtract(x)).subtract(s1.multiply(J).multiply(2n));
    const z = this.z
      .multiply(other.z)
      .multiply(H)
      .multiply(2n);

    return new Point(x, y, z, this.C);
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

  // Isogeny map evaluation specified by map_coeffs
  // map_coeffs should be specified as (xnum, xden, ynum, yden)
  // This function evaluates the isogeny over Jacobian projective coordinates.
  // For details, see Section 4.3 of
  // Wahby and Boneh, "Fast and simple constant-time hashing to the BLS12-381 elliptic curve."
  // ePrint # 2019/403, https://ia.cr/2019/403.
  evalIsogeny(coefficients: Array<Array<Group<T>>>) {
    const mapValues = new Array(4);
    // precompute the required powers of Z^2
    const maxOrd = Math.max(...coefficients.map(a => a.length));
    const zPowers = new Array(maxOrd);
    zPowers[0] = this.z.pow(0n);
    zPowers[1] = this.z.pow(2n);
    for (let i = 2; i < maxOrd; i++) {
      zPowers[i] = zPowers[i - 1].multiply(zPowers[1]);
    }
    for (let i = 0; i < coefficients.length; i++) {
      const coefficient = Array.from(coefficients[i]);
      const coeffsZ = coefficient.map((c, i) => c.multiply(zPowers[i]));
      let tmp = coeffsZ[0];
      for (let j = 1; j < coeffsZ.length; j++) {
        tmp = tmp.multiply(this.x).add(coeffsZ[j]);
      }
      mapValues[i] = tmp;
    }
    mapValues[1] = mapValues[1].multiply(zPowers[1]);
    mapValues[2] = mapValues[2].multiply(this.y);
    mapValues[3] = mapValues[3].multiply(this.z.pow(3n));

    const z = mapValues[1].multiply(mapValues[3]);
    const x = mapValues[0].multiply(mapValues[3]).multiply(z);
    const y = mapValues[2].multiply(mapValues[1]).multiply(z.square());

    return new Point(x, y, z, this.C);
  }
}
