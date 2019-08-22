import { Group } from "./group";
import { BigintTuple } from "./fp2";
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
