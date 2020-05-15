"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Point = void 0;
const fp12_1 = require("./fp12");
class Point {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    static get W() {
        return new fp12_1.Fp12(0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    }
    static get W_SQUARE() {
        return new fp12_1.Fp12(0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    }
    static get W_CUBE() {
        return new fp12_1.Fp12(0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    }
    isEmpty() {
        return this.x.isEmpty() && this.y.isEmpty() && this.z.isEmpty();
    }
    isOnCurve(b) {
        if (this.isEmpty()) {
            return true;
        }
        const lefSide = this.y
            .square()
            .multiply(this.z)
            .subtract(this.x.pow(3n));
        const rightSide = b.multiply(this.z.pow(3n));
        return lefSide.equals(rightSide);
    }
    equals(other) {
        return (this.x.multiply(other.z).equals(other.x.multiply(this.z)) &&
            this.y.multiply(other.z).equals(other.y.multiply(this.z)));
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
        const W = this.x.square().multiply(3n);
        const S = this.y.multiply(this.z);
        const B = this.x.multiply(this.y).multiply(S);
        const H = W.square().subtract(B.multiply(8n));
        const newX = H.multiply(S).multiply(2n);
        const tmp = this.y
            .square()
            .multiply(S.square())
            .multiply(8n);
        const newY = W.multiply(B.multiply(4n).subtract(H)).subtract(tmp);
        const newZ = S.pow(3n).multiply(8n);
        return new Point(newX, newY, newZ, this.C);
    }
    add(other) {
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
        const A = u
            .square()
            .multiply(W)
            .subtract(v.pow(3n))
            .subtract(SQUERED_V_MUL_V2.multiply(2n));
        const newX = v.multiply(A);
        const newY = u
            .multiply(SQUERED_V_MUL_V2.subtract(A))
            .subtract(V_CUBE.multiply(u2));
        const newZ = V_CUBE.multiply(W);
        return new Point(newX, newY, newZ, this.C);
    }
    subtract(other) {
        return this.add(other.negative());
    }
    multiply(n) {
        n = BigInt(n);
        let result = new Point(this.x.one, this.y.one, this.z.zero, this.C);
        let point = this;
        while (n > 0n) {
            if ((n & 1n) === 1n) {
                result = result.add(point);
            }
            point = point.double();
            n >>= 1n;
        }
        return result;
    }
    twist() {
        if (!Array.isArray(this.x.value)) {
            return new Point(new fp12_1.Fp12(), new fp12_1.Fp12(), new fp12_1.Fp12(), fp12_1.Fp12);
        }
        const { x, y, z } = this;
        const [cx1, cx2] = [x.value[0] - x.value[1], x.value[1]];
        const [cy1, cy2] = [y.value[0] - y.value[1], y.value[1]];
        const [cz1, cz2] = [z.value[0] - z.value[1], z.value[1]];
        const newX = new fp12_1.Fp12(cx1, 0n, 0n, 0n, 0n, 0n, cx2, 0n, 0n, 0n, 0n, 0n);
        const newY = new fp12_1.Fp12(cy1, 0n, 0n, 0n, 0n, 0n, cy2, 0n, 0n, 0n, 0n, 0n);
        const newZ = new fp12_1.Fp12(cz1, 0n, 0n, 0n, 0n, 0n, cz2, 0n, 0n, 0n, 0n, 0n);
        return new Point(newX.div(Point.W_SQUARE), newY.div(Point.W_CUBE), newZ, fp12_1.Fp12);
    }
}
exports.Point = Point;
