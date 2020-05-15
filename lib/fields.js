"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Point = exports.Fp12 = exports.Fp2 = exports.Fp = exports.normalized = void 0;
function normalized(target, propertyKey, descriptor) {
    const propertyValue = target[propertyKey];
    if (typeof propertyValue !== "function") {
        return descriptor;
    }
    const previousImplementation = propertyValue;
    descriptor.value = function (arg) {
        const modifiedArgument = target.normalize(arg);
        return previousImplementation.call(this, modifiedArgument);
    };
    return descriptor;
}
exports.normalized = normalized;
let Fp = (() => {
    class Fp {
        constructor(value = 0n) {
            this._value = 0n;
            this._value = this.mod(value, Fp.ORDER);
        }
        get value() {
            return this._value;
        }
        get zero() {
            return new Fp(0n);
        }
        get one() {
            return new Fp(1n);
        }
        mod(a, b) {
            const result = a % b;
            return result >= 0n ? result : b + result;
        }
        normalize(v) {
            return v instanceof Fp ? v : new Fp(v);
        }
        isEmpty() {
            return this._value === 0n;
        }
        equals(other) {
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
        add(other) {
            return new Fp(other._value + this._value);
        }
        square() {
            return new Fp(this._value * this._value);
        }
        pow(n) {
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
        subtract(other) {
            return new Fp(this._value - other._value);
        }
        multiply(other) {
            return new Fp(other._value * this._value);
        }
        div(other) {
            return this.multiply(other.invert());
        }
    }
    Fp.ORDER = 1n;
    __decorate([
        normalized
    ], Fp.prototype, "equals", null);
    __decorate([
        normalized
    ], Fp.prototype, "add", null);
    __decorate([
        normalized
    ], Fp.prototype, "subtract", null);
    __decorate([
        normalized
    ], Fp.prototype, "multiply", null);
    __decorate([
        normalized
    ], Fp.prototype, "div", null);
    return Fp;
})();
exports.Fp = Fp;
let Fp2 = (() => {
    class Fp2 {
        constructor(coef1 = 0n, coef2 = 0n) {
            this.coeficient1 = new Fp(0n);
            this.coeficient2 = new Fp(0n);
            this.coeficient1 = coef1 instanceof Fp ? coef1 : new Fp(coef1);
            this.coeficient2 = coef2 instanceof Fp ? coef2 : new Fp(coef2);
        }
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
        get value() {
            return [this.coeficient1.value, this.coeficient2.value];
        }
        get zero() {
            return new Fp2(0n, 0n);
        }
        get one() {
            return new Fp2(1n, 0n);
        }
        normalize(v) {
            if (typeof v === "bigint") {
                return v;
            }
            return v instanceof Fp2 ? v : new Fp2(...v);
        }
        isEmpty() {
            return this.coeficient1.isEmpty() && this.coeficient2.isEmpty();
        }
        equals(rhs) {
            return (this.coeficient1.equals(rhs.coeficient1) &&
                this.coeficient2.equals(rhs.coeficient2));
        }
        negative() {
            return new Fp2(this.coeficient1.negative(), this.coeficient2.negative());
        }
        add(rhs) {
            return new Fp2(this.coeficient1.add(rhs.coeficient1), this.coeficient2.add(rhs.coeficient2));
        }
        subtract(rhs) {
            return new Fp2(this.coeficient1.subtract(rhs.coeficient1), this.coeficient2.subtract(rhs.coeficient2));
        }
        multiply(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp2(this.coeficient1.multiply(otherValue), this.coeficient2.multiply(otherValue));
            }
            const v0 = this.coeficient1.multiply(otherValue.coeficient1);
            const v1 = this.coeficient2.negative().multiply(otherValue.coeficient2);
            const c0 = v0.add(v1);
            const c1 = this.coeficient1
                .add(this.coeficient2)
                .multiply(otherValue.coeficient1.add(otherValue.coeficient2))
                .subtract(v0)
                .add(v1);
            return new Fp2(c0, c1);
        }
        mulByNonresidue() {
            return new Fp2(this.coeficient1.subtract(this.coeficient2), this.coeficient1.add(this.coeficient2));
        }
        square() {
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
            const x1 = candidateSquareroot.div(Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]);
            const x2 = x1.negative();
            const isImageGreater = x1.coeficient2.value > x2.coeficient2.value;
            const isReconstructedGreater = x1.coeficient2.equals(x2.coeficient2) &&
                x1.coeficient1.value > x2.coeficient1.value;
            return isImageGreater || isReconstructedGreater ? x1 : x2;
        }
        pow(n) {
            if (n === 1n) {
                return this;
            }
            let result = new Fp2(1n, 0n);
            let value = this;
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
            const t = this.coeficient1
                .square()
                .add(this.coeficient2.square())
                .invert();
            return new Fp2(this.coeficient1.multiply(t), this.coeficient2.multiply(t.negative()));
        }
        div(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp2(this.coeficient1.div(otherValue), this.coeficient2.div(otherValue));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp2._order = 1n;
    Fp2.DIV_ORDER = 1n;
    Fp2.EIGHTH_ROOTS_OF_UNITY = Array(8)
        .fill(null)
        .map(() => new Fp2());
    Fp2.COFACTOR = 1n;
    __decorate([
        normalized
    ], Fp2.prototype, "equals", null);
    __decorate([
        normalized
    ], Fp2.prototype, "add", null);
    __decorate([
        normalized
    ], Fp2.prototype, "subtract", null);
    __decorate([
        normalized
    ], Fp2.prototype, "multiply", null);
    __decorate([
        normalized
    ], Fp2.prototype, "div", null);
    return Fp2;
})();
exports.Fp2 = Fp2;
const FP12_DEFAULT = [
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n
];
let Fp12 = (() => {
    class Fp12 {
        constructor(...args) {
            this.coefficients = FP12_DEFAULT.map(a => new Fp(a));
            args =
                args.length === 0 ? FP12_DEFAULT : args.slice(0, 12);
            this.coefficients = args[0] instanceof Fp ? args : args.map(a => new Fp(a));
        }
        get value() {
            return this.coefficients.map(c => c.value);
        }
        get zero() {
            return new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        get one() {
            return new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        normalize(v) {
            if (typeof v === "bigint") {
                return v;
            }
            return v instanceof Fp12 ? v : new Fp12(...v);
        }
        isEmpty() {
            return this.coefficients.every(a => a.isEmpty());
        }
        equals(rhs) {
            return this.coefficients.every((a, i) => a.equals(rhs.coefficients[i]));
        }
        negative() {
            return new Fp12(...this.coefficients.map(a => a.negative()));
        }
        add(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.add(rhs.coefficients[i])));
        }
        subtract(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.subtract(rhs.coefficients[i])));
        }
        multiply(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp12(...this.coefficients.map(a => a.multiply(otherValue)));
            }
            const LENGTH = this.coefficients.length;
            const filler = Array(LENGTH * 2 - 1)
                .fill(null)
                .map(() => new Fp());
            for (let i = 0; i < LENGTH; i++) {
                for (let j = 0; j < LENGTH; j++) {
                    filler[i + j] = filler[i + j].add(this.coefficients[i].multiply(otherValue.coefficients[j]));
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
            return new Fp12(...filler);
        }
        square() {
            return this.multiply(this);
        }
        pow(n) {
            if (n === 1n) {
                return this;
            }
            let result = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
            let value = this;
            while (n > 0n) {
                if ((n & 1n) === 1n) {
                    result = result.multiply(value);
                }
                n >>= 1n;
                value = value.square();
            }
            return result;
        }
        degree(nums) {
            let degree = nums.length - 1;
            while (nums[degree] === 0n && degree !== 0) {
                degree--;
            }
            return degree;
        }
        primeNumberInvariant(num) {
            return new Fp(num).invert().value;
        }
        optimizedRoundedDiv(coefficients, others) {
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
            return new Fp12(...zeros.slice(0, this.degree(zeros) + 1));
        }
        invert() {
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
            const result = new Fp12(...lm);
            return result.div(low[0]);
        }
        div(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp12(...this.coefficients.map(a => a.div(otherValue)));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp12.MODULE_COEFFICIENTS = [
        2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
    ];
    Fp12.ENTRY_COEFFICIENTS = [
        [0, 2n],
        [6, -2n]
    ];
    __decorate([
        normalized
    ], Fp12.prototype, "equals", null);
    __decorate([
        normalized
    ], Fp12.prototype, "add", null);
    __decorate([
        normalized
    ], Fp12.prototype, "subtract", null);
    __decorate([
        normalized
    ], Fp12.prototype, "multiply", null);
    __decorate([
        normalized
    ], Fp12.prototype, "div", null);
    return Fp12;
})();
exports.Fp12 = Fp12;
class Point {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    static get W() {
        return new Fp12(0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    }
    static get W_SQUARE() {
        return new Fp12(0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    }
    static get W_CUBE() {
        return new Fp12(0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
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
            return new Point(new Fp12(), new Fp12(), new Fp12(), Fp12);
        }
        const { x, y, z } = this;
        const [cx1, cx2] = [x.value[0] - x.value[1], x.value[1]];
        const [cy1, cy2] = [y.value[0] - y.value[1], y.value[1]];
        const [cz1, cz2] = [z.value[0] - z.value[1], z.value[1]];
        const newX = new Fp12(cx1, 0n, 0n, 0n, 0n, 0n, cx2, 0n, 0n, 0n, 0n, 0n);
        const newY = new Fp12(cy1, 0n, 0n, 0n, 0n, 0n, cy2, 0n, 0n, 0n, 0n, 0n);
        const newZ = new Fp12(cz1, 0n, 0n, 0n, 0n, 0n, cz2, 0n, 0n, 0n, 0n, 0n);
        return new Point(newX.div(Point.W_SQUARE), newY.div(Point.W_CUBE), newZ, Fp12);
    }
}
exports.Point = Point;
