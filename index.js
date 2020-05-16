"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.G2 = exports.G1 = exports.hashToG2 = exports.signatureToG2 = exports.B12 = exports.B2 = exports.B = exports.CURVE = exports.Point = exports.Fp12 = exports.Fp2 = exports.Fp = void 0;
function normalized(target, propertyKey, descriptor) {
    const propertyValue = target[propertyKey];
    if (typeof propertyValue !== 'function') {
        return descriptor;
    }
    const previousImplementation = propertyValue;
    descriptor.value = function (arg) {
        const modifiedArgument = target.normalize(arg);
        return previousImplementation.call(this, modifiedArgument);
    };
    return descriptor;
}
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
            return new Fp(invert(this._value, Fp.ORDER));
        }
        add(other) {
            return new Fp(other._value + this._value);
        }
        square() {
            return new Fp(this._value * this._value);
        }
        pow(n) {
            return new Fp(powMod(this._value, n, Fp.ORDER));
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
            if (typeof v === 'bigint') {
                return v;
            }
            return v instanceof Fp2 ? v : new Fp2(...v);
        }
        isEmpty() {
            return this.coeficient1.isEmpty() && this.coeficient2.isEmpty();
        }
        equals(rhs) {
            return this.coeficient1.equals(rhs.coeficient1) && this.coeficient2.equals(rhs.coeficient2);
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
            if (typeof otherValue === 'bigint') {
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
        modSqrt() {
            const candidateSqrt = this.pow(Fp2.DIV_ORDER);
            const check = candidateSqrt.square().div(this);
            const rootIndex = Fp2.EIGHTH_ROOTS_OF_UNITY.findIndex((a) => a.equals(check));
            if (rootIndex === -1 || (rootIndex & 1) === 1) {
                return null;
            }
            const x1 = candidateSqrt.div(Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]);
            const x2 = x1.negative();
            const isImageGreater = x1.coeficient2.value > x2.coeficient2.value;
            const isReconstructedGreater = x1.coeficient2.equals(x2.coeficient2) && x1.coeficient1.value > x2.coeficient1.value;
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
            const t = this.coeficient1.square().add(this.coeficient2.square()).invert();
            return new Fp2(this.coeficient1.multiply(t), this.coeficient2.multiply(t.negative()));
        }
        div(otherValue) {
            if (typeof otherValue === 'bigint') {
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
            this.coefficients = FP12_DEFAULT.map((a) => new Fp(a));
            args = args.length === 0 ? FP12_DEFAULT : args.slice(0, 12);
            this.coefficients = args[0] instanceof Fp ? args : args.map(a => new Fp(a));
        }
        get value() {
            return this.coefficients.map((c) => c.value);
        }
        get zero() {
            return new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        get one() {
            return new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        normalize(v) {
            if (typeof v === 'bigint') {
                return v;
            }
            return v instanceof Fp12 ? v : new Fp12(...v);
        }
        isEmpty() {
            return this.coefficients.every((a) => a.isEmpty());
        }
        equals(rhs) {
            return this.coefficients.every((a, i) => a.equals(rhs.coefficients[i]));
        }
        negative() {
            return new Fp12(...this.coefficients.map((a) => a.negative()));
        }
        add(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.add(rhs.coefficients[i])));
        }
        subtract(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.subtract(rhs.coefficients[i])));
        }
        multiply(otherValue) {
            if (typeof otherValue === 'bigint') {
                return new Fp12(...this.coefficients.map((a) => a.multiply(otherValue)));
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
            let lm = [...this.one.coefficients.map((a) => a.value), 0n];
            let hm = [...this.zero.coefficients.map((a) => a.value), 0n];
            let low = [...this.coefficients.map((a) => a.value), 0n];
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
                nm = nm.map((a) => new Fp(a).value);
                nw = nw.map((a) => new Fp(a).value);
                hm = lm;
                lm = nm;
                high = low;
                low = nw;
            }
            const result = new Fp12(...lm);
            return result.div(low[0]);
        }
        div(otherValue) {
            if (typeof otherValue === 'bigint') {
                return new Fp12(...this.coefficients.map((a) => a.div(otherValue)));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp12.MODULE_COEFFICIENTS = [
        2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
    ];
    Fp12.ENTRY_COEFFICIENTS = [
        [0, 2n],
        [6, -2n],
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
        const lefSide = this.y.square().multiply(this.z).subtract(this.x.pow(3n));
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
        const tmp = this.y.square().multiply(S.square()).multiply(8n);
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
        const A = u.square().multiply(W).subtract(v.pow(3n)).subtract(SQUERED_V_MUL_V2.multiply(2n));
        const newX = v.multiply(A);
        const newY = u.multiply(SQUERED_V_MUL_V2.subtract(A)).subtract(V_CUBE.multiply(u2));
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
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    n: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    DOMAIN_LENGTH: 8,
    Gx: 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507n,
    Gy: 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569n,
    G2x: [
        352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160n,
        3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758n,
    ],
    G2y: [
        1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905n,
        927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582n,
    ],
    G2_COFACTOR: 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n,
};
const P_ORDER_X_12_DIVIDED = (exports.CURVE.P ** 12n - 1n) / exports.CURVE.n;
function finalExponentiate(p) {
    return p.pow(P_ORDER_X_12_DIVIDED);
}
Fp.ORDER = exports.CURVE.P;
Fp2.ORDER = exports.CURVE.P ** 2n - 1n;
Fp2.COFACTOR = exports.CURVE.G2_COFACTOR;
exports.B = new Fp(4n);
exports.B2 = new Fp2(4n, 4n);
exports.B12 = new Fp12(4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
const Z1 = new Point(new Fp(1n), new Fp(1n), new Fp(0n), Fp);
const Z2 = new Point(new Fp2(1n, 0n), new Fp2(1n, 0n), new Fp2(0n, 0n), Fp2);
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const sha256 = async (message) => {
    if (typeof window == 'object' && 'crypto' in window) {
        const buffer = await window.crypto.subtle.digest('SHA-256', message.buffer);
        return new Uint8Array(buffer);
    }
    else if (typeof process === 'object' && 'node' in process.versions) {
        const { createHash } = require('crypto');
        const hash = createHash('sha256');
        hash.update(message);
        return Uint8Array.from(hash.digest());
    }
    else {
        throw new Error("The environment doesn't have sha256 function");
    }
};
function fromHexBE(hex) {
    return BigInt(`0x${hex}`);
}
function fromBytesBE(bytes) {
    if (typeof bytes === 'string') {
        return fromHexBE(bytes);
    }
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function padStart(bytes, count, element) {
    if (bytes.length >= count) {
        return bytes;
    }
    const diff = count - bytes.length;
    const elements = Array(diff)
        .fill(element)
        .map((i) => i);
    return concatTypedArrays(new Uint8Array(elements), bytes);
}
function toBytesBE(num, padding = 0) {
    let hex = typeof num === 'string' ? num : num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length && i < len * 2; i += 2, j++) {
        u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return padStart(u8, padding, 0);
}
function toBigInt(num) {
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
function hexToArray(hex) {
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
        result[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return result;
}
function concatTypedArrays(...bytes) {
    return new Uint8Array(bytes.reduce((res, bytesView) => {
        bytesView = bytesView instanceof Uint8Array ? bytesView : hexToArray(bytesView);
        return [...res, ...bytesView];
    }, []));
}
function mod(a, b) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
function powMod(a, power, m) {
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
function egcd(a, b) {
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
function invert(number, modulo) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('invert: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('invert: does not exist');
    }
    return mod(x, modulo);
}
async function getXCoordinate(hash, domain) {
    const xReconstructed = toBigInt(await sha256(concatTypedArrays(hash, domain, '01')));
    const xImage = toBigInt(await sha256(concatTypedArrays(hash, domain, '02')));
    return new Fp2(xReconstructed, xImage);
}
const POW_SUM = POW_2_383 + POW_2_382;
function compressG1(point) {
    if (point.equals(Z1)) {
        return POW_SUM;
    }
    const [x, y] = point.to2D();
    const flag = (y.value * 2n) / P;
    return x.value + flag * POW_2_381 + POW_2_383;
}
const PART_OF_P = (exports.CURVE.P + 1n) / 4n;
function decompressG1(compressedValue) {
    const bflag = (compressedValue % POW_2_383) / POW_2_382;
    if (bflag === 1n) {
        return Z1;
    }
    const x = compressedValue % POW_2_381;
    const fullY = (x ** 3n + exports.B.value) % P;
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
function compressG2(point) {
    if (point.equals(Z2)) {
        return [POW_2_383 + POW_2_382, 0n];
    }
    if (!point.isOnCurve(exports.B2)) {
        throw new Error('The given point is not on the twisted curve over FQ**2');
    }
    const [[x0, x1], [y0, y1]] = point.to2D().map((a) => a.value);
    const producer = y1 > 0 ? y1 : y0;
    const aflag1 = (producer * 2n) / P;
    const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
    const z2 = x0;
    return [z1, z2];
}
function decompressG2([z1, z2]) {
    const bflag1 = (z1 % POW_2_383) / POW_2_382;
    if (bflag1 === 1n) {
        return Z2;
    }
    const x = new Fp2(z2, z1 % POW_2_381);
    let y = x.pow(3n).add(exports.B2).modSqrt();
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
    const point = new Point(x, y, y.one, Fp2);
    if (!point.isOnCurve(exports.B2)) {
        throw new Error('The given point is not on the twisted curve over Fp2');
    }
    return point;
}
function publicKeyFromG1(point) {
    return toBytesBE(compressG1(point), PUBLIC_KEY_LENGTH);
}
function publicKeyToG1(publicKey) {
    return decompressG1(fromBytesBE(publicKey));
}
function signatureFromG2(point) {
    const [z1, z2] = compressG2(point);
    return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
}
function signatureToG2(signature) {
    const halfSignature = signature.length / 2;
    const z1 = fromBytesBE(signature.slice(0, halfSignature));
    const z2 = fromBytesBE(signature.slice(halfSignature));
    return decompressG2([z1, z2]);
}
exports.signatureToG2 = signatureToG2;
async function hashToG2(hash, domain) {
    let xCoordinate = await getXCoordinate(hash, domain);
    let newResult = null;
    do {
        newResult = xCoordinate.pow(3n).add(new Fp2(4n, 4n)).modSqrt();
        const addition = newResult ? xCoordinate.zero : xCoordinate.one;
        xCoordinate = xCoordinate.add(addition);
    } while (newResult === null);
    const yCoordinate = newResult;
    const result = new Point(xCoordinate, yCoordinate, new Fp2(1n, 0n), Fp2);
    return result.multiply(Fp2.COFACTOR);
}
exports.hashToG2 = hashToG2;
const P = exports.CURVE.P;
exports.G1 = new Point(new Fp(exports.CURVE.Gx), new Fp(exports.CURVE.Gy), new Fp(1n), Fp);
exports.G2 = new Point(new Fp2(exports.CURVE.G2x[0], exports.CURVE.G2x[1]), new Fp2(exports.CURVE.G2y[0], exports.CURVE.G2y[1]), new Fp2(1n, 0n), Fp2);
function createLineBetween(p1, p2, n) {
    let mNumerator = p2.y.multiply(p1.z).subtract(p1.y.multiply(p2.z));
    let mDenominator = p2.x.multiply(p1.z).subtract(p1.x.multiply(p2.z));
    if (!mNumerator.equals(mNumerator.zero) && mDenominator.equals(mDenominator.zero)) {
        return [n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)), p1.z.multiply(n.z)];
    }
    else if (mNumerator.equals(mNumerator.zero)) {
        mNumerator = p1.x.square().multiply(3n);
        mDenominator = p1.y.multiply(p1.z).multiply(2n);
    }
    const numeratorLine = mNumerator.multiply(n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)));
    const denominatorLine = mDenominator.multiply(n.y.multiply(p1.z).subtract(p1.y.multiply(n.z)));
    const z = mDenominator.multiply(n.z).multiply(p1.z);
    return [numeratorLine.subtract(denominatorLine), z];
}
function castPointToFp12(pt) {
    if (pt.isEmpty()) {
        return new Point(new Fp12(), new Fp12(), new Fp12(), Fp12);
    }
    return new Point(new Fp12(pt.x.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new Fp12(pt.y.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new Fp12(pt.z.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), Fp12);
}
const PSEUDO_BINARY_ENCODING = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];
function millerLoop(Q, P, withFinalExponent = false) {
    const one = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
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
function pairing(Q, P, withFinalExponent = true) {
    if (!Q.isOnCurve(exports.B2)) {
        throw new Error("Fisrt point isn't on elliptic curve");
    }
    if (!P.isOnCurve(exports.B)) {
        throw new Error("Second point isn't on elliptic curve");
    }
    return millerLoop(Q.twist(), castPointToFp12(P), withFinalExponent);
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    privateKey = toBigInt(privateKey);
    return publicKeyFromG1(exports.G1.multiply(privateKey));
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey, domain) {
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, exports.CURVE.DOMAIN_LENGTH);
    privateKey = toBigInt(privateKey);
    const messageValue = await hashToG2(message, domain);
    const signature = messageValue.multiply(privateKey);
    return signatureFromG2(signature);
}
exports.sign = sign;
async function verify(message, publicKey, signature, domain) {
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, exports.CURVE.DOMAIN_LENGTH);
    const publicKeyPoint = publicKeyToG1(publicKey).negative();
    const signaturePoint = signatureToG2(signature);
    try {
        const signaturePairing = pairing(signaturePoint, exports.G1);
        const hashPairing = pairing(await hashToG2(message, domain), publicKeyPoint);
        const finalExponent = finalExponentiate(signaturePairing.multiply(hashPairing));
        return finalExponent.equals(finalExponent.one);
    }
    catch {
        return false;
    }
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (publicKeys.length === 0)
        throw new Error('Expected non-empty array');
    const aggregatedPublicKey = publicKeys.reduce((sum, publicKey) => sum.add(publicKeyToG1(publicKey)), Z1);
    return publicKeyFromG1(aggregatedPublicKey);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (signatures.length === 0)
        throw new Error('Expected non-empty array');
    const aggregatedSignature = signatures.reduce((sum, signature) => sum.add(signatureToG2(signature)), Z2);
    return signatureFromG2(aggregatedSignature);
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(messages, publicKeys, signature, domain) {
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, exports.CURVE.DOMAIN_LENGTH);
    if (messages.length === 0)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    try {
        let producer = new Fp12().one;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message ? groupPublicKey : groupPublicKey.add(publicKeyToG1(publicKeys[i])), Z1);
            producer = producer.multiply(pairing(await hashToG2(message, domain), groupPublicKey));
        }
        producer = producer.multiply(pairing(signatureToG2(signature), exports.G1.negative()));
        const finalExponent = finalExponentiate(producer);
        return finalExponent.equals(finalExponent.one);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
