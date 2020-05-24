"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG12 = exports.PointG2 = exports.PointG1 = exports.hash_to_field = exports.Point = exports.Fq12 = exports.Fq2 = exports.Fq = exports.time = exports.DST_LABEL = exports.CURVE = void 0;
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    h: 0x396c8c005555e1568c00aaab0000aaabn,
    Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    Gy: 0x8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
    b: 4n,
    P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn **
        2n -
        1n,
    h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
    G2x: [
        0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
    ],
    G2y: [
        0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
    ],
    b2: [4n, 4n]
};
const P = exports.CURVE.P;
exports.DST_LABEL = 'BLS12381G2_XMD:SHA-256_SSWU_RO_';
exports.time = 0n;
function fpToString(num) {
    const str = num.toString(16).padStart(96, '0');
    return str.slice(0, 4) + '...' + str.slice(-4);
}
let Fq = (() => {
    class Fq {
        constructor(value) {
            this._value = mod(value, Fq.ORDER);
        }
        get value() {
            return this._value;
        }
        isEmpty() {
            return this._value === 0n;
        }
        equals(other) {
            return this._value === other._value;
        }
        negate() {
            return new Fq(-this._value);
        }
        invert() {
            let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n];
            let a = Fq.ORDER;
            let b = this.value;
            let q;
            while (a !== 0n) {
                [q, b, a] = [b / a, a, b % a];
                [x0, x1] = [x1, x0 - q * x1];
                [y0, y1] = [y1, y0 - q * y1];
            }
            return new Fq(x0);
        }
        add(other) {
            return new Fq(this._value + other.value);
        }
        square() {
            return new Fq(this._value * this._value);
        }
        pow(n) {
            return new Fq(powMod(this._value, n, Fq.ORDER));
        }
        subtract(other) {
            return new Fq(this._value - other._value);
        }
        multiply(other) {
            if (other instanceof Fq)
                other = other.value;
            return new Fq(this._value * other);
        }
        div(other) {
            return this.multiply(other.invert());
        }
        toString() {
            return fpToString(this.value);
        }
    }
    Fq.ORDER = exports.CURVE.P;
    Fq.ZERO = new Fq(0n);
    Fq.ONE = new Fq(1n);
    return Fq;
})();
exports.Fq = Fq;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
let Fq2 = (() => {
    class Fq2 {
        constructor(coefficients) {
            this.degree = 2;
            if (coefficients.length !== this.degree) {
                throw new Error(`Expected array with ${this.degree} elements`);
            }
            this.coefficients = coefficients.map((i) => (i instanceof Fq ? i : new Fq(i)));
        }
        get real() {
            return this.coefficients[0];
        }
        get imag() {
            return this.coefficients[1];
        }
        get value() {
            return this.coefficients.map((c) => c.value);
        }
        toString() {
            return `(${this.real} + ${this.imag}×i)`;
        }
        zip(other, mapper) {
            return this.coefficients.map((c, i) => mapper(c, other.coefficients[i]));
        }
        isEmpty() {
            return this.coefficients.every((c) => c.isEmpty());
        }
        equals(other) {
            return this.zip(other, (a, b) => a.equals(b)).every((a) => a);
        }
        negate() {
            return new Fq2(this.coefficients.map((c) => c.negate()));
        }
        add(other) {
            return new Fq2(this.zip(other, (a, b) => a.add(b)));
        }
        subtract(other) {
            return new Fq2(this.zip(other, (a, b) => a.subtract(b)));
        }
        multiply(other) {
            if (typeof other === 'bigint') {
                return new Fq2([this.real.multiply(new Fq(other)), this.imag.multiply(new Fq(other))]);
            }
            if (this.constructor !== other.constructor)
                throw new TypeError('Types do not match');
            const a1 = [this.real, this.imag];
            const b1 = [other.real, other.imag];
            const coeffs = [Fq.ZERO, Fq.ZERO];
            const embedding = 2;
            for (let i = 0; i < embedding; i++) {
                const x = a1[i];
                for (let j = 0; j < embedding; j++) {
                    const y = b1[j];
                    if (!x.isEmpty() && !y.isEmpty()) {
                        const degree = i + j;
                        const md = degree % embedding;
                        let xy = x.multiply(y);
                        const root = Fq2.ROOT;
                        if (degree >= embedding)
                            xy = xy.multiply(root);
                        coeffs[md] = coeffs[md].add(xy);
                    }
                }
            }
            return new Fq2(coeffs);
        }
        mulByNonresidue() {
            return new Fq2([this.real.subtract(this.imag), this.real.add(this.imag)]);
        }
        square() {
            const a = this.real.add(this.imag);
            const b = this.real.subtract(this.imag);
            const c = this.real.add(this.real);
            return new Fq2([a.multiply(b), c.multiply(this.imag)]);
        }
        sqrt() {
            const candidateSqrt = this.pow(Fq2.DIV_ORDER);
            const check = candidateSqrt.square().div(this);
            const rootIndex = rootsOfUnity.findIndex((a) => a.equals(check));
            if (rootIndex === -1 || (rootIndex & 1) === 1) {
                return null;
            }
            const x1 = candidateSqrt.div(rootsOfUnity[rootIndex >> 1]);
            const x2 = x1.negate();
            const isImageGreater = x1.imag.value > x2.imag.value;
            const isReconstructedGreater = x1.imag.equals(x2.imag) && x1.real.value > x2.real.value;
            return isImageGreater || isReconstructedGreater ? x1 : x2;
        }
        pow(n) {
            if (n === 0n)
                return Fq2.ONE;
            if (n === 1n)
                return this;
            let result = Fq2.ONE;
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
            const [a, b] = this.value;
            const factor = new Fq(a * a + b * b).invert();
            return new Fq2([factor.multiply(new Fq(a)), factor.multiply(new Fq(-b))]);
        }
        div(other) {
            if (typeof other === 'bigint') {
                return new Fq2([this.real.div(other), this.imag.div(other)]);
            }
            return this.multiply(other.invert());
        }
    }
    Fq2.ORDER = exports.CURVE.P2;
    Fq2.DIV_ORDER = (Fq2.ORDER + 8n) / 16n;
    Fq2.ROOT = new Fq(-1n);
    Fq2.ZERO = new Fq2([0n, 0n]);
    Fq2.ONE = new Fq2([1n, 0n]);
    Fq2.COFACTOR = exports.CURVE.h2;
    return Fq2;
})();
exports.Fq2 = Fq2;
const FP12_DEFAULT = [
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n
];
let Fq12 = (() => {
    class Fq12 {
        constructor(args = FP12_DEFAULT) {
            if (args.length !== 12) {
                throw new Error(`Invalid number of coefficients. Expected 12, not ${args.length}`);
            }
            const coeffs = args.slice().map((c) => (c instanceof Fq ? c : new Fq(c)));
            this.coefficients = coeffs;
        }
        get value() {
            return this.coefficients.map((c) => c.value);
        }
        zip(other, mapper) {
            return this.coefficients.map((c, i) => mapper(c, other.coefficients[i]));
        }
        isEmpty() {
            return this.coefficients.every((c) => c.isEmpty());
        }
        equals(other) {
            return this.zip(other, (a, b) => a.equals(b)).every((a) => a);
        }
        negate() {
            return new Fq12(this.coefficients.map((c) => c.negate()));
        }
        add(other) {
            return new Fq12(this.zip(other, (a, b) => a.add(b)));
        }
        subtract(other) {
            return new Fq12(this.zip(other, (a, b) => a.subtract(b)));
        }
        multiply(other) {
            if (typeof other === 'bigint') {
                return new Fq12(this.coefficients.map((a) => a.multiply(new Fq(other))));
            }
            const LENGTH = this.coefficients.length;
            const filler = Array(LENGTH * 2 - 1)
                .fill(null)
                .map(() => Fq.ZERO);
            for (let i = 0; i < LENGTH; i++) {
                for (let j = 0; j < LENGTH; j++) {
                    filler[i + j] = filler[i + j].add(this.coefficients[i].multiply(other.coefficients[j]));
                }
            }
            for (let exp = LENGTH - 2; exp >= 0; exp--) {
                const top = filler.pop();
                if (top === undefined) {
                    break;
                }
                for (const [i, value] of Fq12.ENTRY_COEFFICIENTS) {
                    filler[exp + i] = filler[exp + i].subtract(top.multiply(new Fq(value)));
                }
            }
            return new Fq12(filler);
        }
        square() {
            return this.multiply(this);
        }
        pow(n) {
            if (n === 1n) {
                return this;
            }
            let result = new Fq12([1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
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
            return new Fq(num).invert().value;
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
            return new Fq12(zeros.slice(0, 12));
        }
        invert() {
            const LENGTH = this.coefficients.length;
            let lm = [...Fq12.ONE.coefficients.map((a) => a.value), 0n];
            let hm = [...Fq12.ZERO.coefficients.map((a) => a.value), 0n];
            let low = [...this.coefficients.map((a) => a.value), 0n];
            let high = [...Fq12.MODULE_COEFFICIENTS, 1n];
            while (this.degree(low) !== 0) {
                const { coefficients } = this.optimizedRoundedDiv(high, low);
                const zeros = Array(LENGTH + 1 - coefficients.length)
                    .fill(null)
                    .map(() => Fq.ZERO);
                const roundedDiv = coefficients.concat(zeros);
                let nm = [...hm];
                let nw = [...high];
                for (let i = 0; i <= LENGTH; i++) {
                    for (let j = 0; j <= LENGTH - i; j++) {
                        nm[i + j] -= lm[i] * roundedDiv[j].value;
                        nw[i + j] -= low[i] * roundedDiv[j].value;
                    }
                }
                nm = nm.map((a) => new Fq(a).value);
                nw = nw.map((a) => new Fq(a).value);
                hm = lm;
                lm = nm;
                high = low;
                low = nw;
            }
            const result = new Fq12(lm.slice(0, 12));
            return result.div(low[0]);
        }
        div(other) {
            if (typeof other === 'bigint') {
                const num = new Fq(other);
                return new Fq12(this.coefficients.map((a) => a.div(num)));
            }
            return this.multiply(other.invert());
        }
    }
    Fq12.ZERO = new Fq12([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    Fq12.ONE = new Fq12([1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    Fq12.MODULE_COEFFICIENTS = [
        2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
    ];
    Fq12.ENTRY_COEFFICIENTS = [
        [0, 2n],
        [6, -2n],
    ];
    return Fq12;
})();
exports.Fq12 = Fq12;
class Point {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    static get W() {
        return new Fq12([0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    }
    static get W_SQUARE() {
        return new Fq12([0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    }
    static get W_CUBE() {
        return new Fq12([0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    }
    static fromAffine(x, y, C) {
        return new Point(x, y, C.ONE, C);
    }
    isZero() {
        return this.z.isEmpty();
    }
    getZero() {
        return new Point(this.C.ZERO, this.C.ONE, this.C.ZERO, this.C);
    }
    equals(other) {
        const a = this;
        const b = other;
        const az2 = a.z.multiply(a.z);
        const az3 = az2.multiply(a.z);
        const bz2 = b.z.multiply(b.z);
        const bz3 = bz2.multiply(b.z);
        return (a.x.multiply(bz2).equals(az2.multiply(b.x)) && a.y.multiply(bz3).equals(az3.multiply(b.y)));
    }
    negative() {
        return new Point(this.x, this.y.negate(), this.z, this.C);
    }
    toString(isAffine = true) {
        if (!isAffine) {
            return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
        }
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
    }
    toAffine() {
        const z3Inv = this.z.pow(3n).invert();
        return [this.x.multiply(this.z).multiply(z3Inv), this.y.multiply(z3Inv)];
    }
    double() {
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
        const Y3 = E.multiply(D.subtract(X3)).subtract(C.multiply(8n));
        const Z3 = Y1.multiply(Z1).multiply(2n);
        if (Z3.isEmpty())
            return this.getZero();
        return new Point(X3, Y3, Z3, this.C);
    }
    add(other) {
        if (!(other instanceof Point))
            throw new TypeError('Point#add: expected Point');
        const X1 = this.x;
        const Y1 = this.y;
        const Z1 = this.z;
        const X2 = other.x;
        const Y2 = other.y;
        const Z2 = other.z;
        const Z1Z1 = Z1.pow(2n);
        const Z2Z2 = Z2.pow(2n);
        const U1 = X1.multiply(Z2Z2);
        const U2 = X2.multiply(Z1Z1);
        const S1 = Y1.multiply(Z2).multiply(Z2Z2);
        const S2 = Y2.multiply(Z1).multiply(Z1Z1);
        const H = U2.subtract(U1);
        const rr = S2.subtract(S1).multiply(2n);
        if (U1.equals(U2) && S1.equals(S2))
            return this.double();
        const I = H.multiply(2n).pow(2n);
        const J = H.multiply(I);
        const V = U1.multiply(I);
        const X3 = rr.pow(2n).subtract(J).subtract(V.multiply(2n));
        const Y3 = rr.multiply(V.subtract(X3)).subtract(S1.multiply(J).multiply(2n));
        const Z3 = Z1.multiply(Z2).multiply(H).multiply(2n);
        const p_inf = Z1.isEmpty();
        const q_inf = Z2.isEmpty();
        if (p_inf && q_inf)
            return this.getZero();
        if (q_inf)
            return this;
        if (p_inf)
            return other;
        if (Z3.isEmpty())
            return this.getZero();
        return new Point(X3, Y3, Z3, this.C);
    }
    subtract(other) {
        return this.add(other.negative());
    }
    multiply(scalar) {
        let n = scalar;
        if (n instanceof Fq)
            n = n.value;
        if (typeof n === 'number')
            n = BigInt(n);
        const bin = n
            .toString(2)
            .split('')
            .map((a) => parseInt(a, 2));
        let Q = this.getZero();
        let P = this;
        for (let b of bin) {
            Q = Q.double();
            if (b === 1) {
                Q = P.add(Q);
            }
        }
        return Q;
    }
}
exports.Point = Point;
function finalExponentiate(p) {
    return p.pow((exports.CURVE.P ** 12n - 1n) / exports.CURVE.r);
}
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
const P_ORDER_X_9 = (P ** 2n - 9n) / 16n;
async function sha256(message) {
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
}
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
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}
function os2ip(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result;
}
function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}
function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
    }
    return arr;
}
const xnum = [
    new Fq2([
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    ]),
    new Fq2([
        0x0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
    ]),
    new Fq2([
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
    ]),
    new Fq2([
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0x0n,
    ]),
];
const xden = [
    new Fq2([
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
    ]),
    new Fq2([
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
    ]),
    new Fq2([0x1n, 0x0n]),
];
const ynum = [
    new Fq2([
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    ]),
    new Fq2([
        0x0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
    ]),
    new Fq2([
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
    ]),
    new Fq2([
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0x0n,
    ]),
];
const yden = [
    new Fq2([
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    ]),
    new Fq2([
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
    ]),
    new Fq2([
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
    ]),
    new Fq2([0x1n, 0x0n]),
];
function computeIsogeny(p, coefficients = [xnum, xden, ynum, yden]) {
    const { x, y, z } = p;
    const vals = new Array(4);
    const maxOrd = Math.max(...coefficients.map((a) => a.length));
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
const h_eff = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;
function clear_cofactor_bls12381_g2(point) {
    const P = computeIsogeny(point);
    return P.multiply(h_eff);
}
async function expand_message_xmd(msg, DST, len_in_bytes) {
    const H = sha256;
    const b_in_bytes = Number(SHA256_DIGEST_SIZE);
    const r_in_bytes = b_in_bytes * 2;
    const ell = Math.ceil(len_in_bytes / b_in_bytes);
    if (ell > 255)
        throw new Error('Invalid xmd length');
    const DST_prime = concatTypedArrays(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(len_in_bytes, 2);
    const b = new Array(ell);
    const b_0 = await H(concatTypedArrays(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = await H(concatTypedArrays(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = await H(concatTypedArrays(...args));
    }
    const pseudo_random_bytes = concatTypedArrays(...b);
    return pseudo_random_bytes.slice(0, len_in_bytes);
}
async function hash_to_field(msg, degree, isRandomOracle = true) {
    const count = isRandomOracle ? 2 : 1;
    const m = degree;
    const L = 64;
    const len_in_bytes = count * m * L;
    const DST = stringToBytes(exports.DST_LABEL);
    const pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes);
    const u = new Array(count);
    for (let i = 0; i < count; i++) {
        const e = new Array(m);
        for (let j = 0; j < m; j++) {
            const elm_offset = L * (j + i * m);
            const tv = pseudo_random_bytes.slice(elm_offset, elm_offset + L);
            e[j] = mod(os2ip(tv), exports.CURVE.P);
        }
        u[i] = e;
    }
    return u;
}
exports.hash_to_field = hash_to_field;
async function hashToG2(msg) {
    if (typeof msg === 'string')
        msg = hexToArray(msg);
    const u = await hash_to_field(msg, 2);
    const Q0 = map_to_curve_G2(new Fq2(u[0]));
    const Q1 = map_to_curve_G2(new Fq2(u[1]));
    const R = Q0.add(Q1);
    const P = clear_cofactor_bls12381_g2(R);
    return P;
}
function sgn0(x) {
    const [x0, x1] = x.value;
    const sign_0 = x0 % 2n;
    const zero_0 = x0 === 0n;
    const sign_1 = x1 % 2n;
    return BigInt(sign_0 || (zero_0 && sign_1));
}
const Ell2p_a = new Fq2([0n, 240n]);
const Ell2p_b = new Fq2([1012n, 1012n]);
const xi_2 = new Fq2([-2n, -1n]);
const rootsOfUnity = [
    new Fq2([1n, 0n]),
    new Fq2([0n, 1n]),
    new Fq2([rv1, rv1]),
    new Fq2([rv1, -rv1]),
];
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
const etas = [new Fq2([ev1, ev2]), new Fq2([-ev2, ev1]), new Fq2([ev3, ev4]), new Fq2([-ev4, ev3])];
function map_to_curve_G2(t) {
    const denominator = xi_2.square().multiply(t.pow(4n)).add(xi_2.multiply(t.square()));
    const x0_num = Ell2p_b.multiply(denominator.add(Fq2.ONE));
    const tmp = Ell2p_a.negate().multiply(denominator);
    const x0_den = tmp.isEmpty() ? Ell2p_a.multiply(xi_2) : tmp;
    const gx0_den = x0_den.pow(3n);
    const gx0_num = Ell2p_b.multiply(gx0_den)
        .add(Ell2p_a.multiply(x0_num).multiply(x0_den.square()))
        .add(x0_num.pow(3n));
    let tmp1 = gx0_den.pow(7n);
    let tmp2 = gx0_num.multiply(tmp1);
    tmp1 = tmp1.multiply(tmp2).multiply(gx0_den);
    let sqrt_candidate = tmp2.multiply(tmp1.pow(P_ORDER_X_9));
    for (const root of rootsOfUnity) {
        let y0 = sqrt_candidate.multiply(root);
        if (y0.square().multiply(gx0_den).equals(gx0_num)) {
            if (sgn0(y0) !== sgn0(t))
                y0 = y0.negate();
            return new Point(x0_num.multiply(x0_den), y0.multiply(x0_den.pow(3n)), x0_den, Fq2);
        }
    }
    const x1_num = xi_2.multiply(t.square()).multiply(x0_num);
    const x1_den = x0_den;
    const gx1_num = xi_2.pow(3n).multiply(t.pow(6n)).multiply(gx0_num);
    const gx1_den = gx0_den;
    sqrt_candidate = sqrt_candidate.multiply(t.pow(3n));
    for (const eta of etas) {
        let y1 = sqrt_candidate.multiply(eta);
        const candidate = y1.square().multiply(gx1_den);
        if (candidate.equals(gx1_num)) {
            if (sgn0(y1) !== sgn0(t))
                y1 = y1.negate();
            return new Point(x1_num.multiply(x1_den), y1.multiply(x1_den.pow(3n)), x1_den, Fq2);
        }
    }
    throw new Error('osswu2help failed for unknown reasons!');
}
let PointG1 = (() => {
    class PointG1 {
        constructor(point) {
            this.point = point;
        }
        static fromHex(hex) {
            const compressedValue = fromBytesBE(hex);
            const bflag = (compressedValue % POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = compressedValue % POW_2_381;
            const fullY = (x ** 3n + new Fq(exports.CURVE.b).value) % P;
            let y = powMod(fullY, (P + 1n) / 4n, P);
            if (powMod(y, 2n, P) !== fullY) {
                throw new Error('The given point is not on G1: y**2 = x**3 + b');
            }
            const aflag = (compressedValue % POW_2_382) / POW_2_381;
            if ((y * 2n) / P !== aflag) {
                y = P - y;
            }
            const p = new Point(new Fq(x), new Fq(y), new Fq(1n), Fq);
            return p;
        }
        toHex() {
            const { point } = this;
            let hex;
            if (point.equals(PointG1.ZERO)) {
                hex = POW_2_383 + POW_2_382;
            }
            else {
                const [x, y] = point.toAffine();
                const flag = (y.value * 2n) / P;
                hex = x.value + flag * POW_2_381 + POW_2_383;
            }
            return toBytesBE(hex, PUBLIC_KEY_LENGTH);
        }
        toFq12() {
            const pt = this.point;
            if (pt.isZero()) {
                return new Point(new Fq12(), new Fq12(), new Fq12(), Fq12);
            }
            return new Point(new Fq12([pt.x.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), new Fq12([pt.y.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), new Fq12([pt.z.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), Fq12);
        }
        assertValidity() {
            const b = new Fq(exports.CURVE.b);
            if (this.point.isZero())
                return true;
            const { x, y, z } = this.point;
            const squaredY = y.square();
            const cubedX = x.pow(3n);
            const z6 = z.pow(6n);
            const infty = x.isEmpty() && !y.isEmpty() && z.isEmpty();
            const match = squaredY.equals(b.multiply(z6).add(cubedX));
            const isOnCurve = infty || match;
            if (!isOnCurve)
                throw new Error('Invalid point: not on curve over Fq');
        }
    }
    PointG1.BASE = new Point(new Fq(exports.CURVE.Gx), new Fq(exports.CURVE.Gy), Fq.ONE, Fq);
    PointG1.ZERO = new Point(Fq.ONE, Fq.ONE, Fq.ZERO, Fq);
    return PointG1;
})();
exports.PointG1 = PointG1;
let PointG2 = (() => {
    class PointG2 {
        constructor(point) {
            this.point = point;
        }
        static fromx1x1(z1, z2) {
            const bflag1 = (z1 % POW_2_383) / POW_2_382;
            if (bflag1 === 1n) {
                return this.ZERO;
            }
            const x = new Fq2([z2, z1 % POW_2_381]);
            let y = x.pow(3n).add(new Fq2(exports.CURVE.b2)).sqrt();
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
            const point = new PointG2(new Point(x, y, Fq2.ONE, Fq2));
            point.assertValidity();
            return point.point;
        }
        static fromSignature(hex) {
            const half = hex.length / 2;
            const z1 = fromBytesBE(hex.slice(0, half));
            const z2 = fromBytesBE(hex.slice(half));
            return this.fromx1x1(z1, z2);
        }
        toHex() {
            const { point } = this;
            if (point.equals(PointG2.ZERO)) {
                return [POW_2_383 + POW_2_382, 0n];
            }
            this.assertValidity();
            const [[x0, x1], [y0, y1]] = point.toAffine().map((a) => a.value);
            const producer = y1 > 0 ? y1 : y0;
            const aflag1 = (producer * 2n) / P;
            const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
            const z2 = x0;
            return [z1, z2];
        }
        toSignature() {
            const [z1, z2] = this.toHex();
            return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
        }
        toFq12() {
            const { point } = this;
            if (!Array.isArray(point.x.value)) {
                return new Point(new Fq12(), new Fq12(), new Fq12(), Fq12);
            }
            const { x, y, z } = p;
            const [cx1, cx2] = [x.value[0] - x.value[1], x.value[1]];
            const [cy1, cy2] = [y.value[0] - y.value[1], y.value[1]];
            const [cz1, cz2] = [z.value[0] - z.value[1], z.value[1]];
            const newX = new Fq12([cx1, 0n, 0n, 0n, 0n, 0n, cx2, 0n, 0n, 0n, 0n, 0n]);
            const newY = new Fq12([cy1, 0n, 0n, 0n, 0n, 0n, cy2, 0n, 0n, 0n, 0n, 0n]);
            const newZ = new Fq12([cz1, 0n, 0n, 0n, 0n, 0n, cz2, 0n, 0n, 0n, 0n, 0n]);
            return new Point(newX.div(Point.W_SQUARE), newY.div(Point.W_CUBE), newZ, Fq12);
        }
        assertValidity() {
            const b = new Fq2(exports.CURVE.b2);
            if (this.point.isZero())
                return true;
            const { x, y, z } = this.point;
            const squaredY = y.square();
            const cubedX = x.pow(3n);
            const z6 = z.pow(6n);
            const infty = x.isEmpty() && !y.isEmpty() && z.isEmpty();
            const match = squaredY.equals(b.multiply(z6).add(cubedX));
            const isOnCurve = infty || match;
            if (!isOnCurve)
                throw new Error('Invalid point: not on curve over Fq2');
        }
    }
    PointG2.BASE = new Point(new Fq2(exports.CURVE.G2x), new Fq2(exports.CURVE.G2y), Fq2.ONE, Fq2);
    PointG2.ZERO = new Point(Fq2.ONE, Fq2.ONE, Fq2.ZERO, Fq2);
    return PointG2;
})();
exports.PointG2 = PointG2;
let PointG12 = (() => {
    class PointG12 {
    }
    PointG12.B = new Fq12([4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    return PointG12;
})();
exports.PointG12 = PointG12;
function createLineBetween(p1, p2, n) {
    let mNumerator = p2.y.multiply(p1.z).subtract(p1.y.multiply(p2.z));
    let mDenominator = p2.x.multiply(p1.z).subtract(p1.x.multiply(p2.z));
    if (!mNumerator.isEmpty() && mDenominator.isEmpty()) {
        return [n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)), p1.z.multiply(n.z)];
    }
    else if (mNumerator.isEmpty()) {
        mNumerator = p1.x.square().multiply(3n);
        mDenominator = p1.y.multiply(p1.z).multiply(2n);
    }
    const numeratorLine = mNumerator.multiply(n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)));
    const denominatorLine = mDenominator.multiply(n.y.multiply(p1.z).subtract(p1.y.multiply(n.z)));
    const z = mDenominator.multiply(n.z).multiply(p1.z);
    return [numeratorLine.subtract(denominatorLine), z];
}
const PSEUDO_BINARY_ENCODING = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];
function millerLoop(Q, P, withFinalExponent = false) {
    const one = Fq12.ONE;
    if (Q.isZero() || P.isZero()) {
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
    const q = new PointG2(Q);
    const p = new PointG1(P);
    q.assertValidity();
    p.assertValidity();
    return millerLoop(q.toFq12(), p.toFq12(), withFinalExponent);
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    privateKey = toBigInt(privateKey);
    return new PointG1(PointG1.BASE.multiply(privateKey)).toHex();
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    privateKey = toBigInt(privateKey);
    const messageValue = await hashToG2(message);
    const sigPoint = messageValue.multiply(privateKey);
    return new PointG2(sigPoint).toSignature();
}
exports.sign = sign;
async function verify(message, publicKey, signature) {
    const publicKeyPoint = PointG1.fromHex(publicKey).negative();
    const signaturePoint = await hashToG2(signature);
    try {
        const signaturePairing = pairing(signaturePoint, PointG1.BASE);
        const hashPairing = pairing(await hashToG2(message), publicKeyPoint);
        const finalExponent = finalExponentiate(signaturePairing.multiply(hashPairing));
        return finalExponent.equals(Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    const aggregatedPublicKey = publicKeys.reduce((sum, publicKey) => sum.add(PointG1.fromHex(publicKey)), PointG1.ZERO);
    return new PointG1(aggregatedPublicKey).toHex();
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (!signatures.length)
        throw new Error('Expected non-empty array');
    const aggregatedSignature = signatures.reduce((sum, signature) => sum.add(PointG2.fromSignature(signature)), PointG2.ZERO);
    return new PointG2(aggregatedSignature).toSignature();
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(messages, publicKeys, signature) {
    if (!messages.length)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    try {
        let producer = Fq12.ONE;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message ? groupPublicKey : groupPublicKey.add(PointG1.fromHex(publicKeys[i])), PointG1.ZERO);
            producer = producer.multiply(pairing(await hashToG2(message), groupPublicKey));
        }
        producer = producer.multiply(pairing(PointG2.fromSignature(signature), PointG1.BASE.negative()));
        const finalExponent = finalExponentiate(producer);
        return finalExponent.equals(Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
