"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG12 = exports.PointG2 = exports.PointG1 = exports.hash_to_field = exports.ProjectivePoint = exports.Fq12 = exports.Fq2 = exports.Fq = exports.DST_LABEL = exports.CURVE = void 0;
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
    b2: [4n, 4n],
};
const P = exports.CURVE.P;
exports.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
let Fq = (() => {
    class Fq {
        constructor(value) {
            this._value = mod(value, Fq.ORDER);
        }
        get value() {
            return this._value;
        }
        isZero() {
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
            const str = this.value.toString(16).padStart(96, '0');
            return str.slice(0, 2) + '.' + str.slice(-2);
        }
    }
    Fq.ORDER = exports.CURVE.P;
    Fq.ZERO = new Fq(0n);
    Fq.ONE = new Fq(1n);
    return Fq;
})();
exports.Fq = Fq;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
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
        isZero() {
            return this.coefficients.every((c) => c.isZero());
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
                const rhs = new Fq(other);
                return new Fq2(this.coefficients.map((c) => c.multiply(rhs)));
            }
            if (this.constructor !== other.constructor)
                throw new TypeError('Types do not match');
            const a1 = this.coefficients;
            const b1 = other.coefficients;
            const coeffs = [Fq.ZERO, Fq.ZERO];
            const embedding = 2;
            for (let i = 0; i < embedding; i++) {
                const x = a1[i];
                for (let j = 0; j < embedding; j++) {
                    const y = b1[j];
                    if (!x.isZero() && !y.isZero()) {
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
            const candidateSqrt = this.pow((Fq2.ORDER + 8n) / 16n);
            const check = candidateSqrt.square().div(this);
            const R = Fq2.ROOTS_OF_UNITY;
            const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
            if (!divisor)
                return undefined;
            const index = R.indexOf(divisor);
            const root = R[index / 2];
            if (!root)
                throw new Error('Invalid root');
            const x1 = candidateSqrt.div(root);
            const x2 = x1.negate();
            const [x1_re, x1_im] = x1.value;
            const [x2_re, x2_im] = x2.value;
            if (x1_im > x2_im || (x1_im == x2_im && x1_re > x2_re))
                return x1;
            return x2;
        }
        pow(n) {
            if (n === 0n)
                return Fq2.ONE;
            if (n === 1n)
                return this;
            let p = Fq2.ONE;
            let d = this;
            while (n > 0n) {
                if (n & 1n)
                    p = p.multiply(d);
                n >>= 1n;
                d = d.square();
            }
            return p;
        }
        invert() {
            const [a, b] = this.value;
            const factor = new Fq(a * a + b * b).invert();
            return new Fq2([factor.multiply(new Fq(a)), factor.multiply(new Fq(-b))]);
        }
        div(other) {
            if (typeof other === 'bigint') {
                return new Fq2(this.coefficients.map((c) => c.div(other)));
            }
            return this.multiply(other.invert());
        }
    }
    Fq2.ORDER = exports.CURVE.P2;
    Fq2.ROOT = new Fq(-1n);
    Fq2.ZERO = new Fq2([0n, 0n]);
    Fq2.ONE = new Fq2([1n, 0n]);
    Fq2.COFACTOR = exports.CURVE.h2;
    Fq2.ROOTS_OF_UNITY = [
        new Fq2([1n, 0n]),
        new Fq2([rv1, -rv1]),
        new Fq2([0n, 1n]),
        new Fq2([rv1, rv1]),
        new Fq2([-1n, 0n]),
        new Fq2([-rv1, rv1]),
        new Fq2([0n, -1n]),
        new Fq2([-rv1, -rv1]),
    ];
    Fq2.ETAs = [
        new Fq2([ev1, ev2]),
        new Fq2([-ev2, ev1]),
        new Fq2([ev3, ev4]),
        new Fq2([-ev4, ev3]),
    ];
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
        isZero() {
            return this.coefficients.every((c) => c.isZero());
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
            const degree = this.coefficients.length;
            const filler = Array(degree * 2 - 1)
                .fill(null)
                .map(() => Fq.ZERO);
            for (let i = 0; i < degree; i++) {
                for (let j = 0; j < degree; j++) {
                    filler[i + j] = filler[i + j].add(this.coefficients[i].multiply(other.coefficients[j]));
                }
            }
            for (let exp = degree - 2; exp >= 0; exp--) {
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
            if (n === 0n)
                return Fq12.ONE;
            if (n === 1n)
                return this;
            let p = Fq12.ONE;
            let d = this;
            while (n > 0n) {
                if (n & 1n)
                    p = p.multiply(d);
                n >>= 1n;
                d = d.square();
            }
            return p;
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
        toString() {
            const coeffs = this.coefficients.map((c) => c.toString()).join(' + \n');
            return `Fq12 (${coeffs})`;
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
class ProjectivePoint {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    static fromAffine(x, y, C) {
        return new ProjectivePoint(x, y, C.ONE, C);
    }
    isZero() {
        return this.z.isZero();
    }
    getZero() {
        return new ProjectivePoint(this.C.ONE, this.C.ONE, this.C.ZERO, this.C);
    }
    equals(other) {
        const a = this;
        const b = other;
        const xe = a.x.multiply(b.z).equals(b.x.multiply(a.z));
        return xe && a.y.multiply(b.z).equals(b.y.multiply(a.z));
    }
    negate() {
        return new ProjectivePoint(this.x, this.y.negate(), this.z, this.C);
    }
    toString(isAffine = true) {
        if (!isAffine) {
            return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
        }
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
    }
    toAffine() {
        const iz = this.z.invert();
        return [this.x.multiply(iz), this.y.multiply(iz)];
    }
    double() {
        const { x, y, z } = this;
        const W = x.multiply(x).multiply(3n);
        const S = y.multiply(z);
        const SS = S.multiply(S);
        const SSS = SS.multiply(S);
        const B = x.multiply(y).multiply(S);
        const H = W.multiply(W).subtract(B.multiply(8n));
        const X3 = H.multiply(S).multiply(2n);
        const Y3 = W.multiply(B.multiply(4n).subtract(H)).subtract(y.multiply(y).multiply(8n).multiply(SS));
        const Z3 = SSS.multiply(8n);
        return new ProjectivePoint(X3, Y3, Z3, this.C);
    }
    add(other) {
        const p1 = this;
        const p2 = other;
        if (p1.isZero())
            return p2;
        if (p2.isZero())
            return p1;
        const X1 = p1.x;
        const Y1 = p1.y;
        const Z1 = p1.z;
        const X2 = p2.x;
        const Y2 = p2.y;
        const Z2 = p2.z;
        const U1 = Y2.multiply(Z1);
        const U2 = Y1.multiply(Z2);
        const V1 = X2.multiply(Z1);
        const V2 = X1.multiply(Z2);
        if (V1.equals(V2) && U1.equals(U2))
            return this.double();
        if (V1.equals(V2))
            return new ProjectivePoint(this.C.ONE, this.C.ONE, this.C.ZERO, this.C);
        const U = U1.subtract(U2);
        const V = V1.subtract(V2);
        const VV = V.multiply(V);
        const VVV = VV.multiply(V);
        const V2VV = V2.multiply(VV);
        const W = Z1.multiply(Z2);
        const A = U.multiply(U).multiply(W).subtract(VVV).subtract(V2VV.multiply(2n));
        const X3 = V.multiply(A);
        const Y3 = U.multiply(V2VV.subtract(A)).subtract(VVV.multiply(U2));
        const Z3 = VVV.multiply(W);
        return new ProjectivePoint(X3, Y3, Z3, this.C);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        let n = scalar;
        if (n instanceof Fq)
            n = n.value;
        if (typeof n === 'number')
            n = BigInt(n);
        let p = this.getZero();
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }
}
exports.ProjectivePoint = ProjectivePoint;
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
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
    if (!hex.length)
        return new Uint8Array([]);
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
    Fq2.ONE,
    Fq2.ZERO,
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
const isoCoefficients = [xnum, xden, ynum, yden];
function isogenyMapG2(xyz) {
    const [x, y, z] = xyz;
    const mapped = [Fq2.ZERO, Fq2.ZERO, Fq2.ZERO, Fq2.ZERO];
    const zPowers = [z, z.pow(2n), z.pow(3n)];
    for (let i = 0; i < isoCoefficients.length; i++) {
        const k_i = isoCoefficients[i];
        mapped[i] = k_i.slice(-1)[0];
        const arr = k_i.slice(0, -1).reverse();
        for (let j = 0; j < arr.length; j++) {
            const k_i_j = arr[j];
            mapped[i] = mapped[i].multiply(x).add(zPowers[j].multiply(k_i_j));
        }
    }
    mapped[2] = mapped[2].multiply(y);
    mapped[3] = mapped[3].multiply(z);
    const z2 = mapped[1].multiply(mapped[3]);
    const x2 = mapped[0].multiply(mapped[3]);
    const y2 = mapped[1].multiply(mapped[2]);
    return new ProjectivePoint(x2, y2, z2, Fq2);
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
function sgn0(x) {
    const [x0, x1] = x.value;
    const sign_0 = x0 % 2n;
    const zero_0 = x0 === 0n;
    const sign_1 = x1 % 2n;
    return BigInt(sign_0 || (zero_0 && sign_1));
}
const P_MINUS_9_DIV_16 = (P ** 2n - 9n) / 16n;
function sqrt_div_fq2(u, v) {
    const uv7 = u.multiply(v.pow(7n));
    const uv15 = uv7.multiply(v.pow(8n));
    const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
    let success = false;
    let result = gamma;
    const positiveRootsOfUnity = Fq2.ROOTS_OF_UNITY.slice(0, 4);
    for (const root of positiveRootsOfUnity) {
        const candidate = root.multiply(gamma);
        if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
            success = true;
            result = candidate;
        }
    }
    return [success, result];
}
function map_to_curve_SSWU_G2(t) {
    const iso_3_a = new Fq2([0n, 240n]);
    const iso_3_b = new Fq2([1012n, 1012n]);
    const iso_3_z = new Fq2([-2n, -1n]);
    if (Array.isArray(t))
        t = new Fq2(t);
    const t2 = t.pow(2n);
    const iso_3_z_t2 = iso_3_z.multiply(t2);
    const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
    let denominator = iso_3_a.multiply(ztzt).negate();
    let numerator = iso_3_b.multiply(ztzt.add(Fq2.ONE));
    if (denominator.isZero())
        denominator = iso_3_z.multiply(iso_3_a);
    let v = denominator.pow(3n);
    let u = numerator
        .pow(3n)
        .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
        .add(iso_3_b.multiply(v));
    const [success, sqrtCandidateOrGamma] = sqrt_div_fq2(u, v);
    let y;
    if (success)
        y = sqrtCandidateOrGamma;
    const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));
    u = iso_3_z_t2.pow(3n).multiply(u);
    let success2 = false;
    for (const eta of Fq2.ETAs) {
        const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
        const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
        if (temp.isZero() && !success && !success2) {
            y = etaSqrtCandidate;
            success2 = true;
        }
    }
    if (!success && !success2)
        throw new Error('Hash to Curve - Optimized SWU failure');
    if (success2)
        numerator = numerator.multiply(iso_3_z_t2);
    y = y;
    if (sgn0(t) !== sgn0(y))
        y = y.negate();
    y = y.multiply(denominator);
    return [numerator, y, denominator];
}
function normalizePrivKey(privateKey) {
    return new Fq(toBigInt(privateKey));
}
let PointG1 = (() => {
    class PointG1 {
        constructor(jpoint) {
            this.jpoint = jpoint;
            if (!jpoint)
                throw new Error('Expected point');
        }
        static fromCompressedHex(hex) {
            const compressedValue = fromBytesBE(hex);
            const bflag = mod(compressedValue, POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = mod(compressedValue, POW_2_381);
            const fullY = mod(x ** 3n + new Fq(exports.CURVE.b).value, P);
            let y = powMod(fullY, (P + 1n) / 4n, P);
            if (powMod(y, 2n, P) !== fullY) {
                throw new Error('The given point is not on G1: y**2 = x**3 + b');
            }
            const aflag = mod(compressedValue, POW_2_382) / POW_2_381;
            if ((y * 2n) / P !== aflag) {
                y = P - y;
            }
            const p = new ProjectivePoint(new Fq(x), new Fq(y), new Fq(1n), Fq);
            return p;
        }
        static fromPrivateKey(privateKey) {
            return new PointG1(this.BASE.multiply(normalizePrivKey(privateKey)));
        }
        toCompressedHex() {
            const { jpoint: point } = this;
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
            const pt = this.jpoint;
            if (pt.isZero()) {
                return new ProjectivePoint(new Fq12(), new Fq12(), new Fq12(), Fq12);
            }
            return new ProjectivePoint(new Fq12([pt.x.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), new Fq12([pt.y.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), new Fq12([pt.z.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), Fq12);
        }
        assertValidity() {
            const b = new Fq(exports.CURVE.b);
            if (this.jpoint.isZero())
                return;
            const { x, y, z } = this.jpoint;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq');
        }
    }
    PointG1.BASE = new ProjectivePoint(new Fq(exports.CURVE.Gx), new Fq(exports.CURVE.Gy), Fq.ONE, Fq);
    PointG1.ZERO = new ProjectivePoint(Fq.ONE, Fq.ONE, Fq.ZERO, Fq);
    return PointG1;
})();
exports.PointG1 = PointG1;
const H_EFF = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;
function clearCofactorG2(P) {
    return P.multiply(H_EFF);
}
let PointG2 = (() => {
    class PointG2 {
        constructor(jpoint) {
            this.jpoint = jpoint;
            if (!jpoint)
                throw new Error('Expected point');
        }
        toString() {
            return this.jpoint.toString();
        }
        static async hashToCurve(msg) {
            if (typeof msg === 'string')
                msg = hexToArray(msg);
            const u = await hash_to_field(msg, 2);
            const Q0 = isogenyMapG2(map_to_curve_SSWU_G2(u[0]));
            const Q1 = isogenyMapG2(map_to_curve_SSWU_G2(u[1]));
            const R = Q0.add(Q1);
            const P = clearCofactorG2(R);
            return P;
        }
        static fromSignature(hex) {
            const half = hex.length / 2;
            const z1 = fromBytesBE(hex.slice(0, half));
            const z2 = fromBytesBE(hex.slice(half));
            const bflag1 = mod(z1, POW_2_383) / POW_2_382;
            if (bflag1 === 1n)
                return this.ZERO;
            const x1 = z1 % POW_2_381;
            const x2 = z2;
            const x = new Fq2([x2, x1]);
            let y = x.pow(3n).add(new Fq2(exports.CURVE.b2)).sqrt();
            if (!y)
                throw new Error('Failed to find a square root');
            const [y0, y1] = y.value;
            const aflag1 = (z1 % POW_2_382) / POW_2_381;
            const isGreater = y1 > 0n && (y1 * 2n) / P !== aflag1;
            const isZero = y1 === 0n && (y0 * 2n) / P !== aflag1;
            if (isGreater || isZero)
                y = y.multiply(-1n);
            const point = new PointG2(new ProjectivePoint(x, y, Fq2.ONE, Fq2));
            point.assertValidity();
            return point.jpoint;
        }
        static fromPrivateKey(privateKey) {
            return new PointG2(this.BASE.multiply(normalizePrivKey(privateKey)));
        }
        toSignature() {
            const { jpoint } = this;
            if (jpoint.equals(PointG2.ZERO)) {
                const sum = POW_2_383 + POW_2_382;
                return concatTypedArrays(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
            }
            this.assertValidity();
            const [[x0, x1], [y0, y1]] = jpoint.toAffine().map((a) => a.value);
            const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
            const aflag1 = tmp / exports.CURVE.P;
            const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
            const z2 = x0;
            return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
        }
        toFq12() {
            const { x, y, z } = this.jpoint;
            if (!Array.isArray(x.value)) {
                return new ProjectivePoint(new Fq12(), new Fq12(), new Fq12(), Fq12);
            }
            const [cx1, cx2] = [x.value[0] - x.value[1], x.value[1]];
            const [cy1, cy2] = [y.value[0] - y.value[1], y.value[1]];
            const [cz1, cz2] = [z.value[0] - z.value[1], z.value[1]];
            const newX = new Fq12([cx1, 0n, 0n, 0n, 0n, 0n, cx2, 0n, 0n, 0n, 0n, 0n]);
            const newY = new Fq12([cy1, 0n, 0n, 0n, 0n, 0n, cy2, 0n, 0n, 0n, 0n, 0n]);
            const newZ = new Fq12([cz1, 0n, 0n, 0n, 0n, 0n, cz2, 0n, 0n, 0n, 0n, 0n]);
            return new ProjectivePoint(newX.div(PointG12.W_SQUARE), newY.div(PointG12.W_CUBE), newZ, Fq12);
        }
        assertValidity() {
            const b = new Fq2(exports.CURVE.b2);
            if (this.jpoint.isZero())
                return;
            const { x, y, z } = this.jpoint;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq2');
        }
    }
    PointG2.BASE = new ProjectivePoint(new Fq2(exports.CURVE.G2x), new Fq2(exports.CURVE.G2y), Fq2.ONE, Fq2);
    PointG2.ZERO = new ProjectivePoint(Fq2.ONE, Fq2.ONE, Fq2.ZERO, Fq2);
    return PointG2;
})();
exports.PointG2 = PointG2;
let PointG12 = (() => {
    class PointG12 {
    }
    PointG12.B = new Fq12([4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    PointG12.W_SQUARE = new Fq12([0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    PointG12.W_CUBE = new Fq12([0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    return PointG12;
})();
exports.PointG12 = PointG12;
function createLineBetween(p1, p2, t) {
    const [X1, Y1, Z1] = [p1.x, p1.y, p1.z];
    const [X2, Y2, Z2] = [p2.x, p2.y, p2.z];
    const [XT, YT, ZT] = [t.x, t.y, t.z];
    let num = Y2.multiply(Z1).subtract(Y1.multiply(Z2));
    let den = X2.multiply(Z1).subtract(X1.multiply(Z2));
    if (!num.isZero() && den.isZero()) {
        return [XT.multiply(Z1).subtract(X1.multiply(ZT)), Z1.multiply(ZT)];
    }
    else if (num.isZero()) {
        num = X1.square().multiply(3n);
        den = Y1.multiply(Z1).multiply(2n);
    }
    const numeratorLine = num.multiply(XT.multiply(Z1).subtract(X1.multiply(ZT)));
    const denominatorLine = den.multiply(YT.multiply(Z1).subtract(Y1.multiply(ZT)));
    const z = den.multiply(ZT).multiply(Z1);
    return [numeratorLine.subtract(denominatorLine), z];
}
const PSEUDO_BINARY_ENCODING = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];
const finalExp = (exports.CURVE.P ** 12n - 1n) / exports.CURVE.r;
function finalExponentiate(p) {
    return p.pow(finalExp);
}
function millerLoop(Q, P, withFinalExponent) {
    const one = Fq12.ONE;
    if (Q.isZero() || P.isZero()) {
        return one;
    }
    let R = Q;
    let num = one;
    let den = one;
    for (let i = PSEUDO_BINARY_ENCODING.length - 2; i >= 0n; i--) {
        const [n, d] = createLineBetween(R, R, P);
        num = num.square().multiply(n);
        den = den.square().multiply(d);
        R = R.double();
        if (PSEUDO_BINARY_ENCODING[i] === 1) {
            const [n, d] = createLineBetween(R, Q, P);
            num = num.multiply(n);
            den = den.multiply(d);
            R = R.add(Q);
        }
    }
    const f = num.div(den);
    return withFinalExponent ? finalExponentiate(f) : f;
}
function pairing(P, Q, withFinalExponent = true) {
    const p = new PointG1(P);
    const q = new PointG2(Q);
    p.assertValidity();
    q.assertValidity();
    return millerLoop(q.toFq12(), p.toFq12(), withFinalExponent);
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    return PointG1.fromPrivateKey(privateKey).toCompressedHex();
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    const msgPoint = await PointG2.hashToCurve(message);
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    const S = new PointG2(sigPoint);
    return S.toSignature();
}
exports.sign = sign;
async function verify(signature, message, publicKey) {
    const P = PointG1.fromCompressedHex(publicKey).negate();
    const Hm = await PointG2.hashToCurve(message);
    const G = PointG1.BASE;
    const S = PointG2.fromSignature(signature);
    const ePHm = pairing(P, Hm, false);
    const eGS = pairing(G, S, false);
    const exp = finalExponentiate(eGS.multiply(ePHm));
    return exp.equals(Fq12.ONE);
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    const aggregatedPublicKey = publicKeys.reduce((sum, publicKey) => sum.add(PointG1.fromCompressedHex(publicKey)), PointG1.ZERO);
    return new PointG1(aggregatedPublicKey).toCompressedHex();
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
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message
                ? groupPublicKey
                : groupPublicKey.add(PointG1.fromCompressedHex(publicKeys[i])), PointG1.ZERO);
            const msg = await PointG2.hashToCurve(message);
            producer = producer.multiply(pairing(groupPublicKey, msg, false));
        }
        const sig = PointG2.fromSignature(signature);
        producer = producer.multiply(pairing(PointG1.BASE.negate(), sig, false));
        const finalExponent = finalExponentiate(producer);
        return finalExponent.equals(Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
