"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.G2 = exports.G1 = exports.hashToG2 = exports.signatureToG2 = exports.thash_to_curve = exports.hash_to_field = exports.B12 = exports.B2 = exports.B = exports.Point = exports.Fp12 = exports.Fp2 = exports.Fp = exports.CURVE = void 0;
const { getTime } = require('micro-bmark');
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    h: 0x396c8c005555e1568c00aaab0000aaabn,
    Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    Gy: 0x8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
    P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn ** 2n - 1n,
    h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
    G2x: [
        0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
    ],
    G2y: [
        0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
    ],
};
const P = exports.CURVE.P;
const DST_LABEL = 'BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN';
function fpToString(num) {
    const str = num.toString(16).padStart(96, '0');
    return str.slice(0, 4) + '...' + str.slice(-4);
}
let Fp = (() => {
    class Fp {
        constructor(value) {
            this._value = mod(value, Fp.ORDER);
        }
        get value() {
            return this._value;
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
        negate() {
            return new Fp(-this._value);
        }
        invert() {
            return new Fp(invert(this._value, Fp.ORDER));
        }
        add(other) {
            return new Fp(this._value + other.value);
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
            return new Fp(this._value * other._value);
        }
        div(other) {
            return this.multiply(other.invert());
        }
        toString() {
            return fpToString(this.value);
        }
    }
    Fp.ORDER = exports.CURVE.P;
    Fp.ZERO = new Fp(0n);
    Fp.ONE = new Fp(1n);
    return Fp;
})();
exports.Fp = Fp;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
let Fp2 = (() => {
    class Fp2 {
        constructor(real, imag) {
            this.real = real instanceof Fp ? real : new Fp(real);
            this.imag = imag instanceof Fp ? imag : new Fp(imag);
        }
        get value() {
            return [this.real.value, this.imag.value];
        }
        toString() {
            const c1 = this.real.toString();
            const c2 = this.imag.toString();
            return `(${c1} + ${c2}×i)`;
        }
        isEmpty() {
            return this.real.isEmpty() && this.imag.isEmpty();
        }
        equals(rhs) {
            return this.real.equals(rhs.real) && this.imag.equals(rhs.imag);
        }
        negate() {
            return new Fp2(this.real.negate(), this.imag.negate());
        }
        add(rhs) {
            return new Fp2(this.real.add(rhs.real), this.imag.add(rhs.imag));
        }
        subtract(rhs) {
            return new Fp2(this.real.subtract(rhs.real), this.imag.subtract(rhs.imag));
        }
        multiply(rhs) {
            if (typeof rhs === 'bigint') {
                return new Fp2(this.real.multiply(new Fp(rhs)), this.imag.multiply(new Fp(rhs)));
            }
            if (this.constructor !== rhs.constructor)
                throw new TypeError('Types do not match');
            const a1 = [this.real, this.imag];
            const b1 = [rhs.real, rhs.imag];
            const c1 = [Fp.ZERO, Fp.ZERO];
            const embedding = 2;
            for (let i = 0; i < embedding; i++) {
                const x = a1[i];
                for (let j = 0; j < embedding; j++) {
                    const y = b1[j];
                    if (!x.isEmpty() && !y.isEmpty()) {
                        const degree = i + j;
                        const md = degree % embedding;
                        let xy = x.multiply(y);
                        const root = Fp2.ROOT;
                        if (degree >= embedding)
                            xy = xy.multiply(root);
                        c1[md] = c1[md].add(xy);
                    }
                }
            }
            const [real, imag] = c1;
            return new Fp2(real, imag);
        }
        mulByNonresidue() {
            return new Fp2(this.real.subtract(this.imag), this.real.add(this.imag));
        }
        square() {
            const a = this.real.add(this.imag);
            const b = this.real.subtract(this.imag);
            const c = this.real.add(this.real);
            return new Fp2(a.multiply(b), c.multiply(this.imag));
        }
        sqrt() {
            const candidateSqrt = this.pow(Fp2.DIV_ORDER);
            const check = candidateSqrt.square().div(this);
            const rootIndex = Fp2.EIGHTH_ROOTS_OF_UNITY.findIndex((a) => a.equals(check));
            if (rootIndex === -1 || (rootIndex & 1) === 1) {
                return null;
            }
            const x1 = candidateSqrt.div(Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]);
            const x2 = x1.negate();
            const isImageGreater = x1.imag.value > x2.imag.value;
            const isReconstructedGreater = x1.imag.equals(x2.imag) && x1.real.value > x2.real.value;
            return isImageGreater || isReconstructedGreater ? x1 : x2;
        }
        pow(n) {
            if (n === 0n)
                return Fp2.ONE;
            if (n === 1n)
                return this;
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
            const t = this.real.square().add(this.imag.square()).invert();
            return new Fp2(this.real.multiply(t), this.imag.multiply(t.negate()));
        }
        div(otherValue) {
            if (typeof otherValue === 'bigint') {
                return new Fp2(this.real.div(otherValue), this.imag.div(otherValue));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp2.ORDER = exports.CURVE.P2;
    Fp2.DIV_ORDER = (Fp2.ORDER + 8n) / 16n;
    Fp2.ROOT = new Fp(-1n);
    Fp2.ZERO = new Fp2(0n, 0n);
    Fp2.ONE = new Fp2(1n, 0n);
    Fp2.EIGHTH_ROOTS_OF_UNITY = [
        new Fp2(1n, 0n),
        new Fp2(0n, 1n),
        new Fp2(rv1, rv1),
        new Fp2(rv1, Fp2.ORDER - rv1)
    ];
    Fp2.COFACTOR = exports.CURVE.h2;
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
        negate() {
            return new Fp12(...this.coefficients.map((a) => a.negate()));
        }
        add(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.add(rhs.coefficients[i])));
        }
        subtract(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.subtract(rhs.coefficients[i])));
        }
        multiply(otherValue) {
            if (typeof otherValue === 'bigint') {
                return new Fp12(...this.coefficients.map((a) => a.multiply(new Fp(otherValue))));
            }
            const LENGTH = this.coefficients.length;
            const filler = Array(LENGTH * 2 - 1)
                .fill(null)
                .map(() => new Fp(0n));
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
                    filler[exp + i] = filler[exp + i].subtract(top.multiply(new Fp(value)));
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
            let lm = [...Fp12.ONE.coefficients.map((a) => a.value), 0n];
            let hm = [...Fp12.ZERO.coefficients.map((a) => a.value), 0n];
            let low = [...this.coefficients.map((a) => a.value), 0n];
            let high = [...Fp12.MODULE_COEFFICIENTS, 1n];
            while (this.degree(low) !== 0) {
                const { coefficients } = this.optimizedRoundedDiv(high, low);
                const zeros = Array(LENGTH + 1 - coefficients.length)
                    .fill(null)
                    .map(() => new Fp(0n));
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
                return new Fp12(...this.coefficients.map((a) => a.div(new Fp(otherValue))));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp12.ZERO = new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    Fp12.ONE = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
    Fp12.MODULE_COEFFICIENTS = [
        2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
    ];
    Fp12.ENTRY_COEFFICIENTS = [
        [0, 2n],
        [6, -2n],
    ];
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
        return this.x.isEmpty() && this.y.isEmpty() && this.z.equals(this.C.ONE);
    }
    isOnCurve(b) {
        if (this.isEmpty()) {
            return true;
        }
        const squaredY = this.y.square();
        const cubedX = this.x.pow(3n);
        const z6 = this.z.pow(6n);
        const infty = this.x.isEmpty() && !this.y.isEmpty() && this.z.isEmpty();
        const match = squaredY.equals(b.multiply(z6).add(cubedX));
        return infty || match;
    }
    equals(other) {
        return (this.x.multiply(other.z).equals(other.x.multiply(this.z)) &&
            this.y.multiply(other.z).equals(other.y.multiply(this.z)));
    }
    negative() {
        return new Point(this.x, this.y.negate(), this.z, this.C);
    }
    toString() {
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
    }
    toAffine() {
        const zInv = this.z.pow(3n).invert();
        return [this.x.multiply(this.z).multiply(zInv), this.y.multiply(zInv)];
    }
    double() {
        if (this.isEmpty())
            return this;
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
        const Y3 = E.multiply((D.subtract(X3)).subtract(C.multiply(8n)));
        const Z3 = Y1.multiply(Z1).multiply(2n);
        if (Z3.isEmpty())
            return new Point(this.C.ZERO, this.C.ONE, this.C.ZERO, this.C);
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
        if (Z2.isEmpty())
            return this;
        if (Z1.isEmpty())
            return other;
        const Z1Z1 = Z1.pow(2n);
        const Z2Z2 = Z2.pow(2n);
        const U1 = X1.multiply(Z2Z2);
        const U2 = X2.multiply(Z1Z1);
        const S1 = Y1.multiply(Z2).multiply(Z2Z2);
        const S2 = Y2.multiply(Z1).multiply(Z1Z1);
        const H = U2.subtract(U1);
        const rr = S2.subtract(S1).multiply(2n);
        if (H.isEmpty()) {
            if (rr.isEmpty()) {
                return this.double();
            }
            else {
                throw new Error();
                return new Point(this.C.ZERO, this.C.ZERO, this.C.ONE, this.C);
            }
        }
        const I = H.multiply(2n).pow(2n);
        const J = H.multiply(I);
        const V = U1.multiply(I);
        const X3 = rr.pow(2n).subtract(J).subtract(V.multiply(2n));
        const Y3 = rr.multiply(V.subtract(X3)).subtract(S1.multiply(J).multiply(2n));
        const Z3 = Z1.multiply(Z2).multiply(H).multiply(2n);
        return new Point(X3, Y3, Z3, this.C);
    }
    subtract(other) {
        return this.add(other.negative());
    }
    multiply(n) {
        n = BigInt(n);
        this.C.prototype;
        let result = new Point(this.C.ONE, this.C.ONE, this.C.ZERO, this.C);
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
function evalIsogeny(p, coefficients) {
    const { x, y, z } = p;
    const vals = new Array(4);
    const maxOrd = Math.max(...coefficients.map(a => a.length));
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
function finalExponentiate(p) {
    return p.pow((exports.CURVE.P ** 12n - 1n) / exports.CURVE.r);
}
exports.B = new Fp(4n);
exports.B2 = new Fp2(4n, 4n);
exports.B12 = new Fp12(4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
const Z1 = new Point(new Fp(1n), new Fp(1n), new Fp(0n), Fp);
const Z2 = new Point(new Fp2(1n, 0n), new Fp2(1n, 0n), new Fp2(0n, 0n), Fp2);
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
const P_ORDER_X_9 = (P ** 2n - 9n) / 16n;
const kQix = new Fp(0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn);
const kQiy = new Fp(0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n);
const kCx = new Fp2(0n, 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn);
const kCy = new Fp2(0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n, 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n);
const IWSC = 0xd0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556n;
const iwsc = new Fp2(IWSC, IWSC - 1n);
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
        const args = [
            strxor(b_0, b[i - 1]),
            i2osp(i + 1, 1),
            DST_prime
        ];
        b[i] = await H(concatTypedArrays(...args));
    }
    const pseudo_random_bytes = concatTypedArrays(...b);
    return pseudo_random_bytes.slice(0, len_in_bytes);
}
const toHex = (n) => {
    if (typeof n === 'bigint')
        return n.toString(16);
    if (n instanceof Uint8Array)
        n = Array.from(n);
    return n.map((item) => {
        return typeof item === 'string' ? item : item.toString(16);
    }).join('');
};
async function hash_to_field(msg, count) {
    const m = 2;
    const L = 64;
    const len_in_bytes = count * m * L;
    const DST = stringToBytes(DST_LABEL);
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
async function thash_to_curve(msg) {
    const [tuple1, tuple2] = await hash_to_field(msg, 2);
    const t1 = new Fp2(tuple1[0], tuple1[1]);
    const t2 = new Fp2(tuple2[0], tuple2[1]);
    return opt_swu2_map(t1, t2);
}
exports.thash_to_curve = thash_to_curve;
function getSign(xi, thresh, sign) {
    if (xi > thresh) {
        return sign || -1n;
    }
    if (xi > 0n) {
        return sign || 1n;
    }
    return sign;
}
function sign0(x) {
    const thresh = (P - 1n) / 2n;
    const [x1, x2] = x.value;
    let sign = 0n;
    sign = getSign(x2, thresh, sign);
    sign = getSign(x1, thresh, sign);
    return sign === 0n ? 1n : sign;
}
const Ell2p_a = new Fp2(0n, 240n);
const Ell2p_b = new Fp2(1012n, 1012n);
const xi_2 = new Fp2(-2n, -1n);
const rootsOfUnity = [
    new Fp2(1n, 0n),
    new Fp2(0n, 1n),
    new Fp2(rv1, rv1),
    new Fp2(rv1, -rv1)
];
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
const etas = [
    new Fp2(ev1, ev2),
    new Fp2(-ev2, ev1),
    new Fp2(ev3, ev4),
    new Fp2(-ev4, ev3)
];
function osswu2_help(t) {
    console.log('osswu2_help', t.toString());
    const denominator = xi_2.square()
        .multiply(t.pow(4n))
        .add(xi_2.multiply(t.square()));
    const x0_num = Ell2p_b.multiply(denominator.add(Fp2.ONE));
    const tmp = Ell2p_a.negate().multiply(denominator);
    const x0_den = tmp.equals(Fp2.ZERO) ? Ell2p_a.multiply(xi_2) : tmp;
    console.log('x0_den', denominator.toString(), x0_den.toString());
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
            y0 = y0.multiply(sign0(y0) * sign0(t));
            return new Point(x0_num.multiply(x0_den), y0.multiply(x0_den.pow(3n)), x0_den, Fp2);
        }
    }
    const x1_num = xi_2.multiply(t.square()).multiply(x0_num);
    const x1_den = x0_den;
    const gx1_num = xi_2.pow(3n)
        .multiply(t.pow(6n))
        .multiply(gx0_num);
    const gx1_den = gx0_den;
    sqrt_candidate = sqrt_candidate.multiply(t.pow(3n));
    for (const eta of etas) {
        const y1 = sqrt_candidate.multiply(eta);
        const candidate = y1.square().multiply(gx1_den);
        if (candidate.equals(gx1_num)) {
            const y = y1.multiply(sign0(y1) * sign0(t));
            console.log('sqrt 2');
            return new Point(x1_num.multiply(x1_den), y.multiply(x1_den.pow(3n)), x1_den, Fp2);
        }
    }
    throw new Error("osswu2help failed for unknown reasons!");
}
const xnum = [
    new Fp2(0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n, 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n),
    new Fp2(0x0n, 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an),
    new Fp2(0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en, 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn),
    new Fp2(0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n, 0x0n)
];
const xden = [
    new Fp2(0x0n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n),
    new Fp2(0xcn, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn),
    new Fp2(0x1n, 0x0n)
];
const ynum = [
    new Fp2(0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n, 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n),
    new Fp2(0x0n, 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben),
    new Fp2(0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn, 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn),
    new Fp2(0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n, 0x0n)
];
const yden = [
    new Fp2(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn),
    new Fp2(0x0n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n),
    new Fp2(0x12n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n),
    new Fp2(0x1n, 0x0n)
];
function computeIsogeny3(p) {
    return evalIsogeny(p, [xnum, xden, ynum, yden]);
}
function clear_cofactor_bls12381_g2(point) {
    return point.multiply(exports.CURVE.h2);
}
function opt_swu2_map(u1, u2) {
    console.log('opt_swu2_map');
    console.log('u1=', u1.toString());
    console.log('u2=', u2?.toString());
    let point = osswu2_help(u1);
    if (u2 instanceof Fp2) {
        const point2 = osswu2_help(u2);
        console.log('preiso', point.toString(), point2.toString());
        point = point.add(point2);
        console.log('preiso2', point.toString());
    }
    const iso = computeIsogeny3(point);
    console.log(`iso ${iso}`);
    return clear_cofactor_bls12381_g2(iso);
}
const POW_SUM = POW_2_383 + POW_2_382;
function compressG1(point) {
    if (point.equals(Z1)) {
        return POW_SUM;
    }
    const [x, y] = point.toAffine();
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
    const [[x0, x1], [y0, y1]] = point.toAffine().map((a) => a.value);
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
    let y = x.pow(3n).add(exports.B2).sqrt();
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
    const point = new Point(x, y, Fp2.ONE, Fp2);
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
    return new Uint8Array([hash, domain]);
}
exports.hashToG2 = hashToG2;
exports.G1 = new Point(new Fp(exports.CURVE.Gx), new Fp(exports.CURVE.Gy), Fp.ONE, Fp);
exports.G2 = new Point(new Fp2(exports.CURVE.G2x[0], exports.CURVE.G2x[1]), new Fp2(exports.CURVE.G2y[0], exports.CURVE.G2y[1]), Fp2.ONE, Fp2);
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
    if (!Q.isOnCurve(exports.B2))
        throw new Error("Point 1 is not on curve");
    if (!P.isOnCurve(exports.B))
        throw new Error("Point 2 is not on curve");
    return millerLoop(Q.twist(), castPointToFp12(P), withFinalExponent);
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    privateKey = toBigInt(privateKey);
    return publicKeyFromG1(exports.G1.multiply(privateKey));
}
exports.getPublicKey = getPublicKey;
const DOMAIN_LENGTH = 8;
async function sign(message, privateKey, domain) {
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
    privateKey = toBigInt(privateKey);
    const messageValue = await hashToG2(message, domain);
    const signature = messageValue.multiply(privateKey);
    return signatureFromG2(signature);
}
exports.sign = sign;
async function verify(message, publicKey, signature, domain) {
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
    const publicKeyPoint = publicKeyToG1(publicKey).negative();
    const signaturePoint = signatureToG2(signature);
    try {
        const signaturePairing = pairing(signaturePoint, exports.G1);
        const hashPairing = pairing(await hashToG2(message, domain), publicKeyPoint);
        const finalExponent = finalExponentiate(signaturePairing.multiply(hashPairing));
        return finalExponent.equals(Fp12.ONE);
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
    domain = domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
    if (messages.length === 0)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    try {
        let producer = Fp12.ONE;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message ? groupPublicKey : groupPublicKey.add(publicKeyToG1(publicKeys[i])), Z1);
            producer = producer.multiply(pairing(await hashToG2(message, domain), groupPublicKey));
        }
        producer = producer.multiply(pairing(signatureToG2(signature), exports.G1.negative()));
        const finalExponent = finalExponentiate(producer);
        return finalExponent.equals(Fp12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
