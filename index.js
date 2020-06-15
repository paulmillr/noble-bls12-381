"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.clearCofactorG2 = exports.PointG1 = exports.hash_to_field = exports.utils = exports.CURVE = exports.Fq12 = exports.Fq2 = exports.Fr = exports.Fq = exports.DST_LABEL = void 0;
const math_1 = require("./math");
Object.defineProperty(exports, "Fq", { enumerable: true, get: function () { return math_1.Fq; } });
Object.defineProperty(exports, "Fr", { enumerable: true, get: function () { return math_1.Fr; } });
Object.defineProperty(exports, "Fq2", { enumerable: true, get: function () { return math_1.Fq2; } });
Object.defineProperty(exports, "Fq12", { enumerable: true, get: function () { return math_1.Fq12; } });
Object.defineProperty(exports, "CURVE", { enumerable: true, get: function () { return math_1.CURVE; } });
const P = math_1.CURVE.P;
exports.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
exports.utils = {
    async sha256(message) {
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
    },
    mod: math_1.mod
};
function hexToNumberBE(hex) {
    return BigInt(`0x${hex}`);
}
function bytesToNumberBE(bytes) {
    if (typeof bytes === 'string') {
        return hexToNumberBE(bytes);
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
    return concatBytes(new Uint8Array(elements), bytes);
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
    if (typeof num === 'string')
        return hexToNumberBE(num);
    if (typeof num === 'number')
        return BigInt(num);
    if (num instanceof Uint8Array)
        return bytesToNumberBE(num);
    return num;
}
function hexToBytes(hex) {
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
function concatBytes(...bytes) {
    return new Uint8Array(bytes.reduce((res, bytesView) => {
        bytesView = bytesView instanceof Uint8Array ? bytesView : hexToBytes(bytesView);
        return [...res, ...bytesView];
    }, []));
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
    const H = exports.utils.sha256;
    const b_in_bytes = Number(SHA256_DIGEST_SIZE);
    const r_in_bytes = b_in_bytes * 2;
    const ell = Math.ceil(len_in_bytes / b_in_bytes);
    if (ell > 255)
        throw new Error('Invalid xmd length');
    const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(len_in_bytes, 2);
    const b = new Array(ell);
    const b_0 = await H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = await H(concatBytes(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = await H(concatBytes(...args));
    }
    const pseudo_random_bytes = concatBytes(...b);
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
            e[j] = math_1.mod(os2ip(tv), math_1.CURVE.P);
        }
        u[i] = e;
    }
    return u;
}
exports.hash_to_field = hash_to_field;
function normalizePrivKey(privateKey) {
    return new math_1.Fq(toBigInt(privateKey));
}
let PointG1 = (() => {
    class PointG1 extends math_1.ProjectivePoint {
        constructor(x, y, z) {
            super(x, y, z, math_1.Fq);
        }
        static fromCompressedHex(hex) {
            const compressedValue = bytesToNumberBE(hex);
            const bflag = math_1.mod(compressedValue, POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = math_1.mod(compressedValue, POW_2_381);
            const fullY = math_1.mod(x ** 3n + new math_1.Fq(math_1.CURVE.b).value, P);
            let y = math_1.powMod(fullY, (P + 1n) / 4n, P);
            if (math_1.powMod(y, 2n, P) - fullY !== 0n) {
                throw new Error('The given point is not on G1: y**2 = x**3 + b');
            }
            const aflag = math_1.mod(compressedValue, POW_2_382) / POW_2_381;
            if ((y * 2n) / P !== aflag) {
                y = P - y;
            }
            const p = new PointG1(new math_1.Fq(x), new math_1.Fq(y), new math_1.Fq(1n));
            return p;
        }
        static fromPrivateKey(privateKey) {
            return this.BASE.multiply(normalizePrivKey(privateKey));
        }
        toCompressedHex() {
            let hex;
            if (this.equals(PointG1.ZERO)) {
                hex = POW_2_383 + POW_2_382;
            }
            else {
                const [x, y] = this.toAffine();
                const flag = (y.value * 2n) / P;
                hex = x.value + flag * POW_2_381 + POW_2_383;
            }
            return toBytesBE(hex, PUBLIC_KEY_LENGTH);
        }
        assertValidity() {
            const b = new math_1.Fq(math_1.CURVE.b);
            if (this.isZero())
                return;
            const { x, y, z } = this;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq');
        }
        millerLoop(P) {
            return math_1.millerLoop(P.pairingPrecomputes(), this.toAffine());
        }
    }
    PointG1.BASE = new PointG1(new math_1.Fq(math_1.CURVE.Gx), new math_1.Fq(math_1.CURVE.Gy), math_1.Fq.ONE);
    PointG1.ZERO = new PointG1(math_1.Fq.ONE, math_1.Fq.ONE, math_1.Fq.ZERO);
    return PointG1;
})();
exports.PointG1 = PointG1;
function clearCofactorG2(P) {
    const t1 = P.multiplyUnsafe(math_1.CURVE.x).negate();
    const t2 = P.fromAffineTuple(math_1.psi(...P.toAffine()));
    const p2 = P.fromAffineTuple(math_1.psi2(...P.double().toAffine()));
    return p2
        .subtract(t2)
        .add(t1.add(t2).multiplyUnsafe(math_1.CURVE.x).negate())
        .subtract(t1)
        .subtract(P);
}
exports.clearCofactorG2 = clearCofactorG2;
let PointG2 = (() => {
    class PointG2 extends math_1.ProjectivePoint {
        constructor(x, y, z) {
            super(x, y, z, math_1.Fq2);
        }
        static async hashToCurve(msg) {
            if (typeof msg === 'string')
                msg = hexToBytes(msg);
            const u = await hash_to_field(msg, 2);
            const Q0 = new PointG2(...math_1.isogenyMapG2(math_1.map_to_curve_SSWU_G2(u[0])));
            const Q1 = new PointG2(...math_1.isogenyMapG2(math_1.map_to_curve_SSWU_G2(u[1])));
            const R = Q0.add(Q1);
            const P = clearCofactorG2(R);
            return P;
        }
        static fromSignature(hex) {
            const half = hex.length / 2;
            const z1 = bytesToNumberBE(hex.slice(0, half));
            const z2 = bytesToNumberBE(hex.slice(half));
            const bflag1 = math_1.mod(z1, POW_2_383) / POW_2_382;
            if (bflag1 === 1n)
                return this.ZERO;
            const x1 = z1 % POW_2_381;
            const x2 = z2;
            const x = new math_1.Fq2([x2, x1]);
            let y = x.pow(3n).add(new math_1.Fq2(math_1.CURVE.b2)).sqrt();
            if (!y)
                throw new Error('Failed to find a square root');
            const [y0, y1] = y.values;
            const aflag1 = (z1 % POW_2_382) / POW_2_381;
            const isGreater = y1 > 0n && (y1 * 2n) / P !== aflag1;
            const isZero = y1 === 0n && (y0 * 2n) / P !== aflag1;
            if (isGreater || isZero)
                y = y.multiply(-1n);
            const point = new PointG2(x, y, math_1.Fq2.ONE);
            point.assertValidity();
            return point;
        }
        static fromPrivateKey(privateKey) {
            return this.BASE.multiply(normalizePrivKey(privateKey));
        }
        toSignature() {
            if (this.equals(PointG2.ZERO)) {
                const sum = POW_2_383 + POW_2_382;
                return concatBytes(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
            }
            this.assertValidity();
            const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
            const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
            const aflag1 = tmp / math_1.CURVE.P;
            const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
            const z2 = x0;
            return concatBytes(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
        }
        assertValidity() {
            const b = new math_1.Fq2(math_1.CURVE.b2);
            if (this.isZero())
                return;
            const { x, y, z } = this;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq2');
        }
        clearPairingPrecomputes() {
            this._PPRECOMPUTES = undefined;
        }
        pairingPrecomputes() {
            if (this._PPRECOMPUTES)
                return this._PPRECOMPUTES;
            this._PPRECOMPUTES = math_1.calcPairingPrecomputes(...this.toAffine());
            return this._PPRECOMPUTES;
        }
    }
    PointG2.BASE = new PointG2(new math_1.Fq2(math_1.CURVE.G2x), new math_1.Fq2(math_1.CURVE.G2y), math_1.Fq2.ONE);
    PointG2.ZERO = new PointG2(math_1.Fq2.ONE, math_1.Fq2.ONE, math_1.Fq2.ZERO);
    return PointG2;
})();
exports.PointG2 = PointG2;
function pairing(P, Q, withFinalExponent = true) {
    if (P.isZero() || Q.isZero())
        throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    let res = P.millerLoop(Q);
    return withFinalExponent ? res.finalExponentiate() : res;
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    return PointG1.fromPrivateKey(privateKey).toCompressedHex();
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    const msgPoint = await PointG2.hashToCurve(message);
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    return sigPoint.toSignature();
}
exports.sign = sign;
async function verify(signature, message, publicKey) {
    const P = PointG1.fromCompressedHex(publicKey).negate();
    const Hm = await PointG2.hashToCurve(message);
    const G = PointG1.BASE;
    const S = PointG2.fromSignature(signature);
    const ePHm = pairing(P, Hm, false);
    const eGS = pairing(G, S, false);
    const exp = eGS.multiply(ePHm).finalExponentiate();
    return exp.equals(math_1.Fq12.ONE);
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    return publicKeys.reduce((sum, publicKey) => sum.add(PointG1.fromCompressedHex(publicKey)), PointG1.ZERO);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (!signatures.length)
        throw new Error('Expected non-empty array');
    const aggregatedSignature = signatures.reduce((sum, signature) => sum.add(PointG2.fromSignature(signature)), PointG2.ZERO);
    return aggregatedSignature.toSignature();
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(messages, publicKeys, signature) {
    if (!messages.length)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    try {
        let producer = math_1.Fq12.ONE;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message
                ? groupPublicKey
                : groupPublicKey.add(PointG1.fromCompressedHex(publicKeys[i])), PointG1.ZERO);
            const msg = await PointG2.hashToCurve(message);
            producer = producer.multiply(pairing(groupPublicKey, msg, false));
        }
        const sig = PointG2.fromSignature(signature);
        producer = producer.multiply(pairing(PointG1.BASE.negate(), sig, false));
        const finalExponent = producer.finalExponentiate();
        return finalExponent.equals(math_1.Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
PointG1.BASE.calcMultiplyPrecomputes(4);
