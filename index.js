"use strict";
/*! noble-bls12-381 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.PointG1 = exports.hash_to_field = exports.utils = exports.DST_LABEL = exports.CURVE = exports.Fq12 = exports.Fq2 = exports.Fr = exports.Fq = void 0;
const math_1 = require("./math");
Object.defineProperty(exports, "Fq", { enumerable: true, get: function () { return math_1.Fq; } });
Object.defineProperty(exports, "Fr", { enumerable: true, get: function () { return math_1.Fr; } });
Object.defineProperty(exports, "Fq2", { enumerable: true, get: function () { return math_1.Fq2; } });
Object.defineProperty(exports, "Fq12", { enumerable: true, get: function () { return math_1.Fq12; } });
Object.defineProperty(exports, "CURVE", { enumerable: true, get: function () { return math_1.CURVE; } });
exports.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32;
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
    randomPrivateKey: (bytesLength = 32) => {
        if (typeof window == 'object' && 'crypto' in window) {
            return window.crypto.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (typeof process === 'object' && 'node' in process.versions) {
            const { randomBytes } = require('crypto');
            return new Uint8Array(randomBytes(bytesLength).buffer);
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    mod: math_1.mod,
};
function bytesToNumberBE(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2)
        throw new Error('Expected valid hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function toPaddedHex(num, padding) {
    if (num < 0n)
        throw new Error('Expected valid number');
    if (typeof padding !== 'number')
        throw new TypeError('Expected valid padding');
    return num.toString(16).padStart(padding * 2, '0');
}
function expectHex(item) {
    if (typeof item !== 'string' && !(item instanceof Uint8Array)) {
        throw new TypeError('Expected hex string or Uint8Array');
    }
}
function concatBytes(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
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
    const b_in_bytes = SHA256_DIGEST_SIZE;
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
function normalizePrivKey(key) {
    let int;
    if (key instanceof Uint8Array && key.length === 32)
        int = bytesToNumberBE(key);
    else if (typeof key === 'string' && key.length === 64)
        int = BigInt(`0x${key}`);
    else if (typeof key === 'number' && key > 0 && Number.isSafeInteger(key))
        int = BigInt(key);
    else if (typeof key === 'bigint' && key > 0n)
        int = key;
    else
        throw new TypeError('Expected valid private key');
    int = math_1.mod(int, math_1.CURVE.r);
    if (int < 1n)
        throw new Error('Private key must be 0 < key < CURVE.r');
    return int;
}
class PointG1 extends math_1.ProjectivePoint {
    constructor(x, y, z) {
        super(x, y, z, math_1.Fq);
    }
    static fromHex(bytes) {
        expectHex(bytes);
        if (typeof bytes === 'string')
            bytes = hexToBytes(bytes);
        const { P } = math_1.CURVE;
        let point;
        if (bytes.length === 48) {
            const compressedValue = bytesToNumberBE(bytes);
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
            point = new PointG1(new math_1.Fq(x), new math_1.Fq(y), new math_1.Fq(1n));
        }
        else if (bytes.length === 96) {
            if ((bytes[0] & (1 << 6)) !== 0) {
                return PointG1.ZERO;
            }
            const x = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
            const y = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH));
            point = new PointG1(new math_1.Fq(x), new math_1.Fq(y), math_1.Fq.ONE);
        }
        else {
            throw new Error('Invalid point G1, expected 48/96 bytes');
        }
        point.assertValidity();
        return point;
    }
    static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        const { P } = math_1.CURVE;
        if (isCompressed) {
            let hex;
            if (this.equals(PointG1.ZERO)) {
                hex = POW_2_383 + POW_2_382;
            }
            else {
                const [x, y] = this.toAffine();
                const flag = (y.value * 2n) / P;
                hex = x.value + flag * POW_2_381 + POW_2_383;
            }
            return toPaddedHex(hex, PUBLIC_KEY_LENGTH);
        }
        else {
            if (this.equals(PointG1.ZERO)) {
                return '4'.padEnd(2 * 2 * PUBLIC_KEY_LENGTH, '0');
            }
            else {
                const [x, y] = this.toAffine();
                return toPaddedHex(x.value, PUBLIC_KEY_LENGTH) + toPaddedHex(y.value, PUBLIC_KEY_LENGTH);
            }
        }
    }
    assertValidity() {
        if (this.isZero())
            return;
        if (!this.isOnCurve())
            throw new Error('Invalid point: not on curve Fq');
        if (!this.isTorsionFree())
            throw new Error('Invalid point: must be of prime-order subgroup');
    }
    toRepr() {
        return [this.x, this.y, this.z].map((v) => v.value);
    }
    millerLoop(P) {
        return math_1.millerLoop(P.pairingPrecomputes(), this.toAffine());
    }
    isOnCurve() {
        const b = new math_1.Fq(math_1.CURVE.b);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).equals(math_1.Fq.ZERO);
    }
    isTorsionFree() {
        return !this.multiplyUnsafe(math_1.CURVE.h).isZero();
    }
}
exports.PointG1 = PointG1;
PointG1.BASE = new PointG1(new math_1.Fq(math_1.CURVE.Gx), new math_1.Fq(math_1.CURVE.Gy), math_1.Fq.ONE);
PointG1.ZERO = new PointG1(math_1.Fq.ONE, math_1.Fq.ONE, math_1.Fq.ZERO);
class PointG2 extends math_1.ProjectivePoint {
    constructor(x, y, z) {
        super(x, y, z, math_1.Fq2);
    }
    _clearCofactorG2() {
        const P = this;
        const t1 = P.multiplyUnsafe(math_1.CURVE.x).negate();
        const t2 = P.psi();
        const p2 = P.fromAffineTuple(math_1.psi2(...P.double().toAffine()));
        return p2
            .subtract(t2)
            .add(t1.add(t2).multiplyUnsafe(math_1.CURVE.x).negate())
            .subtract(t1)
            .subtract(P);
    }
    static async hashToCurve(msg) {
        expectHex(msg);
        if (typeof msg === 'string')
            msg = hexToBytes(msg);
        const u = await hash_to_field(msg, 2);
        const Q0 = new PointG2(...math_1.isogenyMapG2(math_1.map_to_curve_SSWU_G2(u[0])));
        const Q1 = new PointG2(...math_1.isogenyMapG2(math_1.map_to_curve_SSWU_G2(u[1])));
        const R = Q0.add(Q1);
        const P = R._clearCofactorG2();
        return P;
    }
    static fromSignature(hex) {
        expectHex(hex);
        if (typeof hex === 'string')
            hex = hexToBytes(hex);
        const { P } = math_1.CURVE;
        const half = hex.length / 2;
        if (half !== 48 && half !== 96)
            throw new Error('Invalid compressed signature length, must be 96 or 192');
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
    static fromHex(bytes) {
        expectHex(bytes);
        if (typeof bytes === 'string')
            bytes = hexToBytes(bytes);
        let point;
        if (bytes.length === 96) {
            throw new Error('Compressed format not supported yet.');
        }
        else if (bytes.length === 192) {
            if ((bytes[0] & (1 << 6)) !== 0) {
                return PointG2.ZERO;
            }
            const x1 = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
            const x0 = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH, 2 * PUBLIC_KEY_LENGTH));
            const y1 = bytesToNumberBE(bytes.slice(2 * PUBLIC_KEY_LENGTH, 3 * PUBLIC_KEY_LENGTH));
            const y0 = bytesToNumberBE(bytes.slice(3 * PUBLIC_KEY_LENGTH));
            point = new PointG2(new math_1.Fq2([x0, x1]), new math_1.Fq2([y0, y1]), math_1.Fq2.ONE);
        }
        else {
            throw new Error('Invalid uncompressed point G2, expected 192 bytes');
        }
        point.assertValidity();
        return point;
    }
    static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
    }
    toSignature() {
        if (this.equals(PointG2.ZERO)) {
            const sum = POW_2_383 + POW_2_382;
            return toPaddedHex(sum, PUBLIC_KEY_LENGTH) + toPaddedHex(0n, PUBLIC_KEY_LENGTH);
        }
        this.assertValidity();
        const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
        const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
        const aflag1 = tmp / math_1.CURVE.P;
        const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
        const z2 = x0;
        return toPaddedHex(z1, PUBLIC_KEY_LENGTH) + toPaddedHex(z2, PUBLIC_KEY_LENGTH);
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        if (isCompressed) {
            throw new Error('Not supported');
        }
        else {
            if (this.equals(PointG2.ZERO)) {
                return '4'.padEnd(2 * 4 * PUBLIC_KEY_LENGTH, '0');
            }
            else {
                this.assertValidity();
                const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
                return (toPaddedHex(x1, PUBLIC_KEY_LENGTH) +
                    toPaddedHex(x0, PUBLIC_KEY_LENGTH) +
                    toPaddedHex(y1, PUBLIC_KEY_LENGTH) +
                    toPaddedHex(y0, PUBLIC_KEY_LENGTH));
            }
        }
    }
    assertValidity() {
        if (this.isZero())
            return;
        if (!this.isOnCurve())
            throw new Error('Invalid point: not on curve Fq2');
        if (!this.isTorsionFree())
            throw new Error('Invalid point: must be of prime-order subgroup');
    }
    psi() {
        return this.fromAffineTuple(math_1.psi(...this.toAffine()));
    }
    isOnCurve() {
        const b = new math_1.Fq2(math_1.CURVE.b2);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).equals(math_1.Fq2.ZERO);
    }
    isTorsionFree() {
        const psi1 = this.psi();
        const psi2 = psi1.psi();
        const psi3 = psi2.psi();
        const zPsi3 = psi3.multiplyUnsafe(math_1.CURVE.x).negate();
        return zPsi3.subtract(psi2).add(this).isZero();
    }
    toRepr() {
        return [this.x, this.y, this.z].map((v) => v.values);
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
exports.PointG2 = PointG2;
PointG2.BASE = new PointG2(new math_1.Fq2(math_1.CURVE.G2x), new math_1.Fq2(math_1.CURVE.G2y), math_1.Fq2.ONE);
PointG2.ZERO = new PointG2(math_1.Fq2.ONE, math_1.Fq2.ONE, math_1.Fq2.ZERO);
function pairing(P, Q, withFinalExponent = true) {
    if (P.isZero() || Q.isZero())
        throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    const looped = P.millerLoop(Q);
    return withFinalExponent ? looped.finalExponentiate() : looped;
}
exports.pairing = pairing;
function normP1(point) {
    if (point instanceof PointG1)
        return point;
    expectHex(point);
    return PointG1.fromHex(point);
}
function normP2(point) {
    if (point instanceof PointG2)
        return point;
    expectHex(point);
    return PointG2.fromSignature(point);
}
async function normP2H(point) {
    if (point instanceof PointG2)
        return point;
    expectHex(point);
    return await PointG2.hashToCurve(point);
}
function getPublicKey(privateKey) {
    const bytes = PointG1.fromPrivateKey(privateKey).toRawBytes(true);
    return typeof privateKey === 'string' ? bytesToHex(bytes) : bytes;
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    const msgPoint = await normP2H(message);
    msgPoint.assertValidity();
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    if (message instanceof PointG2)
        return sigPoint;
    const bytes = sigPoint.toSignature();
    return typeof message === 'string' ? bytes : hexToBytes(bytes);
}
exports.sign = sign;
async function verify(signature, message, publicKey) {
    const P = normP1(publicKey);
    const Hm = await normP2H(message);
    const G = PointG1.BASE;
    const S = normP2(signature);
    const ePHm = pairing(P.negate(), Hm, false);
    const eGS = pairing(G, S, false);
    const exp = eGS.multiply(ePHm).finalExponentiate();
    return exp.equals(math_1.Fq12.ONE);
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    const agg = publicKeys.map(normP1).reduce((sum, p) => sum.add(p), PointG1.ZERO);
    if (publicKeys[0] instanceof PointG1)
        return agg;
    const bytes = agg.toRawBytes(true);
    if (publicKeys[0] instanceof Uint8Array)
        return bytes;
    return bytesToHex(bytes);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (!signatures.length)
        throw new Error('Expected non-empty array');
    const agg = signatures.map(normP2).reduce((sum, s) => sum.add(s), PointG2.ZERO);
    if (signatures[0] instanceof PointG2)
        return agg;
    const bytes = agg.toSignature();
    if (signatures[0] instanceof Uint8Array)
        return bytes;
    return bytes;
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(signature, messages, publicKeys) {
    if (!messages.length)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    const sig = normP2(signature);
    const nMessages = await Promise.all(messages.map(normP2H));
    const nPublicKeys = publicKeys.map(normP1);
    try {
        const paired = [];
        for (const message of new Set(nMessages)) {
            const groupPublicKey = nMessages.reduce((groupPublicKey, subMessage, i) => subMessage === message ? groupPublicKey.add(nPublicKeys[i]) : groupPublicKey, PointG1.ZERO);
            paired.push(pairing(groupPublicKey, message, false));
        }
        paired.push(pairing(PointG1.BASE.negate(), sig, false));
        const product = paired.reduce((a, b) => a.multiply(b), math_1.Fq12.ONE);
        const exp = product.finalExponentiate();
        return exp.equals(math_1.Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
PointG1.BASE.calcMultiplyPrecomputes(4);
