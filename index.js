'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.clearCofactorG2 = exports.PointG1 = exports.hash_to_field = exports.utils = exports.CURVE = exports.Fq12 = exports.Fq2 = exports.Fq = exports.DST_LABEL = void 0;
const math_1 = require("./math");
Object.defineProperty(exports, "Fq", { enumerable: true, get: function () { return math_1.Fq; } });
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
function isogenyMapG2(xyz) {
    const [x, y, z] = xyz;
    const mapped = [math_1.Fq2.ZERO, math_1.Fq2.ZERO, math_1.Fq2.ZERO, math_1.Fq2.ZERO];
    const zPowers = [z, z.pow(2n), z.pow(3n)];
    for (let i = 0; i < math_1.isogenyCoefficients.length; i++) {
        const k_i = math_1.isogenyCoefficients[i];
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
    return new PointG2(x2, y2, z2);
}
async function expand_message_xmd(msg, DST, len_in_bytes) {
    const H = exports.utils.sha256;
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
            e[j] = math_1.mod(os2ip(tv), math_1.CURVE.P);
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
    const positiveRootsOfUnity = math_1.Fq2.ROOTS_OF_UNITY.slice(0, 4);
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
    const iso_3_a = new math_1.Fq2([0n, 240n]);
    const iso_3_b = new math_1.Fq2([1012n, 1012n]);
    const iso_3_z = new math_1.Fq2([-2n, -1n]);
    if (Array.isArray(t))
        t = new math_1.Fq2(t);
    const t2 = t.pow(2n);
    const iso_3_z_t2 = iso_3_z.multiply(t2);
    const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
    let denominator = iso_3_a.multiply(ztzt).negate();
    let numerator = iso_3_b.multiply(ztzt.add(math_1.Fq2.ONE));
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
    for (const eta of math_1.Fq2.ETAs) {
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
    return new math_1.Fq(toBigInt(privateKey));
}
let PointG1 = (() => {
    class PointG1 extends math_1.ProjectivePoint {
        constructor(x, y, z) {
            super(x, y, z, math_1.Fq);
        }
        static fromCompressedHex(hex) {
            const compressedValue = fromBytesBE(hex);
            const bflag = math_1.mod(compressedValue, POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = math_1.mod(compressedValue, POW_2_381);
            const fullY = math_1.mod(x ** 3n + new math_1.Fq(math_1.CURVE.b).value, P);
            let y = math_1.powMod(fullY, (P + 1n) / 4n, P);
            if (math_1.powMod(y, 2n, P) !== fullY) {
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
            const ell = P.pairingPrecomputes();
            let f12 = math_1.Fq12.ONE;
            let [x, y] = this.toAffine();
            let [Px, Py] = [x, y];
            for (let j = 0, i = math_1.BLS_X_LEN - 2; i >= 0; i--, j++) {
                f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
                if (math_1.bitGet(math_1.CURVE.BLS_X, i)) {
                    j += 1;
                    f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
                }
                if (i != 0)
                    f12 = f12.square();
            }
            return f12.conjugate();
        }
    }
    PointG1.BASE = new PointG1(new math_1.Fq(math_1.CURVE.Gx), new math_1.Fq(math_1.CURVE.Gy), math_1.Fq.ONE);
    PointG1.ZERO = new PointG1(math_1.Fq.ONE, math_1.Fq.ONE, math_1.Fq.ZERO);
    return PointG1;
})();
exports.PointG1 = PointG1;
const ut_root = new math_1.Fq6([math_1.Fq2.ZERO, math_1.Fq2.ONE, math_1.Fq2.ZERO]);
const wsq = new math_1.Fq12([ut_root, math_1.Fq6.ZERO]);
const wsq_inv = wsq.invert();
const wcu = new math_1.Fq12([math_1.Fq6.ZERO, ut_root]);
const wcu_inv = wcu.invert();
function psi(P) {
    let [x, y] = P.toAffine();
    let new_x = wsq_inv.multiplyByFq2(x).frobeniusMap(1).multiply(wsq).c[0].c[0];
    let new_y = wcu_inv.multiplyByFq2(y).frobeniusMap(1).multiply(wcu).c[0].c[0];
    return new PointG2(new_x, new_y, math_1.Fq2.ONE);
}
const PSI2_C1 = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
function psi2(P) {
    let [x, y] = P.toAffine();
    return new PointG2(x.multiply(PSI2_C1), y.negate(), math_1.Fq2.ONE);
}
function clearCofactorG2(P) {
    let t1 = P.multiplyUnsafe(math_1.CURVE.BLS_X).negate();
    let t2 = psi(P);
    return psi2(P.double())
        .subtract(t2)
        .add(t1.add(t2).multiplyUnsafe(math_1.CURVE.BLS_X).negate())
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
            const bflag1 = math_1.mod(z1, POW_2_383) / POW_2_382;
            if (bflag1 === 1n)
                return this.ZERO;
            const x1 = z1 % POW_2_381;
            const x2 = z2;
            const x = new math_1.Fq2([x2, x1]);
            let y = x.pow(3n).add(new math_1.Fq2(math_1.CURVE.b2)).sqrt();
            if (!y)
                throw new Error('Failed to find a square root');
            const [y0, y1] = y.value;
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
                return concatTypedArrays(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
            }
            this.assertValidity();
            const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.value);
            const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
            const aflag1 = tmp / math_1.CURVE.P;
            const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
            const z2 = x0;
            return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
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
        calculatePrecomputes() {
            const [x, y] = this.toAffine();
            const [Qx, Qy, Qz] = [x, y, math_1.Fq2.ONE];
            let [Rx, Ry, Rz] = [Qx, Qy, Qz];
            let ell_coeff = [];
            for (let i = math_1.BLS_X_LEN - 2; i >= 0; i--) {
                let t0 = Ry.square();
                let t1 = Rz.square();
                let t2 = t1.multiply(3n).multiplyByB();
                let t3 = t2.multiply(3n);
                let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0);
                ell_coeff.push([
                    t2.subtract(t0),
                    Rx.square().multiply(3n),
                    t4.negate(),
                ]);
                Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n);
                Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n));
                Rz = t0.multiply(t4);
                if (math_1.bitGet(math_1.CURVE.BLS_X, i)) {
                    let t0 = Ry.subtract(Qy.multiply(Rz));
                    let t1 = Rx.subtract(Qx.multiply(Rz));
                    ell_coeff.push([
                        t0.multiply(Qx).subtract(t1.multiply(Qy)),
                        t0.negate(),
                        t1,
                    ]);
                    let t2 = t1.square();
                    let t3 = t2.multiply(t1);
                    let t4 = t2.multiply(Rx);
                    let t5 = t3.subtract(t4.multiply(2n)).add(t0.square().multiply(Rz));
                    Rx = t1.multiply(t5);
                    Ry = t4.subtract(t5).multiply(t0).subtract(t3.multiply(Ry));
                    Rz = Rz.multiply(t3);
                }
            }
            return ell_coeff;
        }
        clearPairingPrecomputes() {
            this.pair_precomputes = undefined;
        }
        pairingPrecomputes() {
            if (this.pair_precomputes)
                return this.pair_precomputes;
            return (this.pair_precomputes = this.calculatePrecomputes());
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
