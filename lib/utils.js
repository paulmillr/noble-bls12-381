"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashToG2 = exports.signatureToG2 = exports.signatureFromG2 = exports.publicKeyToG1 = exports.publicKeyFromG1 = exports.getXCoordinate = exports.toBigInt = exports.toBytesBE = exports.Z2 = exports.Z1 = exports.B12 = exports.B2 = exports.B = exports.P_ORDER_X_12_DIVIDED = exports.DOMAIN_LENGTH = exports.P = exports.CURVE = void 0;
const fields_1 = require("./fields");
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    n: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    DOMAIN_LENGTH: 8,
    Gx: 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507n,
    Gy: 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569n,
    G2x: [352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160n, 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758n],
    G2y: [1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905n, 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582n],
    G2_COFACTOR: 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n
};
exports.P = exports.CURVE.P;
exports.DOMAIN_LENGTH = 8;
const P_ORDER_X_12 = exports.P ** 12n - 1n;
exports.P_ORDER_X_12_DIVIDED = P_ORDER_X_12 / exports.CURVE.n;
fields_1.Fp.ORDER = exports.P;
fields_1.Fp2.ORDER = exports.P ** 2n - 1n;
fields_1.Fp2.COFACTOR = exports.CURVE.G2_COFACTOR;
exports.B = new fields_1.Fp(4n);
exports.B2 = new fields_1.Fp2(4n, 4n);
exports.B12 = new fields_1.Fp12(4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
exports.Z1 = new fields_1.Point(new fields_1.Fp(1n), new fields_1.Fp(1n), new fields_1.Fp(0n), fields_1.Fp);
exports.Z2 = new fields_1.Point(new fields_1.Fp2(1n, 0n), new fields_1.Fp2(1n, 0n), new fields_1.Fp2(0n, 0n), fields_1.Fp2);
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
let sha256;
if (typeof window == "object" && "crypto" in window) {
    sha256 = async (message) => {
        const buffer = await window.crypto.subtle.digest("SHA-256", message.buffer);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === "object" && "node" in process.versions) {
    const req = require;
    const { createHash } = req("crypto");
    sha256 = async (message) => {
        const hash = createHash("sha256");
        hash.update(message);
        return Uint8Array.from(hash.digest());
    };
}
else {
    throw new Error("The environment doesn't have sha256 function");
}
function fromHexBE(hex) {
    return BigInt(`0x${hex}`);
}
function fromBytesBE(bytes) {
    if (typeof bytes === "string") {
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
    const elements = Array(diff).fill(element).map((i) => i);
    return concatBytes(new Uint8Array(elements), bytes);
}
function toBytesBE(num, padding = 0) {
    let hex = typeof num === "string" ? num : num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length && i < len * 2; i += 2, j++) {
        u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return padStart(u8, padding, 0);
}
exports.toBytesBE = toBytesBE;
function toBigInt(num) {
    if (typeof num === "string") {
        return fromHexBE(num);
    }
    if (typeof num === "number") {
        return BigInt(num);
    }
    if (num instanceof Uint8Array) {
        return fromBytesBE(num);
    }
    return num;
}
exports.toBigInt = toBigInt;
function hexToBytes(hex) {
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
        bytesView =
            bytesView instanceof Uint8Array ? bytesView : hexToBytes(bytesView);
        return [...res, ...bytesView];
    }, []));
}
function powMod(x, power, order) {
    let fx = new fields_1.Fp(x);
    let res = new fields_1.Fp(1n);
    while (power > 0) {
        if (power & 1n) {
            res = res.multiply(fx);
        }
        power >>= 1n;
        fx = fx.square();
    }
    return res.value;
}
async function getXCoordinate(hash, domain) {
    const xReconstructed = toBigInt(await sha256(concatBytes(hash, domain, "01")));
    const xImage = toBigInt(await sha256(concatBytes(hash, domain, "02")));
    return new fields_1.Fp2(xReconstructed, xImage);
}
exports.getXCoordinate = getXCoordinate;
const POW_SUM = POW_2_383 + POW_2_382;
function compressG1(point) {
    if (point.equals(exports.Z1)) {
        return POW_SUM;
    }
    const [x, y] = point.to2D();
    const flag = (y.value * 2n) / exports.P;
    return x.value + flag * POW_2_381 + POW_2_383;
}
const PART_OF_P = (exports.P + 1n) / 4n;
function uncompressG1(compressedValue) {
    const bflag = (compressedValue % POW_2_383) / POW_2_382;
    if (bflag === 1n) {
        return exports.Z1;
    }
    const x = compressedValue % POW_2_381;
    const fullY = (x ** 3n + exports.B.value) % exports.P;
    let y = powMod(fullY, PART_OF_P, exports.P);
    if (powMod(y, 2n, exports.P) !== fullY) {
        throw new Error("The given point is not on G1: y**2 = x**3 + b");
    }
    const aflag = (compressedValue % POW_2_382) / POW_2_381;
    if ((y * 2n) / exports.P !== aflag) {
        y = exports.P - y;
    }
    return new fields_1.Point(new fields_1.Fp(x), new fields_1.Fp(y), new fields_1.Fp(1n), fields_1.Fp);
}
function compressG2(point) {
    if (point.equals(exports.Z2)) {
        return [POW_2_383 + POW_2_382, 0n];
    }
    if (!point.isOnCurve(exports.B2)) {
        throw new Error("The given point is not on the twisted curve over FQ**2");
    }
    const [[x0, x1], [y0, y1]] = point.to2D().map(a => a.value);
    const producer = y1 > 0 ? y1 : y0;
    const aflag1 = (producer * 2n) / exports.P;
    const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
    const z2 = x0;
    return [z1, z2];
}
function uncompressG2([z1, z2]) {
    const bflag1 = (z1 % POW_2_383) / POW_2_382;
    if (bflag1 === 1n) {
        return exports.Z2;
    }
    const x = new fields_1.Fp2(z2, z1 % POW_2_381);
    let y = x
        .pow(3n)
        .add(exports.B2)
        .modularSquereRoot();
    if (y === null) {
        throw new Error("Failed to find a modular squareroot");
    }
    const [y0, y1] = y.value;
    const aflag1 = (z1 % POW_2_382) / POW_2_381;
    const isGreaterCoefficient = y1 > 0 && (y1 * 2n) / exports.P !== aflag1;
    const isZeroCoefficient = y1 === 0n && (y0 * 2n) / exports.P !== aflag1;
    if (isGreaterCoefficient || isZeroCoefficient) {
        y = y.multiply(-1n);
    }
    const point = new fields_1.Point(x, y, y.one, fields_1.Fp2);
    if (!point.isOnCurve(exports.B2)) {
        throw new Error("The given point is not on the twisted curve over Fp2");
    }
    return point;
}
function publicKeyFromG1(point) {
    const z = compressG1(point);
    return toBytesBE(z, PUBLIC_KEY_LENGTH);
}
exports.publicKeyFromG1 = publicKeyFromG1;
function publicKeyToG1(publicKey) {
    const z = fromBytesBE(publicKey);
    return uncompressG1(z);
}
exports.publicKeyToG1 = publicKeyToG1;
function signatureFromG2(point) {
    const [z1, z2] = compressG2(point);
    return concatBytes(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
}
exports.signatureFromG2 = signatureFromG2;
function signatureToG2(signature) {
    const halfSignature = signature.length / 2;
    const z1 = fromBytesBE(signature.slice(0, halfSignature));
    const z2 = fromBytesBE(signature.slice(halfSignature));
    return uncompressG2([z1, z2]);
}
exports.signatureToG2 = signatureToG2;
async function hashToG2(hash, domain) {
    let xCoordinate = await getXCoordinate(hash, domain);
    let newResult = null;
    do {
        newResult = xCoordinate
            .pow(3n)
            .add(new fields_1.Fp2(4n, 4n))
            .modularSquereRoot();
        const addition = newResult ? xCoordinate.zero : xCoordinate.one;
        xCoordinate = xCoordinate.add(addition);
    } while (newResult === null);
    const yCoordinate = newResult;
    const result = new fields_1.Point(xCoordinate, yCoordinate, new fields_1.Fp2(1n, 0n), fields_1.Fp2);
    return result.multiply(fields_1.Fp2.COFACTOR);
}
exports.hashToG2 = hashToG2;
