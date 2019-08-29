"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fp_1 = require("./fp");
const point_1 = require("./point");
const fp2_1 = require("./fp2");
const fp12_1 = require("./fp12");
const utils_1 = require("./utils");
var fp_2 = require("./fp");
exports.Fp = fp_2.Fp;
var fp2_2 = require("./fp2");
exports.Fp2 = fp2_2.Fp2;
var fp12_2 = require("./fp12");
exports.Fp12 = fp12_2.Fp12;
var point_2 = require("./point");
exports.Point = point_2.Point;
var utils_2 = require("./utils");
exports.P = utils_2.P;
exports.PRIME_ORDER = utils_2.PRIME_ORDER;
exports.G1 = new point_1.Point(new fp_1.Fp(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507n), new fp_1.Fp(1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569n), new fp_1.Fp(1n), fp_1.Fp);
exports.G2 = new point_1.Point(new fp2_1.Fp2(352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160n, 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758n), new fp2_1.Fp2(1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905n, 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582n), new fp2_1.Fp2(1n, 0n), fp2_1.Fp2);
const G12 = exports.G2.twist();
const ONE = exports.G1;
const TWO = exports.G1.double();
const THREE = exports.G1.multiply(3);
const NE_ONE = exports.G1.multiply(utils_1.PRIME_ORDER - 1n);
const NE_TWO = exports.G1.multiply(utils_1.PRIME_ORDER - 2n);
const NE_THREE = exports.G1.multiply(utils_1.PRIME_ORDER - 3n);
function createLineBetween(p1, p2, n) {
    let mNumerator = p2.y.multiply(p1.z).subtract(p1.y.multiply(p2.z));
    let mDenominator = p2.x.multiply(p1.z).subtract(p1.x.multiply(p2.z));
    if (!mNumerator.equals(mNumerator.zero) &&
        mDenominator.equals(mDenominator.zero)) {
        return [
            n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)),
            p1.z.multiply(n.z)
        ];
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
        return new point_1.Point(new fp12_1.Fp12(), new fp12_1.Fp12(), new fp12_1.Fp12(), fp12_1.Fp12);
    }
    return new point_1.Point(new fp12_1.Fp12(pt.x.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new fp12_1.Fp12(pt.y.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new fp12_1.Fp12(pt.z.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), fp12_1.Fp12);
}
const PSEUDO_BINARY_ENCODING = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];
function millerLoop(Q, P, withFinalExponent = false) {
    const one = new fp12_1.Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
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
    return withFinalExponent ? f.pow(utils_1.P_ORDER_X_12_DIVIDED) : f;
}
function finalExponentiate(p) {
    return p.pow(utils_1.P_ORDER_X_12_DIVIDED);
}
function pairing(Q, P, withFinalExponent = true) {
    if (!Q.isOnCurve(utils_1.B2)) {
        throw new Error("Fisrt point isn't on elliptic curve");
    }
    if (!P.isOnCurve(utils_1.B)) {
        throw new Error("Second point isn't on elliptic curve");
    }
    return millerLoop(Q.twist(), castPointToFp12(P), withFinalExponent);
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    privateKey = utils_1.toBigInt(privateKey);
    return utils_1.publicKeyFromG1(exports.G1.multiply(privateKey));
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey, domain) {
    domain =
        domain instanceof Uint8Array ? domain : utils_1.toBytesBE(domain, utils_1.DOMAIN_LENGTH);
    privateKey = utils_1.toBigInt(privateKey);
    const messageValue = await utils_1.hashToG2(message, domain);
    const signature = messageValue.multiply(privateKey);
    return utils_1.signatureFromG2(signature);
}
exports.sign = sign;
async function verify(message, publicKey, signature, domain) {
    domain =
        domain instanceof Uint8Array ? domain : utils_1.toBytesBE(domain, utils_1.DOMAIN_LENGTH);
    const publicKeyPoint = utils_1.publicKeyToG1(publicKey).negative();
    const signaturePoint = utils_1.signatureToG2(signature);
    try {
        const signaturePairing = pairing(signaturePoint, exports.G1);
        const hashPairing = pairing(await utils_1.hashToG2(message, domain), publicKeyPoint);
        const finalExponent = finalExponentiate(signaturePairing.multiply(hashPairing));
        return finalExponent.equals(finalExponent.one);
    }
    catch {
        return false;
    }
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (publicKeys.length === 0) {
        throw new Error("Provide public keys which should be aggregated");
    }
    const aggregatedPublicKey = publicKeys.reduce((sum, publicKey) => sum.add(utils_1.publicKeyToG1(publicKey)), utils_1.Z1);
    return utils_1.publicKeyFromG1(aggregatedPublicKey);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (signatures.length === 0) {
        throw new Error("Provide signatures which should be aggregated");
    }
    const aggregatedSignature = signatures.reduce((sum, signature) => sum.add(utils_1.signatureToG2(signature)), utils_1.Z2);
    return utils_1.signatureFromG2(aggregatedSignature);
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyMultiple(messages, publicKeys, signature, domain) {
    domain =
        domain instanceof Uint8Array ? domain : utils_1.toBytesBE(domain, utils_1.DOMAIN_LENGTH);
    if (messages.length === 0) {
        throw new Error("Provide messsages which should be verified");
    }
    if (publicKeys.length !== messages.length) {
        throw new Error("Count of public keys should be the same as messages");
    }
    try {
        let producer = new fp12_1.Fp12().one;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message
                ? groupPublicKey
                : groupPublicKey.add(utils_1.publicKeyToG1(publicKeys[i])), utils_1.Z1);
            producer = producer.multiply(pairing(await utils_1.hashToG2(message, domain), groupPublicKey));
        }
        producer = producer.multiply(pairing(utils_1.signatureToG2(signature), exports.G1.negative()));
        const finalExponent = finalExponentiate(producer);
        return finalExponent.equals(finalExponent.one);
    }
    catch {
        return false;
    }
}
exports.verifyMultiple = verifyMultiple;
