"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyMultiple = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.G2 = exports.G1 = exports.PRIME_ORDER = exports.P = exports.Point = exports.Fp12 = exports.Fp2 = exports.Fp = void 0;
const fields_1 = require("./fields");
Object.defineProperty(exports, "Fp", { enumerable: true, get: function () { return fields_1.Fp; } });
Object.defineProperty(exports, "Fp2", { enumerable: true, get: function () { return fields_1.Fp2; } });
Object.defineProperty(exports, "Fp12", { enumerable: true, get: function () { return fields_1.Fp12; } });
Object.defineProperty(exports, "Point", { enumerable: true, get: function () { return fields_1.Point; } });
const utils_1 = require("./utils");
Object.defineProperty(exports, "P", { enumerable: true, get: function () { return utils_1.P; } });
const PRIME_ORDER = utils_1.CURVE.n;
exports.PRIME_ORDER = PRIME_ORDER;
exports.G1 = new fields_1.Point(new fields_1.Fp(utils_1.CURVE.Gx), new fields_1.Fp(utils_1.CURVE.Gy), new fields_1.Fp(1n), fields_1.Fp);
exports.G2 = new fields_1.Point(new fields_1.Fp2(utils_1.CURVE.G2x[0], utils_1.CURVE.G2x[1]), new fields_1.Fp2(utils_1.CURVE.G2y[0], utils_1.CURVE.G2y[1]), new fields_1.Fp2(1n, 0n), fields_1.Fp2);
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
        return new fields_1.Point(new fields_1.Fp12(), new fields_1.Fp12(), new fields_1.Fp12(), fields_1.Fp12);
    }
    return new fields_1.Point(new fields_1.Fp12(pt.x.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new fields_1.Fp12(pt.y.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), new fields_1.Fp12(pt.z.value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n), fields_1.Fp12);
}
const PSEUDO_BINARY_ENCODING = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];
function millerLoop(Q, P, withFinalExponent = false) {
    const one = new fields_1.Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
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
        let producer = new fields_1.Fp12().one;
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
