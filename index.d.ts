import { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve, ProjectivePoint, mod } from './math';
export declare let DST_LABEL: string;
declare type Bytes = Uint8Array | string;
declare type PrivateKey = Bytes | bigint | number;
export { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve };
export declare const utils: {
    sha256(message: Uint8Array): Promise<Uint8Array>;
    mod: typeof mod;
};
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 extends ProjectivePoint<Fq> {
    static BASE: PointG1;
    static ZERO: PointG1;
    constructor(x: Fq, y: Fq, z: Fq);
    static fromCompressedHex(hex: Bytes): PointG1;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toCompressedHex(): Uint8Array;
    assertValidity(): void;
    millerLoop(P: PointG2): Fq12;
}
export declare function clearCofactorG2(P: PointG2): PointG2;
declare type EllCoefficients = [Fq2, Fq2, Fq2];
export declare class PointG2 extends ProjectivePoint<Fq2> {
    static BASE: PointG2;
    static ZERO: PointG2;
    private _PPRECOMPUTES;
    constructor(x: Fq2, y: Fq2, z: Fq2);
    static hashToCurve(msg: Bytes): Promise<PointG2>;
    static fromSignature(hex: Bytes): PointG2;
    static fromPrivateKey(privateKey: PrivateKey): PointG2;
    toSignature(): Uint8Array;
    assertValidity(): void;
    clearPairingPrecomputes(): void;
    pairingPrecomputes(): EllCoefficients[];
}
export declare function pairing(P: PointG1, Q: PointG2, withFinalExponent?: boolean): Fq12;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array;
export declare function sign(message: Bytes, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function verify(signature: Bytes, message: Bytes, publicKey: Bytes): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: Bytes[]): PointG1;
export declare function aggregateSignatures(signatures: Bytes[]): Uint8Array;
export declare function verifyBatch(messages: Bytes[], publicKeys: Bytes[], signature: Bytes): Promise<boolean>;
