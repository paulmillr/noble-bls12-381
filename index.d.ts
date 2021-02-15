/*! noble-bls12-381 - MIT License (c) Paul Miller (paulmillr.com) */
import { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve, ProjectivePoint, mod } from './math';
export declare let DST_LABEL: string;
declare type Bytes = Uint8Array | string;
declare type PrivateKey = Bytes | bigint | number;
export { Fq, Fr, Fq2, Fq12, CURVE, BigintTwelve };
export declare const utils: {
    sha256(message: Uint8Array): Promise<Uint8Array>;
    randomPrivateKey: (bytesLength?: number) => Uint8Array;
    mod: typeof mod;
};
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 extends ProjectivePoint<Fq> {
    static BASE: PointG1;
    static ZERO: PointG1;
    constructor(x: Fq, y: Fq, z: Fq);
    static fromHex(hex: Bytes): PointG1;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): void;
    toRepr(): bigint[];
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
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): void;
    toRepr(): [bigint, bigint][];
    clearPairingPrecomputes(): void;
    pairingPrecomputes(): EllCoefficients[];
}
export declare function pairing(P: PointG1, Q: PointG2, withFinalExponent?: boolean): Fq12;
declare type PB1 = Bytes | PointG1;
declare type PB2 = Bytes | PointG2;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array | string;
export declare function sign(message: Uint8Array, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function sign(message: string, privateKey: PrivateKey): Promise<string>;
export declare function sign(message: PointG2, privateKey: PrivateKey): Promise<PointG2>;
export declare function verify(signature: PB2, message: PB2, publicKey: PB1): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array;
export declare function aggregatePublicKeys(publicKeys: string[]): string;
export declare function aggregatePublicKeys(publicKeys: PointG1[]): PointG1;
export declare function aggregateSignatures(signatures: Uint8Array[]): Uint8Array;
export declare function aggregateSignatures(signatures: string[]): string;
export declare function aggregateSignatures(signatures: PointG2[]): PointG2;
export declare function verifyBatch(signature: PB2, messages: PB2[], publicKeys: PB1[]): Promise<boolean>;
