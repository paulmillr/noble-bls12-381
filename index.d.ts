/*! noble-bls12-381 - MIT License (c) Paul Miller (paulmillr.com) */
import { Fq, Fr, Fq2, Fq12, CURVE, EllCoefficients, ProjectivePoint, mod } from './math';
export { Fq, Fr, Fq2, Fq12, CURVE };
export declare let DST_LABEL: string;
declare type Bytes = Uint8Array | string;
declare type PrivateKey = Bytes | bigint | number;
export declare const utils: {
    sha256(message: Uint8Array): Promise<Uint8Array>;
    randomPrivateKey: (bytesLength?: number) => Uint8Array;
    mod: typeof mod;
    setDSTLabel(newLabel: string): void;
};
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 extends ProjectivePoint<Fq> {
    static BASE: PointG1;
    static ZERO: PointG1;
    constructor(x: Fq, y: Fq, z?: Fq);
    static fromHex(bytes: Bytes): PointG1;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): void;
    millerLoop(P: PointG2): Fq12;
    private isOnCurve;
    private isTorsionFree;
}
export declare class PointG2 extends ProjectivePoint<Fq2> {
    static BASE: PointG2;
    static ZERO: PointG2;
    private _PPRECOMPUTES;
    constructor(x: Fq2, y: Fq2, z?: Fq2);
    static hashToCurve(msg: Bytes): Promise<PointG2>;
    static fromSignature(hex: Bytes): PointG2;
    static fromHex(bytes: Bytes): PointG2;
    static fromPrivateKey(privateKey: PrivateKey): PointG2;
    toSignature(): string;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): void;
    private psi;
    private psi2;
    clearCofactor(): PointG2;
    private isOnCurve;
    private isTorsionFree;
    clearPairingPrecomputes(): void;
    pairingPrecomputes(): EllCoefficients[];
}
export declare function pairing(P: PointG1, Q: PointG2, withFinalExponent?: boolean): Fq12;
declare type G1Hex = Bytes | PointG1;
declare type G2Hex = Bytes | PointG2;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array | string;
export declare function sign(message: Uint8Array, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function sign(message: string, privateKey: PrivateKey): Promise<string>;
export declare function sign(message: PointG2, privateKey: PrivateKey): Promise<PointG2>;
export declare function verify(signature: G2Hex, message: G2Hex, publicKey: G1Hex): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array;
export declare function aggregatePublicKeys(publicKeys: string[]): string;
export declare function aggregatePublicKeys(publicKeys: PointG1[]): PointG1;
export declare function aggregateSignatures(signatures: Uint8Array[]): Uint8Array;
export declare function aggregateSignatures(signatures: string[]): string;
export declare function aggregateSignatures(signatures: PointG2[]): PointG2;
export declare function verifyBatch(signature: G2Hex, messages: G2Hex[], publicKeys: G1Hex[]): Promise<boolean>;
