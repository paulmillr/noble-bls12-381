/*! noble-bls12-381 - MIT License (c) Paul Miller (paulmillr.com) */
import { Fp, Fr, Fp2, Fp12, CURVE, ProjectivePoint, mod } from './math';
export { Fp, Fr, Fp2, Fp12, CURVE };
declare type Bytes = Uint8Array | string;
declare type PrivateKey = Bytes | bigint | number;
export declare const utils: {
    sha256(message: Uint8Array): Promise<Uint8Array>;
    randomBytes: (bytesLength?: number) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
    mod: typeof mod;
    getDSTLabel(): string;
    setDSTLabel(newLabel: string): void;
};
export declare class PointG1 extends ProjectivePoint<Fp> {
    static BASE: PointG1;
    static ZERO: PointG1;
    constructor(x: Fp, y: Fp, z?: Fp);
    static fromHex(bytes: Bytes): PointG1;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): this;
    millerLoop(P: PointG2): Fp12;
    clearCofactor(): this;
    private isOnCurve;
    private isTorsionFree;
}
export declare class PointG2 extends ProjectivePoint<Fp2> {
    static BASE: PointG2;
    static ZERO: PointG2;
    private _PPRECOMPUTES;
    constructor(x: Fp2, y: Fp2, z?: Fp2);
    static hashToCurve(msg: Bytes): Promise<PointG2>;
    static fromSignature(hex: Bytes): PointG2;
    static fromHex(bytes: Bytes): PointG2;
    static fromPrivateKey(privateKey: PrivateKey): PointG2;
    toSignature(): string;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    assertValidity(): this;
    private psi;
    private psi2;
    private mulNegX;
    clearCofactor(): PointG2;
    private isOnCurve;
    private isTorsionFree;
    clearPairingPrecomputes(): void;
    pairingPrecomputes(): [Fp2, Fp2, Fp2][];
}
export declare function pairing(P: PointG1, Q: PointG2, withFinalExponent?: boolean): Fp12;
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
