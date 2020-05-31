import { Fq, Fq2, Fq12, ProjectivePoint, CURVE } from './math';
export declare let DST_LABEL: string;
declare type Bytes = Uint8Array | string;
declare type Hash = Bytes;
declare type PrivateKey = Bytes | bigint | number;
declare type PublicKey = Bytes;
declare type Signature = Bytes;
export declare type BigintTwelve = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
export { Fq, Fq2, Fq12, CURVE };
export declare const utils: {
    sha256(message: Uint8Array): Promise<Uint8Array>;
};
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 extends ProjectivePoint<Fq> {
    static BASE: PointG1;
    static ZERO: PointG1;
    constructor(x: Fq, y: Fq, z: Fq);
    static fromCompressedHex(hex: PublicKey): PointG1;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toCompressedHex(): Uint8Array;
    assertValidity(): void;
    millerLoop(P: PointG2): Fq12;
}
declare type EllCoefficients = [Fq2, Fq2, Fq2];
export declare class PointG2 extends ProjectivePoint<Fq2> {
    static BASE: PointG2;
    static ZERO: PointG2;
    private pair_precomputes;
    constructor(x: Fq2, y: Fq2, z: Fq2);
    static hashToCurve(msg: PublicKey): Promise<PointG2>;
    static fromSignature(hex: Signature): PointG2;
    static fromPrivateKey(privateKey: PrivateKey): PointG2;
    toSignature(): Uint8Array;
    assertValidity(): void;
    calculatePrecomputes(): EllCoefficients[];
    clearPairingPrecomputes(): void;
    pairingPrecomputes(): EllCoefficients[];
}
export declare function pairing(P: PointG1, Q: PointG2, withFinalExponent?: boolean): Fq12;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array;
export declare function sign(message: Hash, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function verify(signature: Signature, message: Hash, publicKey: PublicKey): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: PublicKey[]): PointG1;
export declare function aggregateSignatures(signatures: Signature[]): Uint8Array;
export declare function verifyBatch(messages: Hash[], publicKeys: PublicKey[], signature: Signature): Promise<boolean>;
