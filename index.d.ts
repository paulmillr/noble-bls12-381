export declare const CURVE: {
    P: bigint;
    r: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
    b: bigint;
    P2: bigint;
    h2: bigint;
    G2x: bigint[];
    G2y: bigint[];
    b2: bigint[];
};
export declare let DST_LABEL: string;
declare type Bytes = Uint8Array | string;
declare type Hash = Bytes;
declare type PrivateKey = Bytes | bigint | number;
declare type PublicKey = Bytes;
declare type Signature = Bytes;
declare type BigintTuple = [bigint, bigint];
export declare type BigintTwelve = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
interface Field<T> {
    readonly value: T;
    isZero(): boolean;
    equals(other: Field<T> | T): boolean;
    add(other: Field<T> | T): Field<T>;
    multiply(other: Field<T> | T | bigint): Field<T>;
    div(other: Field<T> | T | bigint): Field<T>;
    square(): Field<T>;
    subtract(other: Field<T> | T): Field<T>;
    negate(): Field<T>;
    invert(): Field<T>;
    pow(n: bigint): Field<T>;
}
export declare class Fq implements Field<bigint> {
    static readonly ORDER: bigint;
    static readonly ZERO: Fq;
    static readonly ONE: Fq;
    private _value;
    get value(): bigint;
    constructor(value: bigint);
    isZero(): boolean;
    equals(other: Fq): boolean;
    negate(): Fq;
    invert(): Fq;
    add(other: Fq): Fq;
    square(): Fq;
    pow(n: bigint): Fq;
    subtract(other: Fq): Fq;
    multiply(other: bigint | Fq): Fq;
    div(other: Fq): Fq;
    toString(): string;
}
export declare class Fq2 implements Field<BigintTuple> {
    static readonly ORDER: bigint;
    static readonly ROOT: Fq;
    static readonly ZERO: Fq2;
    static readonly ONE: Fq2;
    static readonly COFACTOR: bigint;
    static readonly ROOTS_OF_UNITY: Fq2[];
    static readonly ETAs: Fq2[];
    coefficients: Fq[];
    private degree;
    get real(): Fq;
    get imag(): Fq;
    get value(): BigintTuple;
    constructor(coefficients: (Fq | bigint)[]);
    toString(): string;
    private zip;
    isZero(): boolean;
    equals(other: Fq2): boolean;
    negate(): Fq2;
    add(other: Fq2): Fq2;
    subtract(other: Fq2): Fq2;
    multiply(other: Fq2 | bigint): Fq2;
    mulByNonresidue(): Fq2;
    square(): Fq2;
    sqrt(): Fq2 | undefined;
    pow(n: bigint): Fq2;
    invert(): Fq2;
    div(other: Fq2): Fq2;
}
export declare class Fq12 implements Field<BigintTwelve> {
    static readonly ZERO: Fq12;
    static readonly ONE: Fq12;
    private coefficients;
    private static readonly MODULE_COEFFICIENTS;
    private static readonly ENTRY_COEFFICIENTS;
    get value(): BigintTwelve;
    constructor(args?: (bigint | Fq)[]);
    private zip;
    isZero(): boolean;
    equals(other: Fq12): boolean;
    negate(): Fq12;
    add(other: Fq12): Fq12;
    subtract(other: Fq12): Fq12;
    multiply(other: Fq12 | BigintTwelve | bigint): Fq12;
    square(): Fq12;
    pow(n: bigint): Fq12;
    private degree;
    private primeNumberInvariant;
    private optimizedRoundedDiv;
    invert(): Fq12;
    div(other: Fq12 | bigint): Fq12;
    toString(): string;
}
declare type Constructor<T> = {
    new (...args: any[]): Field<T>;
} & {
    ZERO: Field<T>;
    ONE: Field<T>;
};
export declare class ProjectivePoint<T> {
    x: Field<T>;
    y: Field<T>;
    z: Field<T>;
    C: Constructor<T>;
    static fromAffine(x: Fq2, y: Fq2, C: Constructor<BigintTuple>): ProjectivePoint<BigintTuple>;
    constructor(x: Field<T>, y: Field<T>, z: Field<T>, C: Constructor<T>);
    isZero(): boolean;
    getZero(): ProjectivePoint<T>;
    equals(other: ProjectivePoint<T>): boolean;
    negate(): ProjectivePoint<T>;
    toString(isAffine?: boolean): string;
    toAffine(): [Field<T>, Field<T>];
    double(): ProjectivePoint<T>;
    add(other: ProjectivePoint<T>): ProjectivePoint<T>;
    subtract(other: ProjectivePoint<T>): ProjectivePoint<T>;
    multiply(scalar: number | bigint | Fq): ProjectivePoint<T>;
}
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 {
    private jpoint;
    static BASE: ProjectivePoint<bigint>;
    static ZERO: ProjectivePoint<bigint>;
    constructor(jpoint: ProjectivePoint<bigint>);
    static fromCompressedHex(hex: PublicKey): ProjectivePoint<bigint>;
    static fromPrivateKey(privateKey: PrivateKey): PointG1;
    toCompressedHex(): Uint8Array;
    toFq12(): ProjectivePoint<BigintTwelve>;
    assertValidity(): void;
}
export declare class PointG2 {
    private jpoint;
    static BASE: ProjectivePoint<BigintTuple>;
    static ZERO: ProjectivePoint<BigintTuple>;
    constructor(jpoint: ProjectivePoint<BigintTuple>);
    toString(): string;
    static hashToCurve(msg: PublicKey): Promise<ProjectivePoint<BigintTuple>>;
    static fromSignature(hex: Signature): ProjectivePoint<BigintTuple>;
    static fromPrivateKey(privateKey: PrivateKey): PointG2;
    toSignature(): Uint8Array;
    toFq12(): ProjectivePoint<BigintTwelve>;
    assertValidity(): void;
}
export declare class PointG12 {
    static B: Fq12;
    static W_SQUARE: Fq12;
    static W_CUBE: Fq12;
}
export declare function pairing(P: ProjectivePoint<bigint>, Q: ProjectivePoint<BigintTuple>, withFinalExponent?: boolean): Field<BigintTwelve>;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array;
export declare function sign(message: Hash, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function verify(signature: Signature, message: Hash, publicKey: PublicKey): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: PublicKey[]): Uint8Array;
export declare function aggregateSignatures(signatures: Signature[]): Uint8Array;
export declare function verifyBatch(messages: Hash[], publicKeys: PublicKey[], signature: Signature): Promise<boolean>;
export {};
