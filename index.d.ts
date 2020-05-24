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
export declare let time: bigint;
interface Field<T> {
    readonly value: T;
    isEmpty(): boolean;
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
    isEmpty(): boolean;
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
    static readonly DIV_ORDER: bigint;
    static readonly ROOT: Fq;
    static readonly ZERO: Fq2;
    static readonly ONE: Fq2;
    static readonly COFACTOR: bigint;
    coefficients: Fq[];
    private degree;
    get real(): Fq;
    get imag(): Fq;
    get value(): BigintTuple;
    constructor(coefficients: (Fq | bigint)[]);
    toString(): string;
    private zip;
    isEmpty(): boolean;
    equals(other: Fq2): boolean;
    negate(): Fq2;
    add(other: Fq2): Fq2;
    subtract(other: Fq2): Fq2;
    multiply(other: Fq2 | bigint): Fq2;
    mulByNonresidue(): Fq2;
    square(): Fq2;
    sqrt(): Fq2 | null;
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
    isEmpty(): boolean;
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
}
declare type Constructor<T> = {
    new (...args: any[]): Field<T>;
} & {
    ZERO: Field<T>;
    ONE: Field<T>;
};
export declare class Point<T> {
    x: Field<T>;
    y: Field<T>;
    z: Field<T>;
    C: Constructor<T>;
    static get W(): Fq12;
    static get W_SQUARE(): Fq12;
    static get W_CUBE(): Fq12;
    static fromAffine(x: Fq2, y: Fq2, C: Constructor<BigintTuple>): Point<BigintTuple>;
    constructor(x: Field<T>, y: Field<T>, z: Field<T>, C: Constructor<T>);
    isZero(): boolean;
    getZero(): Point<T>;
    equals(other: Point<T>): boolean;
    negative(): Point<T>;
    toString(isAffine?: boolean): string;
    toAffine(): [Field<T>, Field<T>];
    double(): Point<T>;
    add(other: Point<T>): Point<T>;
    subtract(other: Point<T>): Point<T>;
    multiply(scalar: number | bigint | Fq): Point<T>;
}
export declare function hash_to_field(msg: Uint8Array, degree: number, isRandomOracle?: boolean): Promise<bigint[][]>;
export declare class PointG1 {
    point: Point<bigint>;
    static BASE: Point<bigint>;
    static ZERO: Point<bigint>;
    constructor(point: Point<bigint>);
    static fromHex(hex: PublicKey): Point<bigint>;
    toHex(): Uint8Array;
    toFq12(): Point<BigintTwelve>;
    assertValidity(): true | undefined;
}
export declare class PointG2 {
    point: Point<BigintTuple>;
    static BASE: Point<BigintTuple>;
    static ZERO: Point<BigintTuple>;
    constructor(point: Point<BigintTuple>);
    static fromx1x1(z1: bigint, z2: bigint): Point<BigintTuple>;
    static fromSignature(hex: Signature): Point<BigintTuple>;
    toHex(): bigint[];
    toSignature(): Uint8Array;
    toFq12(): Point<BigintTwelve>;
    assertValidity(): true | undefined;
}
export declare class PointG12 {
    static B: Fq12;
}
export declare function pairing(Q: Point<BigintTuple>, P: Point<bigint>, withFinalExponent?: boolean): Field<BigintTwelve>;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array;
export declare function sign(message: Hash, privateKey: PrivateKey): Promise<Uint8Array>;
export declare function verify(message: Hash, publicKey: PublicKey, signature: Signature): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: PublicKey[]): Uint8Array;
export declare function aggregateSignatures(signatures: Signature[]): Uint8Array;
export declare function verifyBatch(messages: Hash[], publicKeys: PublicKey[], signature: Signature): Promise<boolean>;
export {};
