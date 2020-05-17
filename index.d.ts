export declare const CURVE: {
    P: bigint;
    r: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
    P2: bigint;
    h2: bigint;
    G2x: bigint[];
    G2y: bigint[];
};
declare type Bytes = Uint8Array | string;
declare type Hash = Bytes;
declare type PrivateKey = Bytes | bigint | number;
declare type Domain = PrivateKey;
declare type PublicKey = Bytes;
declare type Signature = Bytes;
declare type BigintTuple = [bigint, bigint];
export declare type BigintTwelve = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
declare type Fp12Like = Fp12 | BigintTwelve;
interface Field<T> {
    readonly one: Field<T>;
    readonly zero: Field<T>;
    readonly value: T;
    normalize(v: Field<T> | T | bigint): bigint | Field<T>;
    isEmpty(): boolean;
    equals(otherValue: Field<T> | T): boolean;
    add(otherValue: Field<T> | T): Field<T>;
    multiply(otherValue: Field<T> | T | bigint): Field<T>;
    div(otherValue: Field<T> | T | bigint): Field<T>;
    square(): Field<T>;
    subtract(otherValue: Field<T> | T): Field<T>;
    negative(): Field<T>;
    invert(): Field<T>;
    pow(n: bigint): Field<T>;
}
export declare class Fp implements Field<bigint> {
    static ORDER: bigint;
    private _value;
    get value(): bigint;
    get zero(): Fp;
    get one(): Fp;
    constructor(value?: bigint);
    private mod;
    normalize(v: Fp | bigint): Fp;
    isEmpty(): boolean;
    equals(other: Fp): boolean;
    negative(): Fp;
    invert(): Fp;
    add(other: Fp | bigint): Fp;
    square(): Fp;
    pow(n: bigint): Fp;
    subtract(other: Fp | bigint): Fp;
    multiply(other: Fp | bigint): Fp;
    div(other: Fp | bigint): Fp;
}
export declare class Fp2 implements Field<BigintTuple> {
    static ORDER: bigint;
    static DIV_ORDER: bigint;
    private static EIGHTH_ROOTS_OF_UNITY;
    static COFACTOR: bigint;
    private coeficient1;
    private coeficient2;
    get value(): BigintTuple;
    get zero(): Fp2;
    get one(): Fp2;
    constructor(coef1?: Fp | bigint, coef2?: Fp | bigint);
    normalize(v: Fp2 | BigintTuple | bigint): bigint | Fp2;
    isEmpty(): boolean;
    equals(rhs: Fp2): boolean;
    negative(): Fp2;
    add(rhs: Fp2): Fp2;
    subtract(rhs: Fp2): Fp2;
    multiply(otherValue: Fp2 | bigint): Fp2;
    mulByNonresidue(): Fp2;
    square(): Fp2;
    sqrt(): Fp2 | null;
    pow(n: bigint): Fp2;
    invert(): Fp2;
    div(otherValue: Fp2 | bigint): Fp2;
}
export declare class Fp12 implements Field<BigintTwelve> {
    private coefficients;
    private static readonly MODULE_COEFFICIENTS;
    private static readonly ENTRY_COEFFICIENTS;
    get value(): BigintTwelve;
    get zero(): Fp12;
    get one(): Fp12;
    constructor();
    constructor(c0: Fp, c1: Fp, c2: Fp, c3: Fp, c4: Fp, c5: Fp, c6: Fp, c7: Fp, c8: Fp, c9: Fp, c10: Fp, c11: Fp);
    constructor(c0: bigint, c1: bigint, c2: bigint, c3: bigint, c4: bigint, c5: bigint, c6: bigint, c7: bigint, c8: bigint, c9: bigint, c10: bigint, c11: bigint);
    normalize(v: Fp12Like | bigint): bigint | Fp12;
    isEmpty(): boolean;
    equals(rhs: Fp12Like): boolean;
    negative(): Fp12;
    add(rhs: Fp12Like): Fp12;
    subtract(rhs: Fp12Like): Fp12;
    multiply(otherValue: Fp12Like | bigint): Fp12;
    square(): Fp12;
    pow(n: bigint): Fp12;
    private degree;
    private primeNumberInvariant;
    private optimizedRoundedDiv;
    invert(): Fp12;
    div(otherValue: Fp12 | bigint): Fp12;
}
declare type Constructor<T> = {
    new (...args: any[]): Field<T>;
};
export declare class Point<T> {
    x: Field<T>;
    y: Field<T>;
    z: Field<T>;
    private C;
    static get W(): Fp12;
    static get W_SQUARE(): Fp12;
    static get W_CUBE(): Fp12;
    constructor(x: Field<T>, y: Field<T>, z: Field<T>, C: Constructor<T>);
    isEmpty(): boolean;
    isOnCurve(b: Field<T>): boolean;
    equals(other: Point<T>): boolean;
    negative(): Point<T>;
    to2D(): Field<T>[];
    double(): Point<T>;
    add(other: Point<T>): Point<T>;
    subtract(other: Point<T>): Point<T>;
    multiply(n: number | bigint): Point<T>;
    twist(): Point<BigintTwelve>;
}
export declare const B: Fp;
export declare const B2: Fp2;
export declare const B12: Fp12;
export declare function signatureToG2(signature: Bytes): Point<BigintTuple>;
export declare function hashToG2(hash: Hash, domain: Bytes): Promise<Point<BigintTuple>>;
export declare const G1: Point<bigint>;
export declare const G2: Point<BigintTuple>;
export declare function pairing(Q: Point<BigintTuple>, P: Point<bigint>, withFinalExponent?: boolean): Field<BigintTwelve>;
export declare function getPublicKey(privateKey: PrivateKey): Uint8Array;
export declare function sign(message: Hash, privateKey: PrivateKey, domain: Domain): Promise<Uint8Array>;
export declare function verify(message: Hash, publicKey: PublicKey, signature: Signature, domain: Domain): Promise<boolean>;
export declare function aggregatePublicKeys(publicKeys: PublicKey[]): Uint8Array;
export declare function aggregateSignatures(signatures: Signature[]): Uint8Array;
export declare function verifyBatch(messages: Hash[], publicKeys: PublicKey[], signature: Signature, domain: Domain): Promise<boolean>;
export {};
