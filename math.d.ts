export declare const CURVE: {
    P: bigint;
    r: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
    b: bigint;
    hEff: bigint;
    P2: bigint;
    h2: bigint;
    G2x: bigint[];
    G2y: bigint[];
    b2: bigint[];
    x: bigint;
    h2Eff: bigint;
};
declare type BigintTuple = [bigint, bigint];
declare type BigintSix = [bigint, bigint, bigint, bigint, bigint, bigint];
declare type BigintTwelve = [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint
];
interface Field<T> {
    isZero(): boolean;
    equals(rhs: T): boolean;
    negate(): T;
    add(rhs: T): T;
    subtract(rhs: T): T;
    invert(): T;
    multiply(rhs: T | bigint): T;
    square(): T;
    pow(n: bigint): T;
    div(rhs: T | bigint): T;
}
declare type FieldStatic<T extends Field<T>> = {
    ZERO: T;
    ONE: T;
};
export declare function mod(a: bigint, b: bigint): bigint;
export declare function powMod(a: bigint, power: bigint, modulo: bigint): bigint;
export declare class Fp implements Field<Fp> {
    static readonly ORDER: bigint;
    static readonly MAX_BITS: number;
    static readonly ZERO: Fp;
    static readonly ONE: Fp;
    readonly value: bigint;
    constructor(value: bigint);
    isZero(): boolean;
    equals(rhs: Fp): boolean;
    negate(): Fp;
    invert(): Fp;
    add(rhs: Fp): Fp;
    square(): Fp;
    pow(n: bigint): Fp;
    sqrt(): Fp;
    subtract(rhs: Fp): Fp;
    multiply(rhs: Fp | bigint): Fp;
    div(rhs: Fp | bigint): Fp;
    toString(): string;
}
export declare class Fr implements Field<Fr> {
    static readonly ORDER: bigint;
    static readonly ZERO: Fr;
    static readonly ONE: Fr;
    readonly value: bigint;
    constructor(value: bigint);
    static isValid(b: bigint): boolean;
    isZero(): boolean;
    equals(rhs: Fr): boolean;
    negate(): Fr;
    invert(): Fr;
    add(rhs: Fr): Fr;
    square(): Fr;
    pow(n: bigint): Fr;
    subtract(rhs: Fr): Fr;
    multiply(rhs: Fr | bigint): Fr;
    div(rhs: Fr | bigint): Fr;
    legendre(): Fr;
    sqrt(): Fr | undefined;
    toString(): string;
}
declare abstract class FQP<TT extends {
    c: TTT;
} & Field<TT>, CT extends Field<CT>, TTT extends CT[]> implements Field<TT> {
    abstract readonly c: CT[];
    abstract init(c: TTT): TT;
    abstract multiply(rhs: TT | bigint): TT;
    abstract invert(): TT;
    abstract square(): TT;
    zip<T, RT extends T[]>(rhs: TT, mapper: (left: CT, right: CT) => T): RT;
    map<T, RT extends T[]>(callbackfn: (value: CT) => T): RT;
    isZero(): boolean;
    equals(rhs: TT): boolean;
    negate(): TT;
    add(rhs: TT): TT;
    subtract(rhs: TT): TT;
    conjugate(): TT;
    private one;
    pow(n: bigint): TT;
    div(rhs: TT | bigint): TT;
}
export declare class Fp2 extends FQP<Fp2, Fp, [Fp, Fp]> {
    static readonly ORDER: bigint;
    static readonly MAX_BITS: number;
    static readonly ZERO: Fp2;
    static readonly ONE: Fp2;
    readonly c: [Fp, Fp];
    constructor(coeffs: [Fp, Fp] | [bigint, bigint] | bigint[]);
    init(tuple: [Fp, Fp]): Fp2;
    toString(): string;
    get values(): BigintTuple;
    multiply(rhs: Fp2 | bigint): Fp2;
    mulByNonresidue(): Fp2;
    square(): Fp2;
    sqrt(): Fp2 | undefined;
    invert(): Fp2;
    frobeniusMap(power: number): Fp2;
    multiplyByB(): Fp2;
}
export declare class Fp6 extends FQP<Fp6, Fp2, [Fp2, Fp2, Fp2]> {
    readonly c: [Fp2, Fp2, Fp2];
    static readonly ZERO: Fp6;
    static readonly ONE: Fp6;
    static fromTuple(t: BigintSix): Fp6;
    constructor(c: [Fp2, Fp2, Fp2]);
    init(triple: [Fp2, Fp2, Fp2]): Fp6;
    toString(): string;
    conjugate(): any;
    multiply(rhs: Fp6 | bigint): Fp6;
    mulByNonresidue(): Fp6;
    multiplyBy1(b1: Fp2): Fp6;
    multiplyBy01(b0: Fp2, b1: Fp2): Fp6;
    multiplyByFp2(rhs: Fp2): Fp6;
    square(): Fp6;
    invert(): Fp6;
    frobeniusMap(power: number): Fp6;
}
export declare class Fp12 extends FQP<Fp12, Fp6, [Fp6, Fp6]> {
    readonly c: [Fp6, Fp6];
    static readonly ZERO: Fp12;
    static readonly ONE: Fp12;
    static fromTuple(t: BigintTwelve): Fp12;
    constructor(c: [Fp6, Fp6]);
    init(c: [Fp6, Fp6]): Fp12;
    toString(): string;
    multiply(rhs: Fp12 | bigint): Fp12;
    multiplyBy014(o0: Fp2, o1: Fp2, o4: Fp2): Fp12;
    multiplyByFp2(rhs: Fp2): Fp12;
    square(): Fp12;
    invert(): Fp12;
    frobeniusMap(power: number): Fp12;
    private Fp4Square;
    private cyclotomicSquare;
    private cyclotomicExp;
    finalExponentiate(): Fp12;
}
declare type Constructor<T extends Field<T>> = {
    new (...args: any[]): T;
} & FieldStatic<T> & {
    MAX_BITS: number;
};
export declare abstract class ProjectivePoint<T extends Field<T>> {
    readonly x: T;
    readonly y: T;
    readonly z: T;
    private readonly C;
    private _MPRECOMPUTES;
    constructor(x: T, y: T, z: T, C: Constructor<T>);
    isZero(): boolean;
    createPoint<TT extends this>(x: T, y: T, z: T): TT;
    getZero(): this;
    equals(rhs: ProjectivePoint<T>): boolean;
    negate(): this;
    toString(isAffine?: boolean): string;
    fromAffineTuple(xy: [T, T]): this;
    toAffine(invZ?: T): [T, T];
    toAffineBatch(points: ProjectivePoint<T>[]): [T, T][];
    normalizeZ(points: this[]): this[];
    double(): this;
    add(rhs: this): this;
    subtract(rhs: this): this;
    private validateScalar;
    multiplyUnsafe(scalar: bigint): this;
    multiply(scalar: bigint): this;
    private maxBits;
    private precomputeWindow;
    calcMultiplyPrecomputes(W: number): void;
    clearMultiplyPrecomputes(): void;
    private wNAF;
    multiplyPrecomputed(scalar: bigint): this;
}
export declare function map_to_curve_simple_swu_9mod16(t: bigint[] | Fp2): [Fp2, Fp2, Fp2];
export declare function isogenyMapG2(xyz: [Fp2, Fp2, Fp2]): [Fp2, Fp2, Fp2];
export declare function calcPairingPrecomputes(x: Fp2, y: Fp2): [Fp2, Fp2, Fp2][];
export declare function millerLoop(ell: [Fp2, Fp2, Fp2][], g1: [Fp, Fp]): Fp12;
export declare function psi(x: Fp2, y: Fp2): [Fp2, Fp2];
export declare function psi2(x: Fp2, y: Fp2): [Fp2, Fp2];
export {};
