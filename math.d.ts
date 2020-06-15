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
    x: bigint;
    h_eff: bigint;
};
export declare let DST_LABEL: string;
declare type BigintTuple = [bigint, bigint];
declare type BigintSix = [bigint, bigint, bigint, bigint, bigint, bigint];
export declare type BigintTwelve = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
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
export declare function powMod(a: bigint, power: bigint, m: bigint): bigint;
export declare class Fq implements Field<Fq> {
    static readonly ORDER: bigint;
    static readonly MAX_BITS: number;
    static readonly ZERO: Fq;
    static readonly ONE: Fq;
    readonly value: bigint;
    constructor(value: bigint);
    isZero(): boolean;
    equals(rhs: Fq): boolean;
    negate(): Fq;
    invert(): Fq;
    add(rhs: Fq): Fq;
    square(): Fq;
    pow(n: bigint): Fq;
    subtract(rhs: Fq): Fq;
    multiply(rhs: Fq | bigint): Fq;
    div(rhs: Fq | bigint): Fq;
    toString(): string;
}
export declare class Fr implements Field<Fr> {
    static readonly ORDER: bigint;
    static readonly ZERO: Fr;
    static readonly ONE: Fr;
    static isValid(b: bigint): boolean;
    readonly value: bigint;
    constructor(value: bigint);
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
export declare class Fq2 extends FQP<Fq2, Fq, [Fq, Fq]> {
    static readonly ORDER: bigint;
    static readonly MAX_BITS: number;
    static readonly ROOT: Fq;
    static readonly ZERO: Fq2;
    static readonly ONE: Fq2;
    static readonly COFACTOR: bigint;
    static readonly ROOTS_OF_UNITY: Fq2[];
    static readonly ETAs: Fq2[];
    static readonly FROBENIUS_COEFFICIENTS: Fq[];
    readonly c: [Fq, Fq];
    constructor(coeffs: [Fq, Fq] | [bigint, bigint] | bigint[]);
    init(tuple: [Fq, Fq]): Fq2;
    toString(): string;
    get values(): BigintTuple;
    multiply(rhs: Fq2 | bigint): Fq2;
    mulByNonresidue(): Fq2;
    square(): Fq2;
    sqrt(): Fq2 | undefined;
    invert(): Fq2;
    frobeniusMap(power: number): Fq2;
    multiplyByB(): Fq2;
}
export declare class Fq6 extends FQP<Fq6, Fq2, [Fq2, Fq2, Fq2]> {
    readonly c: [Fq2, Fq2, Fq2];
    static readonly ZERO: Fq6;
    static readonly ONE: Fq6;
    static readonly FROBENIUS_COEFFICIENTS_1: Fq2[];
    static readonly FROBENIUS_COEFFICIENTS_2: Fq2[];
    static fromTuple(t: BigintSix): Fq6;
    constructor(c: [Fq2, Fq2, Fq2]);
    init(triple: [Fq2, Fq2, Fq2]): Fq6;
    toString(): string;
    conjugate(): any;
    multiply(rhs: Fq6 | bigint): Fq6;
    mulByNonresidue(): Fq6;
    multiplyBy1(b1: Fq2): Fq6;
    multiplyBy01(b0: Fq2, b1: Fq2): Fq6;
    multiplyByFq2(rhs: Fq2): Fq6;
    square(): Fq6;
    invert(): Fq6;
    frobeniusMap(power: number): Fq6;
}
export declare class Fq12 extends FQP<Fq12, Fq6, [Fq6, Fq6]> {
    readonly c: [Fq6, Fq6];
    static readonly ZERO: Fq12;
    static readonly ONE: Fq12;
    static readonly FROBENIUS_COEFFICIENTS: Fq2[];
    static fromTuple(t: BigintTwelve): Fq12;
    constructor(c: [Fq6, Fq6]);
    init(c: [Fq6, Fq6]): Fq12;
    toString(): string;
    multiply(rhs: Fq12 | bigint): Fq12;
    multiplyBy014(o0: Fq2, o1: Fq2, o4: Fq2): Fq12;
    multiplyByFq2(rhs: Fq2): Fq12;
    square(): Fq12;
    invert(): Fq12;
    frobeniusMap(power: number): Fq12;
    private Fq4Square;
    private cyclotomicSquare;
    private cyclotomicExp;
    finalExponentiate(): Fq12;
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
    getPoint<TT extends this>(x: T, y: T, z: T): TT;
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
    multiplyUnsafe(scalar: number | bigint | Fq): this;
    private maxBits;
    private precomputeWindow;
    calcMultiplyPrecomputes(W: number): void;
    clearMultiplyPrecomputes(): void;
    private wNAF;
    multiply(scalar: number | bigint | Fq): this;
}
export declare function map_to_curve_SSWU_G2(t: bigint[] | Fq2): [Fq2, Fq2, Fq2];
export declare function isogenyMapG2(xyz: [Fq2, Fq2, Fq2]): [Fq2, Fq2, Fq2];
declare type EllCoefficients = [Fq2, Fq2, Fq2];
export declare function calcPairingPrecomputes(x: Fq2, y: Fq2): EllCoefficients[];
export declare function millerLoop(ell: EllCoefficients[], g1: [Fq, Fq]): Fq12;
export declare function psi(x: Fq2, y: Fq2): [Fq2, Fq2];
export declare function psi2(x: Fq2, y: Fq2): [Fq2, Fq2];
declare type Numerators = [Fq2, Fq2, Fq2, Fq2];
export declare const isogenyCoefficients: Numerators[];
export {};
