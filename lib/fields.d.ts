declare type IncludedTypes<Base, Type> = {
    [Key in keyof Base]: Base[Key] extends Type ? Key : never;
};
declare type AllowedNames<Base, Type> = keyof IncludedTypes<Base, Type>;
export interface Group<T> {
    readonly one: Group<T>;
    readonly zero: Group<T>;
    readonly value: T;
    normalize(v: Group<T> | T | bigint): bigint | Group<T>;
    isEmpty(): boolean;
    equals(otherValue: Group<T> | T): boolean;
    add(otherValue: Group<T> | T): Group<T>;
    multiply(otherValue: Group<T> | T | bigint): Group<T>;
    div(otherValue: Group<T> | T | bigint): Group<T>;
    square(): Group<T>;
    subtract(otherValue: Group<T> | T): Group<T>;
    negative(): Group<T>;
    invert(): Group<T>;
    pow(n: bigint): Group<T>;
}
export declare function normalized<T, G extends Group<T>, M extends AllowedNames<G, Function>>(target: G, propertyKey: M, descriptor: PropertyDescriptor): PropertyDescriptor;
export declare type BigintTuple = [bigint, bigint];
export declare class Fp implements Group<bigint> {
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
export declare class Fp2 implements Group<BigintTuple> {
    private static _order;
    private static DIV_ORDER;
    private static EIGHTH_ROOTS_OF_UNITY;
    static COFACTOR: bigint;
    static set ORDER(order: bigint);
    static get ORDER(): bigint;
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
    modularSquereRoot(): Fp2 | null;
    pow(n: bigint): Fp2;
    invert(): Fp2;
    div(otherValue: Fp2 | bigint): Fp2;
}
export declare type BigintTwelve = [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
declare type Fp12Like = Fp12 | BigintTwelve;
export declare type FpTwelve = [Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp, Fp];
export declare class Fp12 implements Group<BigintTwelve> {
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
    new (...args: any[]): Group<T>;
};
export declare class Point<T> {
    x: Group<T>;
    y: Group<T>;
    z: Group<T>;
    private C;
    static get W(): Fp12;
    static get W_SQUARE(): Fp12;
    static get W_CUBE(): Fp12;
    constructor(x: Group<T>, y: Group<T>, z: Group<T>, C: Constructor<T>);
    isEmpty(): boolean;
    isOnCurve(b: Group<T>): boolean;
    equals(other: Point<T>): boolean;
    negative(): Point<T>;
    to2D(): Group<T>[];
    double(): Point<T>;
    add(other: Point<T>): Point<T>;
    subtract(other: Point<T>): Point<T>;
    multiply(n: number | bigint): Point<T>;
    twist(): Point<BigintTwelve>;
}
export {};
