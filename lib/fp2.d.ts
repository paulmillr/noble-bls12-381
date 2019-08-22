import { Fp } from "./fp";
import { Group } from "./group";
export declare type BigintTuple = [bigint, bigint];
export declare class Fp2 implements Group<BigintTuple> {
    private static _order;
    private static DIV_ORDER;
    private static EIGHTH_ROOTS_OF_UNITY;
    static COFACTOR: bigint;
    static ORDER: any;
    private coeficient1;
    private coeficient2;
    readonly value: BigintTuple;
    readonly zero: Fp2;
    readonly one: Fp2;
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
