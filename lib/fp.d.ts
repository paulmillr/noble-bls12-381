import { Group } from "./group";
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
