import { Group } from "./group";
import { Fp12 } from "./fp12";
declare type Constructor<T> = {
    new (...args: any[]): Group<T>;
};
export declare class Point<T> {
    x: Group<T>;
    y: Group<T>;
    z: Group<T>;
    private C;
    static readonly W: Fp12;
    static readonly W_SQUARE: Fp12;
    static readonly W_CUBE: Fp12;
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
    twist(): Point<[bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint]>;
}
export {};
