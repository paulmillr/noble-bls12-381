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
export {};
