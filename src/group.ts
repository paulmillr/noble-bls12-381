type ArgumentTypes<F extends Function> = F extends (...args: infer A) => any
  ? A
  : never;
type ReturnType<T extends Function> = T extends (...args: any[]) => infer R
  ? R
  : any;
type IncludedTypes<Base, Type> = {
  [Key in keyof Base]: Base[Key] extends Type ? Key : never
};
type AllowedNames<Base, Type> = keyof IncludedTypes<Base, Type>;

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

export function normalized<
  T,
  G extends Group<T>,
  M extends AllowedNames<G, Function>
>(
  target: G,
  propertyKey: M,
  descriptor: PropertyDescriptor
): PropertyDescriptor {
  type GroupMethod = G[M] & Function;
  const propertyValue: G[M] | GroupMethod = target[propertyKey];
  if (typeof propertyValue !== "function") {
    return descriptor;
  }
  const previousImplementation: GroupMethod = propertyValue;
  descriptor.value = function(arg: G | T | bigint): ReturnType<GroupMethod> {
    const modifiedArgument = target.normalize(arg);
    return previousImplementation.call(this, modifiedArgument);
  };
  return descriptor;
}
