import * as fc from "fast-check";
import { Fp, Fp12, BigintTwelve } from "../src/fields";

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

const P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
Fp.ORDER = P;

describe("bls12-381 Fp12", () => {
  it("Fp12 equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        const b = new Fp12(...num as BigintTwelve);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 non-equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          expect(a.equals(b)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
          expect(b.equals(a)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 square and multiplication equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.square()).toEqual(a.multiply(a));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 multiplication and add equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.multiply(0n)).toEqual(a.zero);
        expect(a.multiply(a.zero)).toEqual(a.zero);
        expect(a.multiply(1n)).toEqual(a);
        expect(a.multiply(a.one)).toEqual(a);
        expect(a.multiply(2n)).toEqual(a.add(a));
        expect(a.multiply(3n)).toEqual(a.add(a).add(a));
        expect(a.multiply(4n)).toEqual(
          a
            .add(a)
            .add(a)
            .add(a)
        );
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 multiplication commutatity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          expect(a.multiply(b)).toEqual(b.multiply(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 multiplication associativity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          const c = new Fp12(...num3 as BigintTwelve);
          expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 multiplication distributivity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          const c = new Fp12(...num3 as BigintTwelve);
          expect(a.multiply(b.add(c))).toEqual(
            b.multiply(a).add(c.multiply(a))
          );
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division with one equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.div(1n)).toEqual(a);
        expect(a.div(a.one)).toEqual(a);
        expect(a.div(a)).toEqual(a.one);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division with zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.zero.div(a)).toEqual(a.zero);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division distributivity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          const c = new Fp12(...num3 as BigintTwelve);
          expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 addition with zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.add(a.zero)).toEqual(a);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 addition commutatity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          expect(a.add(b)).toEqual(b.add(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 add associativity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          const c = new Fp12(...num3 as BigintTwelve);
          expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 minus zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.subtract(a.zero)).toEqual(a);
        expect(a.subtract(a)).toEqual(a.zero);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 minus and negative equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num1 as BigintTwelve);
          expect(a.zero.subtract(a)).toEqual(a.negative());
          expect(a.subtract(b)).toEqual(a.add(b.negative()));
          expect(a.subtract(b)).toEqual(a.add(b.multiply(-1n)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 negative equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.negative()).toEqual(a.zero.subtract(a));
        expect(a.negative()).toEqual(a.multiply(-1n));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division and multiplitaction equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12),
        (num1, num2) => {
          const a = new Fp12(...num1 as BigintTwelve);
          const b = new Fp12(...num2 as BigintTwelve);
          expect(a.div(b)).toEqual(a.multiply(b.invert()));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 pow and multiplitaction equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 12, 12), num => {
        const a = new Fp12(...num as BigintTwelve);
        expect(a.pow(0n)).toEqual(a.one);
        expect(a.pow(1n)).toEqual(a);
        expect(a.pow(2n)).toEqual(a.multiply(a));
        expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
});

