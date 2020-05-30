import * as fc from "fast-check";
import { Fq, Fq12, BigintTwelve } from "..";

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

describe("bls12-381 Fp12", () => {
  it("Fp12 equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        const b = Fq12.from_tuple(num as BigintTwelve);
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
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.square()).toEqual(a.multiply(a));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 multiplication and add equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.multiply(0n)).toEqual(Fq12.ZERO);
        expect(a.multiply(Fq12.ZERO)).toEqual(Fq12.ZERO);
        expect(a.multiply(1n)).toEqual(a);
        expect(a.multiply(Fq12.ONE)).toEqual(a);
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
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
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
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
          const c = Fq12.from_tuple(num3 as BigintTwelve);
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
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
          const c = Fq12.from_tuple(num3 as BigintTwelve);
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.div(1n)).toEqual(a);
        expect(a.div(Fq12.ONE)).toEqual(a);
        expect(a.div(a)).toEqual(Fq12.ONE);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division with zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(Fq12.ZERO.div(a)).toEqual(Fq12.ZERO);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division distributivity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
          const c = Fq12.from_tuple(num3 as BigintTwelve);
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.add(Fq12.ZERO)).toEqual(a);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 addition commutatity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
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
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2, num3) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
          const c = Fq12.from_tuple(num3 as BigintTwelve);
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.subtract(Fq12.ZERO)).toEqual(a);
        expect(a.subtract(a)).toEqual(Fq12.ZERO);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 minus and negative equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num1 as BigintTwelve);
          expect(Fq12.ZERO.subtract(a)).toEqual(a.negate());
          expect(a.subtract(b)).toEqual(a.add(b.negate()));
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.negate()).toEqual(Fq12.ZERO.subtract(a));
        expect(a.negate()).toEqual(a.multiply(-1n));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp12 division and multiplitaction equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12),
        (num1, num2) => {
          const a = Fq12.from_tuple(num1 as BigintTwelve);
          const b = Fq12.from_tuple(num2 as BigintTwelve);
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
      fc.property(fc.array(fc.bigInt(1n, Fq.ORDER), 12, 12), num => {
        const a = Fq12.from_tuple(num as BigintTwelve);
        expect(a.pow(0n)).toEqual(Fq12.ONE);
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

