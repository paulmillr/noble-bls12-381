import * as fc from "fast-check";
import { Fp, Fp2 } from "..";

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

describe("bls12-381 Fp2", () => {
  it("Fp2 equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        const b = new Fp2(num[0], num[1]);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 non-equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          expect(a.equals(b)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
          expect(b.equals(a)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 square and multiplication equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.square()).toEqual(a.multiply(a));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 multiplication and add equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.multiply(0n)).toEqual(Fp2.ZERO);
        expect(a.multiply(Fp2.ZERO)).toEqual(Fp2.ZERO);
        expect(a.multiply(1n)).toEqual(a);
        expect(a.multiply(Fp2.ONE)).toEqual(a);
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
  it("Fp2 multiplication commutatity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          expect(a.multiply(b)).toEqual(b.multiply(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 multiplication associativity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2, num3) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          const c = new Fp2(num3[0], num3[1]);
          expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 multiplication distributivity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2, num3) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          const c = new Fp2(num3[0], num3[1]);
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
  it("Fp2 division with one equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.div(new Fp2(1n, 0n))).toEqual(a);
        expect(a.div(Fp2.ONE)).toEqual(a);
        expect(a.div(a)).toEqual(Fp2.ONE);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 division with zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(Fp2.ZERO.div(a)).toEqual(Fp2.ZERO);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 division distributivity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2, num3) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          const c = new Fp2(num3[0], num3[1]);
          expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 addition with zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.add(Fp2.ZERO)).toEqual(a);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 addition commutatity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          expect(a.add(b)).toEqual(b.add(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 add associativity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2, num3) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          const c = new Fp2(num3[0], num3[1]);
          expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 minus zero equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.subtract(Fp2.ZERO)).toEqual(a);
        expect(a.subtract(a)).toEqual(Fp2.ZERO);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 minus and negative equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num1[0], num1[1]);
          expect(Fp2.ZERO.subtract(a)).toEqual(a.negate());
          expect(a.subtract(b)).toEqual(a.add(b.negate()));
          expect(a.subtract(b)).toEqual(a.add(b.multiply(-1n)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 negative equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.negate()).toEqual(Fp2.ZERO.subtract(a));
        expect(a.negate()).toEqual(a.multiply(-1n));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 division and multiplitaction equality", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2),
        (num1, num2) => {
          const a = new Fp2(num1[0], num1[1]);
          const b = new Fp2(num2[0], num2[1]);
          expect(a.div(b)).toEqual(a.multiply(b.invert()));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp2 pow and multiplitaction equality", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), num => {
        const a = new Fp2(num[0], num[1]);
        expect(a.pow(0n)).toEqual(Fp2.ONE);
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
