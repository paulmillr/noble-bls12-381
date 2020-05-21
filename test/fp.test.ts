import * as fc from "fast-check";
import { Fp } from "..";

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

describe("bls12-381 Fp", () => {
  it("Fp equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        const b = new Fp(num);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp non-equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.equals(b)).toBe(num1 === num2);
          expect(b.equals(a)).toBe(num1 === num2);
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp square and multiplication equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        expect(a.square()).toEqual(a.multiply(a));
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp multiplication and add equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        expect(a.multiply(new Fp(0n))).toEqual(Fp.ZERO);
        expect(a.multiply(Fp.ZERO)).toEqual(Fp.ZERO);
        expect(a.multiply(new Fp(1n))).toEqual(a);
        expect(a.multiply(Fp.ONE)).toEqual(a);
        expect(a.multiply(new Fp(2n))).toEqual(a.add(a));
        expect(a.multiply(new Fp(3n))).toEqual(a.add(a).add(a));
        expect(a.multiply(new Fp(4n))).toEqual(
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
  it("Fp multiplication commutatity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.multiply(b)).toEqual(b.multiply(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp multiplication associativity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp multiplication distributivity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
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
  it("Fp division with one equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        expect(a.div(Fp.ONE)).toEqual(a);
        expect(a.div(a)).toEqual(Fp.ONE);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp division with.ZERO equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        expect(Fp.ZERO.div(a)).toEqual(Fp.ZERO);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp division distributivity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp addition with.ZERO equality", () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fp.ORDER), num => {
        const a = new Fp(num);
        expect(a.add(Fp.ZERO)).toEqual(a);
      }),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp addition commutatity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.add(b)).toEqual(b.add(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp add associativity", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp minus.ZERO equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        num => {
          const a = new Fp(num);
          expect(a.subtract(Fp.ZERO)).toEqual(a);
          expect(a.subtract(a)).toEqual(Fp.ZERO);
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp minus and negative equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1) => {
          const a = new Fp(num1);
          const b = new Fp(num1);
          expect(Fp.ZERO.subtract(a)).toEqual(a.negate());
          expect(a.subtract(b)).toEqual(a.add(b.negate()));
          expect(a.subtract(b)).toEqual(a.add(b.multiply(new Fp(-1n))));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp negative equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        num => {
          const a = new Fp(num);
          expect(a.negate()).toEqual(Fp.ZERO.subtract(a));
          expect(a.negate()).toEqual(a.multiply(new Fp(-1n)));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp division and multiplitaction equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        fc.bigInt(1n, Fp.ORDER),
        (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.div(b)).toEqual(a.multiply(b.invert()));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
  it("Fp pow and multiplitaction equality", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, Fp.ORDER),
        num => {
          const a = new Fp(num);
          expect(a.pow(0n)).toEqual(Fp.ONE);
          expect(a.pow(1n)).toEqual(a);
          expect(a.pow(2n)).toEqual(a.multiply(a));
          expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
        }
      ),
      {
        numRuns: NUM_RUNS
      }
    );
  });
});
