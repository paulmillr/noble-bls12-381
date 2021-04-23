import * as fc from 'fast-check';
import { Fq } from '..';

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });
const FC_BIGINT = fc.bigInt(1n, Fq.ORDER - 1n);

describe('bls12-381 Fp', () => {
  it('Fp equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        const b = new Fq(num);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      })
    );
  });
  it('Fp non-equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        expect(a.equals(b)).toBe(num1 === num2);
        expect(b.equals(a)).toBe(num1 === num2);
      })
    );
  });
  it('Fp square and multiplication equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.square()).toEqual(a.multiply(a));
      })
    );
  });
  it('Fp multiplication and add equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.multiply(new Fq(0n))).toEqual(Fq.ZERO);
        expect(a.multiply(Fq.ZERO)).toEqual(Fq.ZERO);
        expect(a.multiply(new Fq(1n))).toEqual(a);
        expect(a.multiply(Fq.ONE)).toEqual(a);
        expect(a.multiply(new Fq(2n))).toEqual(a.add(a));
        expect(a.multiply(new Fq(3n))).toEqual(a.add(a).add(a));
        expect(a.multiply(new Fq(4n))).toEqual(a.add(a).add(a).add(a));
      })
    );
  });
  it('Fp multiplication commutatity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        expect(a.multiply(b)).toEqual(b.multiply(a));
      })
    );
  });
  it('Fp multiplication associativity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        const c = new Fq(num3);
        expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
      })
    );
  });
  it('Fp multiplication distributivity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        const c = new Fq(num3);
        expect(a.multiply(b.add(c))).toEqual(b.multiply(a).add(c.multiply(a)));
      })
    );
  });
  it('Fp division with one equality', () => {
    fc.assert(
      fc.property(fc.bigInt(1n, Fq.ORDER - 1n), (num) => {
        const a = new Fq(num);
        expect(a.div(Fq.ONE)).toEqual(a);
        expect(a.div(a)).toEqual(Fq.ONE);
      })
    );
  });
  it('Fp division with.ZERO equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(Fq.ZERO.div(a)).toEqual(Fq.ZERO);
      })
    );
  });
  it('Fp division distributivity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        const c = new Fq(num3);
        expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
      })
    );
  });
  it('Fp addition with.ZERO equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.add(Fq.ZERO)).toEqual(a);
      })
    );
  });
  it('Fp addition commutatity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        expect(a.add(b)).toEqual(b.add(a));
      })
    );
  });
  it('Fp add associativity', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        const c = new Fq(num3);
        expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
      })
    );
  });
  it('Fp minus.ZERO equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.subtract(Fq.ZERO)).toEqual(a);
        expect(a.subtract(a)).toEqual(Fq.ZERO);
      })
    );
  });
  it('Fp minus and negative equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1) => {
        const a = new Fq(num1);
        const b = new Fq(num1);
        expect(Fq.ZERO.subtract(a)).toEqual(a.negate());
        expect(a.subtract(b)).toEqual(a.add(b.negate()));
        expect(a.subtract(b)).toEqual(a.add(b.multiply(new Fq(-1n))));
      })
    );
  });
  it('Fp negative equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.negate()).toEqual(Fq.ZERO.subtract(a));
        expect(a.negate()).toEqual(a.multiply(new Fq(-1n)));
      })
    );
  });
  it('Fp division and multiplitaction equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
        const a = new Fq(num1);
        const b = new Fq(num2);
        expect(a.div(b)).toEqual(a.multiply(b.invert()));
      })
    );
  });
  it('Fp pow and multiplitaction equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fq(num);
        expect(a.pow(0n)).toEqual(Fq.ONE);
        expect(a.pow(1n)).toEqual(a);
        expect(a.pow(2n)).toEqual(a.multiply(a));
        expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
      })
    );
  });
});
