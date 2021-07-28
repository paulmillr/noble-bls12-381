import * as fc from 'fast-check';
import { Fp } from '..';

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });
const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);

describe('bls12-381 Fp', () => {
  it('equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, (num) => {
        const a = new Fp(num);
        const b = new Fp(num);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      })
    );
  });
  it('non-equality', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
        const a = new Fp(num1);
        const b = new Fp(num2);
        expect(a.equals(b)).toBe(num1 === num2);
        expect(b.equals(a)).toBe(num1 === num2);
      })
    );
  });
  describe('add/subtract', () => {
    it('commutativity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.add(b)).toEqual(b.add(a));
        })
      );
    });
    it('associativity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
        })
      );
    });
    it('x+0=x', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.add(Fp.ZERO)).toEqual(a);
        })
      );
    });
    it('x-0=x', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.subtract(Fp.ZERO)).toEqual(a);
          expect(a.subtract(a)).toEqual(Fp.ZERO);
        })
      );
    });
    it('negate equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (num1) => {
          const a = new Fp(num1);
          const b = new Fp(num1);
          expect(Fp.ZERO.subtract(a)).toEqual(a.negate());
          expect(a.subtract(b)).toEqual(a.add(b.negate()));
          expect(a.subtract(b)).toEqual(a.add(b.multiply(new Fp(-1n))));
        })
      );
    });
    it('negate', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.negate()).toEqual(Fp.ZERO.subtract(a));
          expect(a.negate()).toEqual(a.multiply(new Fp(-1n)));
        })
      );
    });
  });
  describe('multiply', () => {
    it('commutativity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.multiply(b)).toEqual(b.multiply(a));
        })
      );
    });
    it('associativity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
        })
      );
    });
    it('distributivity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.multiply(b.add(c))).toEqual(b.multiply(a).add(c.multiply(a)));
        })
      );
    });
    it('add equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.multiply(new Fp(0n))).toEqual(Fp.ZERO);
          expect(a.multiply(Fp.ZERO)).toEqual(Fp.ZERO);
          expect(a.multiply(new Fp(1n))).toEqual(a);
          expect(a.multiply(Fp.ONE)).toEqual(a);
          expect(a.multiply(new Fp(2n))).toEqual(a.add(a));
          expect(a.multiply(new Fp(3n))).toEqual(a.add(a).add(a));
          expect(a.multiply(new Fp(4n))).toEqual(a.add(a).add(a).add(a));
        })
      );
    });
    it('square equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.square()).toEqual(a.multiply(a));
        })
      );
    });
    it('pow equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(a.pow(0n)).toEqual(Fp.ONE);
          expect(a.pow(1n)).toEqual(a);
          expect(a.pow(2n)).toEqual(a.multiply(a));
          expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
        })
      );
    });
    it('sqrt', () => {
      expect(new Fp(300855555557n).sqrt()?.value.toString()).toEqual('364533921369419647282142659217537440628656909375169620464770009670699095647614890229414882377952296797827799113624');
      expect(new Fp(72057594037927816n).sqrt()).toBeUndefined();
    });
  });
  describe('div', () => {
    it('division by one equality', () => {
      fc.assert(
        fc.property(fc.bigInt(1n, Fp.ORDER - 1n), (num) => {
          const a = new Fp(num);
          expect(a.div(Fp.ONE)).toEqual(a);
          expect(a.div(a)).toEqual(Fp.ONE);
        })
      );
    });
    it('division by zero equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, (num) => {
          const a = new Fp(num);
          expect(Fp.ZERO.div(a)).toEqual(Fp.ZERO);
        })
      );
    });
    it('division distributivity', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          const c = new Fp(num3);
          expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
        })
      );
    });
    it('division and multiplication equality', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
          const a = new Fp(num1);
          const b = new Fp(num2);
          expect(a.div(b)).toEqual(a.multiply(b.invert()));
        })
      );
    });
  })
});
