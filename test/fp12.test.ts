import * as fc from 'fast-check';
import { Arbitrary } from 'fast-check';
import { Fp, Fp12 } from '..';

// prettier-ignore
type BigintTwelve = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint
];

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });
const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
const FC_BIGINT_12 = fc.array(FC_BIGINT, {
  minLength: 12,
  maxLength: 12,
}) as Arbitrary<BigintTwelve>;

describe('bls12-381 Fp12', () => {
  it('equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_12, (num) => {
        const a = Fp12.fromBigTwelve(num);
        const b = Fp12.fromBigTwelve(num);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      })
    );
  });
  it('non-equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_12, FC_BIGINT_12, (num1, num2) => {
        const a = Fp12.fromBigTwelve(num1);
        const b = Fp12.fromBigTwelve(num2);
        expect(a.equals(b)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
        expect(b.equals(a)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
      })
    );
  });
  describe('add/subtract', () => {
    it('commutativuty', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, (num1, num2) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          expect(a.add(b)).toEqual(b.add(a));
        })
      );
    });
    it('associativity', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, FC_BIGINT_12, (num1, num2, num3) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          const c = Fp12.fromBigTwelve(num3);
          expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
        })
      );
    });
    it('x+0=x', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.add(Fp12.ZERO)).toEqual(a);
        })
      );
    });
    it('x-0=x', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.subtract(Fp12.ZERO)).toEqual(a);
          expect(a.subtract(a)).toEqual(Fp12.ZERO);
        })
      );
    });
    it('negate equality', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num1) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num1);
          expect(Fp12.ZERO.subtract(a)).toEqual(a.negate());
          expect(a.subtract(b)).toEqual(a.add(b.negate()));
          expect(a.subtract(b)).toEqual(a.add(b.multiply(-1n)));
        })
      );
    });
    it('negate', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.negate()).toEqual(Fp12.ZERO.subtract(a));
          expect(a.negate()).toEqual(a.multiply(-1n));
        })
      );
    });
  });
  describe('multiply', () => {
    it('commutativity', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, (num1, num2) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          expect(a.multiply(b)).toEqual(b.multiply(a));
        })
      );
    });
    it('associativity', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, FC_BIGINT_12, (num1, num2, num3) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          const c = Fp12.fromBigTwelve(num3);
          expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
        })
      );
    });
    it('distributivity', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, FC_BIGINT_12, (num1, num2, num3) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          const c = Fp12.fromBigTwelve(num3);
          expect(a.multiply(b.add(c))).toEqual(b.multiply(a).add(c.multiply(a)));
        })
      );
    });
    it('add equality', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.multiply(0n)).toEqual(Fp12.ZERO);
          expect(a.multiply(Fp12.ZERO)).toEqual(Fp12.ZERO);
          expect(a.multiply(1n)).toEqual(a);
          expect(a.multiply(Fp12.ONE)).toEqual(a);
          expect(a.multiply(2n)).toEqual(a.add(a));
          expect(a.multiply(3n)).toEqual(a.add(a).add(a));
          expect(a.multiply(4n)).toEqual(a.add(a).add(a).add(a));
        })
      );
    });
    it('square equality', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.square()).toEqual(a.multiply(a));
        })
      );
    });
    it('pow equality', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.pow(0n)).toEqual(Fp12.ONE);
          expect(a.pow(1n)).toEqual(a);
          expect(a.pow(2n)).toEqual(a.multiply(a));
          expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
        })
      );
    });
  });
  describe('div', () => {
    it('x/1=x', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(a.div(1n)).toEqual(a);
          expect(a.div(Fp12.ONE)).toEqual(a);
          expect(a.div(a)).toEqual(Fp12.ONE);
        })
      );
    });
    it('x/0=0', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, (num) => {
          const a = Fp12.fromBigTwelve(num);
          expect(Fp12.ZERO.div(a)).toEqual(Fp12.ZERO);
        })
      );
    });
    it('distributivity', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, FC_BIGINT_12, (num1, num2, num3) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          const c = Fp12.fromBigTwelve(num3);
          expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
        })
      );
    });
    it('multiply equality', () => {
      fc.assert(
        fc.property(FC_BIGINT_12, FC_BIGINT_12, (num1, num2) => {
          const a = Fp12.fromBigTwelve(num1);
          const b = Fp12.fromBigTwelve(num2);
          expect(a.div(b)).toEqual(a.multiply(b.invert()));
        })
      );
    });
  });
});
