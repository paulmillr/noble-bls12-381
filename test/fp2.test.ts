import * as fc from 'fast-check';
import { Fp, Fp2 } from '..';

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });
const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
const FC_BIGINT_2 = fc.array(FC_BIGINT, 2, 2);

describe('bls12-381 Fp2', () => {
  it('Fp2 equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        const b = new Fp2([num[0], num[1]]);
        expect(a.equals(b)).toBe(true);
        expect(b.equals(a)).toBe(true);
      })
    );
  });
  it('Fp2 non-equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        expect(a.equals(b)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
        expect(b.equals(a)).toBe(num1[0] === num2[0] && num1[1] === num2[1]);
      })
    );
  });
  it('Fp2 square and multiplication equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.square()).toEqual(a.multiply(a));
      })
    );
  });
  it('Fp2 multiplication and add equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.multiply(0n)).toEqual(Fp2.ZERO);
        expect(a.multiply(Fp2.ZERO)).toEqual(Fp2.ZERO);
        expect(a.multiply(1n)).toEqual(a);
        expect(a.multiply(Fp2.ONE)).toEqual(a);
        expect(a.multiply(2n)).toEqual(a.add(a));
        expect(a.multiply(3n)).toEqual(a.add(a).add(a));
        expect(a.multiply(4n)).toEqual(a.add(a).add(a).add(a));
      })
    );
  });
  it('Fp2 multiplication commutatity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        expect(a.multiply(b)).toEqual(b.multiply(a));
      })
    );
  });
  it('Fp2 multiplication associativity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, FC_BIGINT_2, (num1, num2, num3) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        const c = new Fp2([num3[0], num3[1]]);
        expect(a.multiply(b.multiply(c))).toEqual(a.multiply(b).multiply(c));
      })
    );
  });
  it('Fp2 multiplication distributivity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, FC_BIGINT_2, (num1, num2, num3) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        const c = new Fp2([num3[0], num3[1]]);
        expect(a.multiply(b.add(c))).toEqual(b.multiply(a).add(c.multiply(a)));
      })
    );
  });
  it('Fp2 division with one equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.div(new Fp2([1n, 0n]))).toEqual(a);
        expect(a.div(Fp2.ONE)).toEqual(a);
        expect(a.div(a)).toEqual(Fp2.ONE);
      })
    );
  });
  it('Fp2 division with zero equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(Fp2.ZERO.div(a)).toEqual(Fp2.ZERO);
      })
    );
  });
  it('Fp2 division distributivity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, FC_BIGINT_2, (num1, num2, num3) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        const c = new Fp2([num3[0], num3[1]]);
        expect(a.add(b).div(c)).toEqual(a.div(c).add(b.div(c)));
      })
    );
  });
  it('Fp2 addition with zero equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.add(Fp2.ZERO)).toEqual(a);
      })
    );
  });
  it('Fp2 addition commutatity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        expect(a.add(b)).toEqual(b.add(a));
      })
    );
  });
  it('Fp2 add associativity', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, FC_BIGINT_2, (num1, num2, num3) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        const c = new Fp2([num3[0], num3[1]]);
        expect(a.add(b.add(c))).toEqual(a.add(b).add(c));
      })
    );
  });
  it('Fp2 minus zero equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.subtract(Fp2.ZERO)).toEqual(a);
        expect(a.subtract(a)).toEqual(Fp2.ZERO);
      })
    );
  });
  it('Fp2 minus and negative equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num1[0], num1[1]]);
        expect(Fp2.ZERO.subtract(a)).toEqual(a.negate());
        expect(a.subtract(b)).toEqual(a.add(b.negate()));
        expect(a.subtract(b)).toEqual(a.add(b.multiply(-1n)));
      })
    );
  });
  it('Fp2 negative equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.negate()).toEqual(Fp2.ZERO.subtract(a));
        expect(a.negate()).toEqual(a.multiply(-1n));
      })
    );
  });
  it('Fp2 division and multiplitaction equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
        const a = new Fp2([num1[0], num1[1]]);
        const b = new Fp2([num2[0], num2[1]]);
        expect(a.div(b)).toEqual(a.multiply(b.invert()));
      })
    );
  });
  it('Fp2 pow and multiplitaction equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = new Fp2([num[0], num[1]]);
        expect(a.pow(0n)).toEqual(Fp2.ONE);
        expect(a.pow(1n)).toEqual(a);
        expect(a.pow(2n)).toEqual(a.multiply(a));
        expect(a.pow(3n)).toEqual(a.multiply(a).multiply(a));
      })
    );
  });
  it('Fp2 frobenius', () => {
    // expect(Fp2.FROBENIUS_COEFFICIENTS[0].equals(Fp.ONE)).toBe(true);
    // expect(
    //   Fp2.FROBENIUS_COEFFICIENTS[1].equals(
    //     Fp.ONE.negate().pow(
    //       0x0f81ae6945026025546c75a2a5240311d8ab75fac730cbcacd117de46c663f3fdebb76c445078281bf953ed363fa069bn
    //     )
    //   )
    // ).toBe(true);
    let a = new Fp2([
      0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
      0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
    ]);
    a = a.frobeniusMap(0);
    expect(
      a.equals(
        new Fp2([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
        ])
      )
    ).toBe(true);
    a = a.frobeniusMap(1);
    expect(
      a.equals(
        new Fp2([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x18d400b280d93e62fcd559cbe77bd8b8b07e9bc405608611a9109e8f3041427e8a411ad149045812228109103250c9d0n,
        ])
      )
    ).toBe(true);
    a = a.frobeniusMap(1);
    expect(
      a.equals(
        new Fp2([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
        ])
      )
    ).toBe(true);
    a = a.frobeniusMap(2);
    expect(
      a.equals(
        new Fp2([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
        ])
      )
    ).toBe(true);
  });
});
