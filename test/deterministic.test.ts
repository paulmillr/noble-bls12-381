import * as bls from '..';
import { deepStrictEqual } from 'assert';
import zkVectors from './zkcrypto/converted.json';
import pairingVectors from './go_pairing_vectors/pairing.json';

describe('Killic based', () => {
  // NOTE: Killic returns all items in reversed order, which looks strange:
  // instead of `Fp2(${this.c0} + ${this.c1}×i)`; it returns `Fp2(${this.c0}×i + ${this.c1})`;
  const killicHex = (lst: string[]) =>
    Array.from(lst)
      .reverse()
      .reduce((acc, i) => acc + i);

  it('Pairing', () => {
    const t = bls.pairing(bls.PointG1.BASE, bls.PointG2.BASE);
    deepStrictEqual(
      bls.utils.bytesToHex(t.toBytes()),
      killicHex([
        '0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631',
        '04c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef',
        '03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a2',
        '11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57',
        '06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a',
        '19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d',
        '018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b6',
        '01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5',
        '193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f',
        '1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87',
        '089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f',
        '1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6',
      ])
    );
  });
  it('Pairing (big)', () => {
    let p1 = bls.PointG1.BASE;
    let p2 = bls.PointG2.BASE;
    for (let v of pairingVectors) {
      deepStrictEqual(
        bls.utils.bytesToHex(bls.pairing(p1, p2).toBytes()),
        // Reverse order
        v.match(/.{96}/g)!.reverse().join('')
      );
      p1 = p1.add(bls.PointG1.BASE);
      p2 = p2.add(bls.PointG2.BASE);
    }
  });
});

describe('zkcrypto', () => {
  it(`G1/compressed`, () => {
    let p1 = bls.PointG1.ZERO;
    for (let i = 0; i < zkVectors.G1_Compressed.length; i++) {
      const t = zkVectors.G1_Compressed[i];
      const P = bls.PointG1.fromHex(t);
      deepStrictEqual(P.toHex(true), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(true), t);
      p1 = p1.add(bls.PointG1.BASE);
      if (i) {
        deepStrictEqual(bls.PointG1.BASE.multiply(BigInt(i)).toHex(true), t);
        deepStrictEqual(bls.PointG1.BASE.multiplyUnsafe(BigInt(i)).toHex(true), t);
        deepStrictEqual(bls.PointG1.BASE.multiplyPrecomputed(BigInt(i)).toHex(true), t);
      }
    }
  });
  it(`G1/uncompressed`, () => {
    let p1 = bls.PointG1.ZERO;
    for (let i = 0; i < zkVectors.G1_Uncompressed.length; i++) {
      const t = zkVectors.G1_Uncompressed[i];
      const P = bls.PointG1.fromHex(t);
      deepStrictEqual(P.toHex(), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(), t);
      p1 = p1.add(bls.PointG1.BASE);
      if (i) {
        deepStrictEqual(bls.PointG1.BASE.multiply(BigInt(i)).toHex(), t);
        deepStrictEqual(bls.PointG1.BASE.multiplyUnsafe(BigInt(i)).toHex(), t);
        deepStrictEqual(bls.PointG1.BASE.multiplyPrecomputed(BigInt(i)).toHex(), t);
      }
    }
  });
  it(`G2/compressed`, () => {
    let p1 = bls.PointG2.ZERO;
    for (let i = 0; i < zkVectors.G2_Compressed.length; i++) {
      const t = zkVectors.G2_Compressed[i];
      const P = bls.PointG2.fromHex(t);
      deepStrictEqual(P.toHex(true), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(true), t);
      p1 = p1.add(bls.PointG2.BASE);
      if (i) {
        deepStrictEqual(bls.PointG2.BASE.multiply(BigInt(i)).toHex(true), t);
        deepStrictEqual(bls.PointG2.BASE.multiplyUnsafe(BigInt(i)).toHex(true), t);
        deepStrictEqual(bls.PointG2.BASE.multiplyPrecomputed(BigInt(i)).toHex(true), t);
      }
    }
  });
  it(`G2/uncompressed`, () => {
    let p1 = bls.PointG2.ZERO;
    for (let i = 0; i < zkVectors.G2_Uncompressed.length; i++) {
      const t = zkVectors.G2_Uncompressed[i];
      const P = bls.PointG2.fromHex(t);
      deepStrictEqual(P.toHex(), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(), t);
      p1 = p1.add(bls.PointG2.BASE);
      if (i) {
        deepStrictEqual(bls.PointG2.BASE.multiply(BigInt(i)).toHex(), t);
        deepStrictEqual(bls.PointG2.BASE.multiplyUnsafe(BigInt(i)).toHex(), t);
        deepStrictEqual(bls.PointG2.BASE.multiplyPrecomputed(BigInt(i)).toHex(), t);
      }
    }
  });
});
