import * as fc from 'fast-check';
import * as bls from '..';
import { readFileSync } from 'fs';
import { join } from 'path';
const G2_VECTORS = readFileSync(join(__dirname, 'bls12-381-g2-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n')
  .map((l) => l.split(':'));
// Vectors come from
// https://github.com/zkcrypto/bls12_381/blob/e501265cd36849a4981fe55e10dc87c38ee2213d/src/hash_to_curve/map_scalar.rs#L20
const SCALAR_VECTORS = readFileSync(join(__dirname, 'bls12-381-scalar-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n')
  .map((l) => l.split(':'));

// @ts-ignore
const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });

// @ts-ignore
const CURVE_ORDER = bls.CURVE.r;

const FC_MSG = fc.hexaString(64, 64);
const FC_MSG_5 = fc.array(FC_MSG, 5, 5);
const FC_BIGINT = fc.bigInt(1n, CURVE_ORDER - 1n);
const FC_BIGINT_5 = fc.array(FC_BIGINT, 5, 5);
const B_192_40 = '40'.padEnd(192, '0');
const B_384_40 = '40'.padEnd(384, '0'); // [0x40, 0, 0...]

const getPubKey = (priv: any) => bls.getPublicKey(priv)

describe('bls12-381', () => {
  // bls.PointG1.BASE.clearMultiplyPrecomputes();
  // bls.PointG1.BASE.calcMultiplyPrecomputes(4);

  it('should construct point G1 from its uncompressed form (Raw Bytes)', () => {
    // Test Zero
    const g1 = bls.PointG1.fromHex(B_192_40);
    expect(g1.x).toEqual(bls.PointG1.ZERO.x);
    expect(g1.y).toEqual(bls.PointG1.ZERO.y);
    // Test Non-Zero
    const x = new bls.Fp(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = new bls.Fp(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = bls.PointG1.fromHex(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );

    expect(g1_.x).toEqual(x);
    expect(g1_.y).toEqual(y);
  });

  it('should construct point G1 from its uncompressed form (Hex)', () => {
    // Test Zero
    const g1 = bls.PointG1.fromHex(B_192_40);

    expect(g1.x).toEqual(bls.PointG1.ZERO.x);
    expect(g1.y).toEqual(bls.PointG1.ZERO.y);
    // Test Non-Zero
    const x = new bls.Fp(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = new bls.Fp(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = bls.PointG1.fromHex(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );

    expect(g1_.x).toEqual(x);
    expect(g1_.y).toEqual(y);
  });

  it('should construct point G2 from its uncompressed form (Raw Bytes)', () => {
    // Test Zero
    const g2 = bls.PointG2.fromHex(B_384_40);
    expect(g2.x).toEqual(bls.PointG2.ZERO.x);
    expect(g2.y).toEqual(bls.PointG2.ZERO.y);
    // Test Non-Zero
    const x = new bls.Fp2([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = new bls.Fp2([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);

    const g2_ = bls.PointG2.fromHex(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );

    expect(g2_.x).toEqual(x);
    expect(g2_.y).toEqual(y);
  });

  it('should construct point G2 from its uncompressed form (Hex)', () => {
    // Test Zero
    const g2 = bls.PointG2.fromHex(B_384_40);

    expect(g2.x).toEqual(bls.PointG2.ZERO.x);
    expect(g2.y).toEqual(bls.PointG2.ZERO.y);
    // Test Non-Zero
    const x = new bls.Fp2([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = new bls.Fp2([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);

    const g2_ = bls.PointG2.fromHex(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );

    expect(g2_.x).toEqual(x);
    expect(g2_.y).toEqual(y);
  });

  it('should get uncompressed form of point G1 (Raw Bytes)', () => {
    // Test Zero
    expect(bls.PointG1.ZERO.toHex(false)).toEqual(B_192_40);
    // Test Non-Zero
    const x = new bls.Fp(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = new bls.Fp(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = new bls.PointG1(x, y, bls.Fp.ONE);
    expect(g1.toHex(false)).toEqual(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  it('should get uncompressed form of point G1 (Hex)', () => {
    // Test Zero
    expect(bls.PointG1.ZERO.toHex(false)).toEqual(B_192_40);
    // Test Non-Zero
    const x = new bls.Fp(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = new bls.Fp(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = new bls.PointG1(x, y, bls.Fp.ONE);
    expect(g1.toHex(false)).toEqual(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  it('should get uncompressed form of point G2 (Raw Bytes)', () => {
    // Test Zero
    expect(bls.PointG2.ZERO.toHex(false)).toEqual(B_384_40);
    // Test Non-Zero
    const x = new bls.Fp2([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = new bls.Fp2([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);
    const g2 = new bls.PointG2(x, y, bls.Fp2.ONE);
    expect(g2.toHex(false)).toEqual(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  it('should get uncompressed form of point G2 (Hex)', () => {
    // Test Zero
    expect(bls.PointG2.ZERO.toHex(false)).toEqual(B_384_40);

    // Test Non-Zero
    const x = new bls.Fp2([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = new bls.Fp2([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);
    const g2 = new bls.PointG2(x, y, bls.Fp2.ONE);
    expect(g2.toHex(false)).toEqual(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  it('should compress and decompress G1 points', async () => {
    const priv = bls.PointG1.fromPrivateKey(42n);
    const publicKey = priv.toHex(true);
    const decomp = bls.PointG1.fromHex(publicKey);
    expect(publicKey).toEqual(decomp.toHex(true));
  });
  it('should not compress and decompress zero G1 point', async () => {
    expect(() => bls.PointG1.fromPrivateKey(0n)).toThrowError();
  });
  const VALID_G1 = new bls.PointG1(
    new bls.Fp(
      3609742242174788176010452839163620388872641749536604986743596621604118973777515189035770461528205168143692110933639n
    ),
    new bls.Fp(
      1619277690257184054444116778047375363103842303863153349133480657158810226683757397206929105479676799650932070320089n
    )
  );
  const VALID_G1_2 = new bls.PointG1(
    new bls.Fp(
      1206972466279728255044019580914616126536509750250979180256809997983196363639429409634110400978470384566664128085207n
    ),
    new bls.Fp(
      2991142246317096160788653339959532007292638191110818490939476869616372888657136539642598243964263069435065725313423n
    )
  );
  const INVALID_G1 = new bls.PointG1(new bls.Fp(0n), new bls.Fp(0n));
  it('should aggregate pubkeys', async () => {
    bls.aggregatePublicKeys([VALID_G1, VALID_G1_2]);
  });
  it('should not aggregate invalid pubkeys', async () => {
    expect(() => bls.aggregatePublicKeys([VALID_G1, INVALID_G1])).toThrowError();
  });
  // should aggregate signatures

  it(`should produce correct signatures (${G2_VECTORS.length} vectors)`, async () => {
    for (let vector of G2_VECTORS) {
      const [priv, msg, expected] = vector;
      const sig = await bls.sign(msg, priv);
      expect(bls.utils.bytesToHex(sig)).toEqual(expected);
    }
  });
  it(`should produce correct scalars (${SCALAR_VECTORS.length} vectors)`, async () => {
    const options = {
        p: bls.CURVE.r,
        m: 1,
        expand: false,
    };
    for (let vector of SCALAR_VECTORS) {
      const [okmAscii, expectedHex] = vector;
      const expected = BigInt("0x" + expectedHex);
      const okm = new Uint8Array(okmAscii.split("").map(c => c.charCodeAt(0)));
      const scalars = await bls.utils.hashToField(okm, 1, options);
      expect(scalars[0][0]).toEqual(expected);
    }
  });
  it('should verify signed message', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = await bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = await bls.verify(sig, msg, pub);
      expect(res).toBeTruthy();
    }
  });
  it('should not verify signature with wrong message', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const invMsg = G2_VECTORS[i + 1][1];
      const sig = await bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = await bls.verify(sig, invMsg, pub);
      expect(res).toBeFalsy();
    }
  });
  it('should not verify signature with wrong key', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = await bls.sign(msg, priv);
      const invPriv = G2_VECTORS[i + 1][1].padStart(64, '0');
      const invPub = bls.getPublicKey(invPriv);
      const res = await bls.verify(sig, msg, invPub);
      expect(res).toBeFalsy();
    }
  });
  it('should verify multi-signature', async () => {
    await fc.assert(
      fc.asyncProperty(FC_MSG_5, FC_BIGINT_5, async (messages, privateKeys) => {
        privateKeys = privateKeys.slice(0, messages.length);
        messages = messages.slice(0, privateKeys.length);
        const publicKey = privateKeys.map(getPubKey);
        const signatures = await Promise.all(
          messages.map((message, i) => bls.sign(message, privateKeys[i]))
        );
        const aggregatedSignature = await bls.aggregateSignatures(signatures);
        expect(await bls.verifyBatch(aggregatedSignature, messages, publicKey)).toBe(true);
      })
    );
  });
  it('should batch verify multi-signatures', async () => {
    await fc.assert(
      fc.asyncProperty(
        FC_MSG_5,
        FC_MSG_5,
        FC_BIGINT_5,
        async (messages, wrongMessages, privateKeys) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          wrongMessages = messages.map((a, i) =>
            typeof wrongMessages[i] === 'undefined' ? a : wrongMessages[i]
          );
          const publicKey = await Promise.all(privateKeys.map(getPubKey));
          const signatures = await Promise.all(
            messages.map((message, i) => bls.sign(message, privateKeys[i]))
          );
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(await bls.verifyBatch(aggregatedSignature, wrongMessages, publicKey)).toBe(
            messages.every((m, i) => m === wrongMessages[i])
          );
        }
      )
    );
  });
  it('should not verify multi-signature with wrong public keys', async () => {
    await fc.assert(
      fc.asyncProperty(
        FC_MSG_5,
        FC_BIGINT_5,
        FC_BIGINT_5,
        async (messages, privateKeys, wrongPrivateKeys) => {
          privateKeys = privateKeys.slice(0, messages.length);
          wrongPrivateKeys = privateKeys.map((a, i) =>
            wrongPrivateKeys[i] !== undefined ? wrongPrivateKeys[i] : a
          );
          messages = messages.slice(0, privateKeys.length);
          const wrongPublicKeys = await Promise.all(wrongPrivateKeys.map(getPubKey));
          const signatures = await Promise.all(
            messages.map((message, i) => bls.sign(message, privateKeys[i]))
          );
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(await bls.verifyBatch(aggregatedSignature, messages, wrongPublicKeys)).toBe(
            wrongPrivateKeys.every((p, i) => p === privateKeys[i])
          );
        }
      )
    );
  });
  it('should verify multi-signature as simple signature', async () => {
    await fc.assert(
      fc.asyncProperty(FC_MSG, FC_BIGINT_5, async (message, privateKeys) => {
        const publicKey = (await Promise.all(privateKeys.map(getPubKey)));
        const signatures = await Promise.all(
          privateKeys.map((privateKey) => bls.sign(message, privateKey))
        );
        const aggregatedSignature = await bls.aggregateSignatures(signatures);
        const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
        expect(await bls.verify(aggregatedSignature, message, aggregatedPublicKey)).toBe(true);
      })
    );
  });
  it('should not verify wrong multi-signature as simple signature', async () => {
    await fc.assert(
      fc.asyncProperty(FC_MSG, FC_MSG, FC_BIGINT_5, async (message, wrongMessage, privateKeys) => {
        const publicKey = (await Promise.all(privateKeys.map(getPubKey)));
        const signatures = await Promise.all(
          privateKeys.map((privateKey) => bls.sign(message, privateKey))
        );
        const aggregatedSignature = await bls.aggregateSignatures(signatures);
        const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
        expect(await bls.verify(aggregatedSignature, wrongMessage, aggregatedPublicKey)).toBe(
          message === wrongMessage
        );
      })
    );
  });
});
