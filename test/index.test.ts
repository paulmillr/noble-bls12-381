import * as fc from "fast-check";
import * as bls from "..";
import { readFileSync } from 'fs';
import { join } from 'path';
const G2_VECTORS = readFileSync(join(__dirname, 'bls12-381-g2-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n')
  .map(l => l.split(':'));

// @ts-ignore
const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

// @ts-ignore
const CURVE_ORDER = bls.CURVE.r;

describe("bls12-381", () => {
  bls.PointG1.BASE.clearMultiplyPrecomputes();
  bls.PointG1.BASE.calcMultiplyPrecomputes(8);

  it("should get uncompressed form of point G1", () => {
    // Test Zero
    {
      expect(bls.PointG1.ZERO.toUncompressedHex()).toEqual(new Uint8Array([64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
    // Test Non-Zero
    {
      const x = new bls.Fq(BigInt("0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"));
      const y = new bls.Fq(BigInt("0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"));
      const g1 = new bls.PointG1(x, y, bls.Fq.ONE);
      expect(g1.toUncompressedHex()).toEqual(new Uint8Array([23, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 8, 179, 244, 129, 227, 170, 160, 241, 160, 158, 48, 237, 116, 29, 138, 228, 252, 245, 224, 149, 213, 208, 10, 246, 0, 219, 24, 203, 44, 4, 179, 237, 208, 60, 199, 68, 162, 136, 138, 228, 12, 170, 35, 41, 70, 197, 231, 225]));
    }
  });

  it("should get uncompressed form of point G2", () => {
    // Test Zero
    {
      expect(bls.PointG2.ZERO.toUncompressedHex()).toEqual(new Uint8Array([64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
    // Test Non-Zero
    {
      const x = new bls.Fq2([
        BigInt("0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
        BigInt("0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")
      ]);
      const y = new bls.Fq2([
        BigInt("0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
        BigInt("0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")
      ]);
      const g2 = new bls.PointG2(x, y, bls.Fq2.ONE);
      expect(g2.toUncompressedHex()).toEqual(new Uint8Array([19, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184, 6, 6, 196, 160, 46, 167, 52, 204, 50, 172, 210, 176, 43, 194, 139, 153, 203, 62, 40, 126, 133, 167, 99, 175, 38, 116, 146, 171, 87, 46, 153, 171, 63, 55, 13, 39, 92, 236, 29, 161, 170, 169, 7, 95, 240, 95, 121, 190, 12, 229, 213, 39, 114, 125, 110, 17, 140, 201, 205, 198, 218, 46, 53, 26, 173, 253, 155, 170, 140, 189, 211, 167, 109, 66, 154, 105, 81, 96, 209, 44, 146, 58, 201, 204, 59, 172, 162, 137, 225, 147, 84, 134, 8, 184, 40, 1]));
    }
  });

  it("should compress and decompress G1 points", async () => {
    const priv = bls.PointG1.fromPrivateKey(42n);
    const publicKey = priv.toCompressedHex();
    const decomp = bls.PointG1.fromCompressedHex(publicKey);
    expect(publicKey).toEqual(decomp.toCompressedHex());
  });
  it("should not compress and decompress zero G1 point", async () => {
    expect(() => bls.PointG1.fromPrivateKey(0n)).toThrowError();
  });
  it(`should produce correct signatures (${G2_VECTORS.length} vectors)`, async () => {
    for (let i = 0; i < G2_VECTORS.length; i++) {
      const [priv, msg, expected] = G2_VECTORS[i];
      const sig = await bls.sign(msg, priv);
      expect(sig).toEqual(expected);
    }
  });
  it("should verify signed message", async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = await bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = await bls.verify(sig, msg, pub);
      expect(res).toBeTruthy()
    }
  });
  it("should not verify signature with wrong message", async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const invMsg = G2_VECTORS[i + 1][1];
      const sig = await bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = await bls.verify(sig, invMsg, pub);
      expect(res).toBeFalsy();
    }
  });
  it("should not verify signature with wrong key", async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = await bls.sign(msg, priv);
      const invPub = bls.getPublicKey(G2_VECTORS[i + 1][1]);
      const res = await bls.verify(sig, msg, invPub);
      expect(res).toBeFalsy();
    }
  });
  it("should verify multi-signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, privateKeys) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          const publicKey = privateKeys.map(bls.getPublicKey);
          const signatures = await Promise.all(
            messages.map((message, i) =>
              bls.sign(message, privateKeys[i])
            )
          );
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(
            await bls.verifyBatch(
              aggregatedSignature,
              messages,
              publicKey
            )
          ).toBe(true);
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should batch verify multi-signatures", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, wrongMessages, privateKeys) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          wrongMessages = messages.map((a, i) =>
            typeof wrongMessages[i] === "undefined" ? a : wrongMessages[i]
          );
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            messages.map((message, i) =>
              bls.sign(message, privateKeys[i])
            )
          );
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(
            await bls.verifyBatch(
              aggregatedSignature,
              wrongMessages,
              publicKey

            )
          ).toBe(messages.every((m, i) => m === wrongMessages[i]));
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  // it("should not verify multi-signature with wrong public keys", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.array(fc.hexa(), 1, 100),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (messages, privateKeys, wrongPrivateKeys) => {
  //         privateKeys = privateKeys.slice(0, messages.length);
  //         wrongPrivateKeys = privateKeys.map((a, i) =>
  //           wrongPrivateKeys[i] !== undefined ? wrongPrivateKeys[i] : a
  //         );
  //         messages = messages.slice(0, privateKeys.length);
  //         const wrongPublicKeys = await Promise.all(
  //           wrongPrivateKeys.map(bls.getPublicKey)
  //         );
  //         const signatures = await Promise.all(
  //           messages.map((message, i) =>
  //             bls.sign(message, privateKeys[i])
  //           )
  //         );
  //         const aggregatedSignature = await bls.aggregateSignatures(signatures);
  //         expect(
  //           await bls.verifyBatch(
  //             messages,
  //             wrongPublicKeys,
  //             aggregatedSignature

  //           )
  //         ).toBe(wrongPrivateKeys.every((p, i) => p === privateKeys[i]));
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should verify multi-signature as simple signature", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.hexa(),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (message, privateKeys) => {
  //         const publicKey = await Promise.all(
  //           privateKeys.map(bls.getPublicKey)
  //         );
  //         const signatures = await Promise.all(
  //           privateKeys.map((privateKey) =>
  //             bls.sign(message, privateKey)
  //           )
  //         );
  //         const aggregatedSignature = await bls.aggregateSignatures(signatures);
  //         const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
  //         expect(
  //           await bls.verify(
  //             message,
  //             aggregatedPublicKey,
  //             aggregatedSignature
  //           )
  //         ).toBe(true);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should not verify multi-signature as simple signature", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.hexa(),
  //       fc.hexa(),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (message, wrongMessage, privateKeys) => {
  //         const publicKey = await Promise.all(
  //           privateKeys.map(bls.getPublicKey)
  //         );
  //         const signatures = await Promise.all(
  //           privateKeys.map((privateKey) =>
  //             bls.sign(message, privateKey)
  //           )
  //         );
  //         const aggregatedSignature = await bls.aggregateSignatures(signatures);
  //         const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
  //         expect(
  //           await bls.verify(
  //             wrongMessage,
  //             aggregatedPublicKey,
  //             aggregatedSignature

  //           )
  //         ).toBe(message === wrongMessage);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
});
