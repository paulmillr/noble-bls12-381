import * as fc from "fast-check";
import * as bls from "..";
import { readFileSync } from 'fs';
import { join } from 'path';
const G2_VECTORS = readFileSync(join(__dirname, './bls12-381-g2-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n').map(l => l.split(':'));

// @ts-ignore
const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

// @ts-ignore
const CURVE_ORDER = bls.CURVE.r;

function toHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

describe("bls12-381", () => {
  bls.PointG1.BASE.clearMultiplyPrecomputes();
  bls.PointG1.BASE.calcMultiplyPrecomputes(8);

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
      expect(toHex(sig)).toEqual(expected);
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
              messages,
              publicKey,
              aggregatedSignature
            )
          ).toBe(true);
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should verify multi-signaturez", async () => {
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
              wrongMessages,
              publicKey,
              aggregatedSignature

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
