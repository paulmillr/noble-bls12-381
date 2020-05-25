import * as fc from "fast-check";
import * as bls from "..";
import {readFileSync} from 'fs';
import {join} from 'path';
const G2_VECTORS = readFileSync(join(__dirname, './bls12-381-g2-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n').map(l => l.split(':'));

// @ts-ignore
const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

// @ts-ignore
const CURVE_ORDER = bls.CURVE.r;
const G1 = bls.PointG1.BASE;
const G2 = bls.PointG2.BASE;

function toHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

describe("bls12-381", () => {
  it("should compress and decompress G1 points", async () => {
    const priv = bls.PointG1.fromPrivateKey(42n);
    const publicKey = priv.toCompressedHex();
    const decomp = new bls.PointG1(bls.PointG1.fromCompressedHex(publicKey));
    expect(publicKey).toEqual(decomp.toCompressedHex());
  });
  // it("should compress and decompress G2 points", async () => {
  //   const priv = bls.PointG2.fromPrivateKey(42n);
  //   const publicKey = priv.toCompressedHex();
  //   const decomp = new bls.PointG1(bls.PointG1.fromCompressedHex(publicKey));
  //   expect(publicKey).toEqual(decomp.toCompressedHex());
  // });
  it.only(`should produce correct signatures (${G2_VECTORS.length} vectors)`, async () => {
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
  // it.only("should create negative G1 pairing", () => {
	// 	const p1 = bls.pairing(bls.PointG1.BASE, bls.PointG2.BASE);
	// 	const p2 = bls.pairing(bls.PointG1.BASE.negate(), bls.PointG2.BASE);
	// 	expect(p1.multiply(p2)).toEqual(bls.Fq12.ONE);
  // });
  // it("should create negative G2 pairing", () => {
	// 	const p2 = bls.pairing(bls.G2, bls.G1.negative());
	// 	const p3 = bls.pairing(bls.G2.negative(), bls.G1);
	// 	expect(p2).toEqual(p3);
  // });
  // it.only("should create proper pairing output order", () => {
	// 	const p1 = bls.pairing(G1, G2);
	// 	const p2 = p1.pow(CURVE_ORDER);
	// 	expect(p2).toEqual(bls.Fq12.ONE);
  // });
  it("should create right pairing with bilinearity on G1", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1.multiply(2n), G2);
		expect(p1.multiply(p1)).toEqual(p2);
  });
  it("pairing should not degenerate", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1.multiply(2n), G2);
		const p3 = bls.pairing(G1, G2.negate());
		expect(p1).not.toEqual(p2);
		expect(p1).not.toEqual(p3);
		expect(p2).not.toEqual(p3);
  });
  // it("should create right pairing with bilinearity on G2", () => {
	// 	const p1 = bls.pairing(G1, G2);
	// 	const p2 = bls.pairing(G1, G2.multiply(2n));
	// 	expect(p1.multiply(p1)).toEqual(p2);
  // });
  // it("should create right pairing composite check", () => {
	// 	const p1 = bls.pairing(G1.multiply(37n), G2.multiply(27n));
	// 	const p2 = bls.pairing(G1.multiply(999n), G2);
	// 	expect(p1).toEqual(p2);
  // });
});
