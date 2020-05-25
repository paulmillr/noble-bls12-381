//import * as fc from "fast-check";
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

function toHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

describe("bls12-381", () => {
  it('test', () => {expect(1).toBe(1)})
  // it("should create different signatures for different domains", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.hexa(),
  //       fc.bigInt(1n, CURVE_ORDER),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (message, privateKey) => {
  //         const [publicKey, signature1, signature2] = await Promise.all([
  //           bls.getPublicKey(privateKey),
  //           bls.sign(message, privateKey),
  //           bls.sign(message, privateKey)
  //         ]);
  //         expect(publicKey.length).toBe(48);
  //         expect(signature1.length).toBe(96);
  //         expect(signature2.length).toBe(96);
  //         if (domain !== otherDomain) {
  //           expect(signature1).not.toEqual(signature2);
  //         } else {
  //           expect(signature1).toEqual(signature2);
  //         }
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should create same aggregated public key if order of arguments will be changed", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 2, 200),
  //       async privateKeys => {
  //         const pubkeys = await Promise.all(
  //           privateKeys.map(privateKey => bls.getPublicKey(privateKey))
  //         );
  //         const [
  //           aggregatedPublicKey1,
  //           aggregatedPublicKey2
  //         ] = await Promise.all([
  //           bls.aggregatePublicKeys(pubkeys),
  //           bls.aggregatePublicKeys([...pubkeys].reverse())
  //         ]);
  //         expect(aggregatedPublicKey1).toEqual(aggregatedPublicKey2);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should create same aggregated signature if order of arguments will be changed", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.array(fc.hexa(), 2, 200),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 2, 200),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (messages, privateKeys) => {
  //         const signatures = await Promise.all(
  //           privateKeys.map((privateKey, i) =>
  //             bls.sign(messages[i] || "0", privateKey)
  //           )
  //         );
  //         const [
  //           aggregatedSignature1,
  //           aggregatedSignature2
  //         ] = await Promise.all([
  //           bls.aggregateSignatures(signatures),
  //           bls.aggregateSignatures([...signatures].reverse())
  //         ]);
  //         expect(aggregatedSignature1).toEqual(aggregatedSignature2);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  it("should compress and decompress G1 points", async () => {
    const priv = bls.PointG1.fromPrivateKey(42n);
    const publicKey = priv.toCompressedHex();
    const decomp = new bls.PointG1(bls.PointG1.fromCompressedHex(publicKey));
    expect(publicKey).toEqual(decomp.toCompressedHex());
  });
  it.skip("should produce correct signatures (550 vectors)", async () => {
    for (const [priv, msg, expected] of G2_VECTORS) {
      const sig = await bls.sign(msg, priv);
      //console.log('index', i++);
      expect(toHex(sig)).toEqual(expected);
    }
  });
  it("should verify signed message", async () => {
    for (const [priv, msg] of G2_VECTORS.slice(0, 25)) {
      const sig = await bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = await bls.verify(sig, msg, pub);
      expect(res).toBeTruthy()
    }
  });
  // it("should verify just signed message", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.hexaString(1, 96),
  //       fc.bigInt(2n, CURVE_ORDER),
  //       async (message, privateKey) => {
  //         const publicKey = await bls.getPublicKey(privateKey);
  //         const signature = await bls.sign(message, privateKey);
  //         expect(publicKey.length).toBe(48);
  //         expect(signature.length).toBe(96);
  //         expect(await bls.verify(message, publicKey, signature)).toBe(
  //           true
  //         );
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should not verify signature with wrong message", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.hexa(),
  //       fc.hexa(),
  //       fc.bigInt(1n, CURVE_ORDER),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (message, wrongMessage, privateKey) => {
  //         const publicKey = await bls.getPublicKey(privateKey);
  //         const signature = await bls.sign(message, privateKey);
  //         expect(publicKey.length).toBe(48);
  //         expect(signature.length).toBe(96);
  //         expect(
  //           await bls.verify(wrongMessage, publicKey, signature)
  //         ).toBe(message === wrongMessage);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should verify multi-signature", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.array(fc.hexa(), 1, 100),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (messages, privateKeys) => {
  //         privateKeys = privateKeys.slice(0, messages.length);
  //         messages = messages.slice(0, privateKeys.length);
  //         const publicKey = await Promise.all(
  //           privateKeys.map(bls.getPublicKey)
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
  //             publicKey,
  //             aggregatedSignature
  //           )
  //         ).toBe(true);
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
  // it("should verify multi-signaturez", async () => {
  //   await fc.assert(
  //     fc.asyncProperty(
  //       fc.array(fc.hexa(), 1, 100),
  //       fc.array(fc.hexa(), 1, 100),
  //       fc.array(fc.bigInt(1n, CURVE_ORDER), 1, 100),
  //       fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
  //       async (messages, wrongMessages, privateKeys) => {
  //         privateKeys = privateKeys.slice(0, messages.length);
  //         messages = messages.slice(0, privateKeys.length);
  //         wrongMessages = messages.map((a, i) =>
  //           typeof wrongMessages[i] === "undefined" ? a : wrongMessages[i]
  //         );
  //         const publicKey = await Promise.all(
  //           privateKeys.map(bls.getPublicKey)
  //         );
  //         const signatures = await Promise.all(
  //           messages.map((message, i) =>
  //             bls.sign(message, privateKeys[i])
  //           )
  //         );
  //         const aggregatedSignature = await bls.aggregateSignatures(signatures);
  //         expect(
  //           await bls.verifyBatch(
  //             wrongMessages,
  //             publicKey,
  //             aggregatedSignature

  //           )
  //         ).toBe(messages.every((m, i) => m === wrongMessages[i]));
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });
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
  // it("should create negative G1 pairing", () => {
	// 	const p1 = bls.pairing(bls.G2, bls.G1);
	// 	const p2 = bls.pairing(bls.G2, bls.G1.negative());
	// 	expect(p1.multiply(p2)).toEqual(p1.one);
  // });
  // it("should create negative G2 pairing", () => {
	// 	const p2 = bls.pairing(bls.G2, bls.G1.negative());
	// 	const p3 = bls.pairing(bls.G2.negative(), bls.G1);
	// 	expect(p2).toEqual(p3);
  // });
  // it("should create right pairing output order", () => {
	// 	const p1 = bls.pairing(bls.G2, bls.G1);
	// 	const p2 = p1.pow(CURVE_ORDER);
	// 	expect(p2).toEqual(p1.one);
  // });
  // it("should create right pairing with bilinearity on G1", () => {
	// 	const p1 = bls.pairing(bls.G2, bls.G1);
	// 	const p2 = bls.pairing(bls.G2, bls.G1.multiply(2n));
	// 	expect(p1.multiply(p1)).toEqual(p2);
  // });
  // it("pairing should not be degenerate", () => {
	// 	const p1 = bls.pairing(bls.G2, bls.G1);
	// 	const p2 = bls.pairing(bls.G2, bls.G1.multiply(2n));
	// 	const p3 = bls.pairing(bls.G2.negative(), bls.G1);
	// 	expect(p1).not.toEqual(p2);
	// 	expect(p1).not.toEqual(p3);
	// 	expect(p2).not.toEqual(p3);
  // });
  // it("should create right pairing with bilinearity on G2", () => {
	// 	const p1 = bls.pairing(bls.G2, bls.G1);
	// 	const p2 = bls.pairing(bls.G2.multiply(2n), bls.G1);
	// 	expect(p1.multiply(p1)).toEqual(p2);
  // });
  // it("should create right pairing composite check", () => {
	// 	const p1 = bls.pairing(bls.G2.multiply(27n), bls.G1.multiply(37n));
	// 	const p2 = bls.pairing(bls.G2, bls.G1.multiply(999n));
	// 	expect(p1).toEqual(p2);
  // });
});
