import * as fc from "fast-check";
import * as bls from "./src/index";

const NUM_RUMS = 100; // reduce to 1 to shorten test time

describe("bls12-381", () => {
  it("should verify just signed message", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.bigInt(1n, bls.PRIME_ORDER),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, privateKey, domain) => {
          const publicKey = await bls.getPublicKey(privateKey);
          const signature = await bls.sign(message, privateKey, domain);
          expect(publicKey.length).toBe(48);
          expect(signature.length).toBe(96);
          expect(await bls.verify(message, publicKey, signature, domain)).toBe(
            true
          );
        }
      )
    , {numRuns: NUM_RUMS});
  });
  it("should not verify signature with wrong message", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.hexa(),
        fc.bigInt(1n, bls.PRIME_ORDER),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, wrongMessage, privateKey, domain) => {
          const publicKey = await bls.getPublicKey(privateKey);
          const signature = await bls.sign(message, privateKey, domain);
          expect(publicKey.length).toBe(48);
          expect(signature.length).toBe(96);
          expect(
            await bls.verify(wrongMessage, publicKey, signature, domain)
          ).toBe(message === wrongMessage);
        }
      )
     , {numRuns: NUM_RUMS});
  });
  it("should verify multi-signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, privateKeys, domain) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          const publicKey = await Promise.all(privateKeys.map(bls.getPublicKey));
          const signatures = await Promise.all(messages.map((message, i) =>
            bls.sign(message, privateKeys[i], domain)
          ));
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(
            await bls.verifyMultiple(
              messages,
              publicKey,
              aggregatedSignature,
              domain
            )
          ).toBe(true);
        }
      )
    , {numRuns: NUM_RUMS});
  });
  it("should verify multi-signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, wrongMessages, privateKeys, domain) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          wrongMessages = messages.map((a, i) =>
            typeof wrongMessages[i] === "undefined" ? a : wrongMessages[i]
          );
          const publicKey = await Promise.all(privateKeys.map(bls.getPublicKey));
          const signatures = await Promise.all(messages.map((message, i) =>
            bls.sign(message, privateKeys[i], domain)
          ));
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(
            await bls.verifyMultiple(
              wrongMessages,
              publicKey,
              aggregatedSignature,
              domain
            )
          ).toBe(messages.every((m, i) => m === wrongMessages[i]));
        }
      )
    , {numRuns: NUM_RUMS});
  });
  it("should not verify multi-signature with wrong public keys", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 1, 100),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, privateKeys, wrongPrivateKeys, domain) => {
          privateKeys = privateKeys.slice(0, messages.length);
          wrongPrivateKeys = privateKeys.map((a, i) =>
            wrongPrivateKeys[i] !== undefined ? wrongPrivateKeys[i] : a
          );
          messages = messages.slice(0, privateKeys.length);
          const publicKey = await Promise.all(privateKeys.map(bls.getPublicKey));
          const wrongPublicKeys = await Promise.all(wrongPrivateKeys.map(bls.getPublicKey));
          const signatures = await Promise.all(messages.map((message, i) =>
            bls.sign(message, privateKeys[i], domain)
          ));
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          expect(
            await bls.verifyMultiple(
              messages,
              wrongPublicKeys,
              aggregatedSignature,
              domain
            )
          ).toBe(wrongPrivateKeys.every((p, i) => p === privateKeys[i]));
        }
      )
    , {numRuns: NUM_RUMS});
  });
  it("should verify multi-signature as simple signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, privateKeys, domain) => {
          const publicKey = await Promise.all(privateKeys.map(bls.getPublicKey));
          const signatures = await Promise.all(privateKeys.map((privateKey, i) =>
            bls.sign(message, privateKey, domain)
          ));
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
          expect(
            await bls.verify(
              message,
              aggregatedPublicKey,
              aggregatedSignature,
              domain
            )
          ).toBe(true);
        }
      )
    , {numRuns: NUM_RUMS});
  });
  it("should not verify multi-signature as simple signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.hexa(),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, wrongMessage, privateKeys, domain) => {
          const publicKey = await Promise.all(privateKeys.map(bls.getPublicKey));
          const signatures = await Promise.all(privateKeys.map((privateKey, i) =>
            bls.sign(message, privateKey, domain)
          ));
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          const aggregatedPublicKey = await bls.aggregatePublicKeys(
            publicKey
          );
          expect(
            await bls.verify(
              wrongMessage,
              aggregatedPublicKey,
              aggregatedSignature,
              domain
            )
          ).toBe(message === wrongMessage);
        }
      )
    , {numRuns: NUM_RUMS});
  });
});
