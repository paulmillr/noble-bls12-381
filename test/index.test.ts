import * as fc from "fast-check";
import * as bls from "../src";

const NUM_RUNS = 1; // reduce to 1 to shorten test time

describe("bls12-381", () => {
  it("should create different signatures for different domains", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.bigInt(1n, bls.PRIME_ORDER),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, privateKey, domain, otherDomain) => {
          const [publicKey, signature1, signature2] = await Promise.all([
            bls.getPublicKey(privateKey),
            bls.sign(message, privateKey, domain),
            bls.sign(message, privateKey, otherDomain)
          ]);
          expect(publicKey.length).toBe(48);
          expect(signature1.length).toBe(96);
          expect(signature2.length).toBe(96);
          if (domain !== otherDomain) {
            expect(signature1).not.toEqual(signature2);
          } else {
            expect(signature1).toEqual(signature2);
          }
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should create same aggregated public key if order of arguments will be changed", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 2, 200),
        async privateKeys => {
          const pubkeys = await Promise.all(
            privateKeys.map(privateKey => bls.getPublicKey(privateKey))
          );
          const [
            aggregatedPublicKey1,
            aggregatedPublicKey2
          ] = await Promise.all([
            bls.aggregatePublicKeys(pubkeys),
            bls.aggregatePublicKeys([...pubkeys].reverse())
          ]);
          expect(aggregatedPublicKey1).toEqual(aggregatedPublicKey2);
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should create same aggregated signature if order of arguments will be changed", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.hexa(), 2, 200),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 2, 200),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (messages, privateKeys, domain) => {
          const signatures = await Promise.all(
            privateKeys.map((privateKey, i) =>
              bls.sign(messages[i] || "0", privateKey, domain)
            )
          );
          const [
            aggregatedSignature1,
            aggregatedSignature2
          ] = await Promise.all([
            bls.aggregateSignatures(signatures),
            bls.aggregateSignatures([...signatures].reverse())
          ]);
          expect(aggregatedSignature1).toEqual(aggregatedSignature2);
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
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
      ),
      { numRuns: NUM_RUNS }
    );
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
      ),
      { numRuns: NUM_RUNS }
    );
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
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            messages.map((message, i) =>
              bls.sign(message, privateKeys[i], domain)
            )
          );
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
      ),
      { numRuns: NUM_RUNS }
    );
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
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            messages.map((message, i) =>
              bls.sign(message, privateKeys[i], domain)
            )
          );
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
      ),
      { numRuns: NUM_RUNS }
    );
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
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const wrongPublicKeys = await Promise.all(
            wrongPrivateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            messages.map((message, i) =>
              bls.sign(message, privateKeys[i], domain)
            )
          );
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
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should verify multi-signature as simple signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, privateKeys, domain) => {
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            privateKeys.map((privateKey, i) =>
              bls.sign(message, privateKey, domain)
            )
          );
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
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should not verify multi-signature as simple signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexa(),
        fc.hexa(),
        fc.array(fc.bigInt(1n, bls.PRIME_ORDER), 1, 100),
        fc.bigInt(1n, BigInt(Number.MAX_SAFE_INTEGER)),
        async (message, wrongMessage, privateKeys, domain) => {
          const publicKey = await Promise.all(
            privateKeys.map(bls.getPublicKey)
          );
          const signatures = await Promise.all(
            privateKeys.map((privateKey, i) =>
              bls.sign(message, privateKey, domain)
            )
          );
          const aggregatedSignature = await bls.aggregateSignatures(signatures);
          const aggregatedPublicKey = await bls.aggregatePublicKeys(publicKey);
          expect(
            await bls.verify(
              wrongMessage,
              aggregatedPublicKey,
              aggregatedSignature,
              domain
            )
          ).toBe(message === wrongMessage);
        }
      ),
      { numRuns: NUM_RUNS }
    );
  });
  it("should create right public key for private key 0", async () => {
    const publicKey = await bls.getPublicKey(0n);
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
  });
  it("should create right public key for vector 1", async () => {
    const publicKey = await bls.getPublicKey(15n);
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "8d9e19b3f4c7c233a6112e5397309f9812a4f61f754f11dd3dcb8b07d55a7b1dfea65f19a1488a14fef9a41495083582"
    );
  });
  it("should create right public key for vector 2", async () => {
    const publicKey = await bls.getPublicKey(5566n);
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "98fad4ca8b98082de0ea80ba8e43ac4e7c45ad2730624b92f483370f8aaaf6514d58f472012f7b7b37ae3a8b5af9ed13"
    );
  });
  it("should create right public key for vector 3", async () => {
    const publicKey = await bls.getPublicKey(12344123n);
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "93a0a5db2e72bab8408534e6a022ae26ba5d52e1d082be5238876974ec2d8dde1f8bc3bc52fa6bd6c40e3f9a5b381e6c"
    );
  });
  it("should create right public key for vector 4", async () => {
    const publicKey = await bls.getPublicKey(1n);
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    );
  });
  it("should create right public key for vector 5", async () => {
    const publicKey = await bls.getPublicKey(
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan
    );
    expect(Buffer.from(publicKey).toString("hex")).toBe(
      "a2c8135993f651b6b8ead18769e4ecd957d4f5cdf75df4cae8d16c62bfba117270ad2dbe52e57d691f67e4aed8f6cd16"
    );
  });
  it("should create right aggregated public key for vector 1", async () => {
    const [publicKey1, publicKey2] = await Promise.all([
      bls.getPublicKey(5566n),
      bls.getPublicKey(15n)
    ]);
    const aggregatedPublicKey = await bls.aggregatePublicKeys([
      publicKey1,
      publicKey2
    ]);
    expect(Buffer.from(aggregatedPublicKey).toString("hex")).toBe(
      "a3253d8043c331d9b77076a74c7e6761d8cc90c663a45b6b7c31a5a66d8407faa7709d18fbe6f7364ff90318e636b877"
    );
  });
  it("should create right aggregated public key for vector 2", async () => {
    const [publicKey1, publicKey2] = await Promise.all([
      bls.getPublicKey(5566n),
      bls.getPublicKey(44n)
    ]);
    const aggregatedPublicKey = await bls.aggregatePublicKeys([
      publicKey1,
      publicKey2
    ]);
    expect(Buffer.from(aggregatedPublicKey).toString("hex")).toBe(
      "acb1531c76d1486acd10b3969a1dc40155c65fe9ef0ff7c8773fc142007d8623f3ad8a367b87e182372379f1746fd0c7"
    );
  });
  it("should create right aggregated public key for vector 3", async () => {
    const [publicKey1, publicKey2] = await Promise.all([
      bls.getPublicKey(88888n),
      bls.getPublicKey(44n)
    ]);
    const aggregatedPublicKey = await bls.aggregatePublicKeys([
      publicKey1,
      publicKey2
    ]);
    expect(Buffer.from(aggregatedPublicKey).toString("hex")).toBe(
      "a0270922fc920f32f10b5499b147e4c48f7556d7ade887b7eb5a1165c4902e7a4da07fa8347b9892377981f05bddac1d"
    );
  });
  it("should create right aggregated public key for vector 4", async () => {
    const [publicKey1, publicKey2] = await Promise.all([
      bls.getPublicKey(22n),
      bls.getPublicKey(22n)
    ]);
    const aggregatedPublicKey = await bls.aggregatePublicKeys([
      publicKey1,
      publicKey2
    ]);
    expect(Buffer.from(aggregatedPublicKey).toString("hex")).toBe(
      "95fa3538b8379ff2423656ab436df1632b74311aaef49bc9a3cbd70b1b01febaf2f869b4127d0e8e6d18d7d919f1f6d8"
    );
  });
  it("should create right aggregated public key for vector 5", async () => {
    const [publicKey1, publicKey2] = await Promise.all([
      bls.getPublicKey(4810922311234n),
      bls.getPublicKey(22n)
    ]);
    const aggregatedPublicKey = await bls.aggregatePublicKeys([
      publicKey1,
      publicKey2
    ]);
    expect(Buffer.from(aggregatedPublicKey).toString("hex")).toBe(
      "aa1554bee817c20ac1ae3abd55da26bef2b51299201f1328c73ddab130d943a27ef9330b502c54012079d9bd641f8bfd"
    );
  });
  it("should create right signature for private key 0", async () => {
    const signature = await bls.sign("00", 0n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
  });
  it("should create right signature for vector 1", async () => {
    const signature = await bls.sign("00", 15n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "9141f6aae740ca3b5bedcfc7d4592d4e606062f22b6a7f69be87dec79aab5f809667d98a180e015c618ed43587140bc311fd2eeccb64644deef3957d1444453bfb754e5c31ae3d95dea9ffb2c549bb8d17a974cfe7265b863ed9cb89429bb67b"
    );
  });
  it("should create right signature for vector 2", async () => {
    const signature = await bls.sign("00", 5566n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "8af2311914070f5532da5abacd4356d15e328ad4dacc98e8711e3dfc3623aa58eda2e38acd6ed2d77e9c7ba6e6438efb0b5ac578cec7aebf6bcc84afc405f573a91e35e05417430ba8577829347f1905ff529320c9689f3712d20a820c2ca4aa"
    );
  });
  it("should create right signature for vector 3", async () => {
    const signature = await bls.sign("00", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "945a34c2b51c95c4fba4e2d9e3cac8625993106e714802e8c48435f8c1a4b9633120521dc00aa1890e8599654f0034ae04dc71acafcb8c5e110f217f532ed9b02fd15417b296c89cbdcf7bdb49a19f59ada7d61c46462cc86b1aa783c8cfa7f6"
    );
  });
  it("should create right signature for vector 4", async () => {
    const signature = await bls.sign("00", 1n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "8470e5084e5c7dc6eb9b50c53f6676c65f9f1ed9a4af82a4d96b2cb6c0866689afe0d29a0798bf18616b130327a158ea114df926f850ccc01b2504c432d2e2dccae3b7bc7853045c9d962c39e45c972fab07931b7016a385d2ed5eed3f96cf92"
    );
  });
  it("should create right signature for vector 5", async () => {
    const signature = await bls.sign(
      "00",
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
      1
    );
    expect(Buffer.from(signature).toString("hex")).toBe(
      "a068d5f2c73e87c70a148ca6c9802e7207b24aefbcc5e5cc75127a87c58d1d455327e3efcdb27e0646d3f705b0679f4b0bf2a7b762d5217b203b1a0f2800265f0b7fa1bb9f2e5d135e10202f21b1bd63ef81ec12ce7df3a34e2ef25d7ef02062"
    );
  });
  it("should create right signature for vector 6", async () => {
    const signature = await bls.sign("aabb", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "86851968a2164bd233402586777fb53a942308f6aa67f5b56a374b117478f409751aa7b9ec83f71bf634ee7018041ff70ddd51f648eaafd88f166fe8acee57b4a776a17f7b7d9321a594af449c1704bbfa5b14ef895aaf4eb4941047840b6d37"
    );
  });
  it("should create right signature for vector 7", async () => {
    const signature = await bls.sign("01", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "a4756a5e480f1ed64ad6b57d829d5f42b925286faf771678dbc48e9b51a475e1459168bf0ba0e2bdfc6e747a330366700a2c843a8baaad0c5c9201ea6d6cbe9f9fd306844e06f8956ad5aa6294538eef4297f9d59b01c46469224f5b561f9215"
    );
  });
  it("should create right signature for vector 8", async () => {
    const signature = await bls.sign("deadbeaf", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "ad70dfb462fa4d6ae7d6bb2510b9254940cb3716de204f91e22343ea065c8564daeae37038a6704e9de9b9717127dfa90436424999301d97cf70366c66da5f5d1585890a6b293026582779397464f0531e5a77337f993e7d349afdffb8b3671e"
    );
  });
  it("should create right signature for vector 9", async () => {
    const signature = await bls.sign("2498796dfae14fd241a4", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "ac2c73066c65a43b4cc901073d8818b7a7b70aca49acf7f246aaa0ad4dc16b7a776b954909ba08e3f54b46c733b572b60261828049443cdd2bc8bb31b8c1101a57a6e1add206eb7fe67aaa5e6c0547d063f66cbffa0173da0e0318ada931e374"
    );
  });
  it("should create right signature for vector 10", async () => {
    const signature = await bls.sign("", 12344123n, 1);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "9545022728bddbfe3c56b86d92ed7af747da671f5ebbc4fe4d6d94acabd951e55d59c37725ad477fe91df00d9c5f99c81837575efb7162bf5d06fe7f981a8e746fd317b0d82ae8f7df8b2faee8255b2134142b40d5e51287859c6eddabf0aa4e"
    );
  });
  it("should create right signature for vector 11", async () => {
    const signature = await bls.sign("aabb", 12344123n, 43);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "ab53da7fab88ac018733d42dd892039b6c869d1bc02fd90b6d63beee421e5b0a717929a5532719e8c818cdf4db5b1a8312b395b83e87884171cf9f2dd5a8ebb7185008b376e546a42a92f024c3d967e8bc831a99d56bdc7a83bfa2acee6e7d24"
    );
  });
  it("should create right signature for vector 12", async () => {
    const signature = await bls.sign("01", 12344123n, 2);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "9269f9dc872321b3d877e4a110d2e90cb0dbbc028e893e194aa9dbe46a66eaa9b107d31dd5c03d5c6034277f865a2a1e090f47e93c32b83ad5b3f79a2890b68fc3c243f6ec443f6c8d14cb57822c8b0138ecff563391420ac8ae24c0c1b522d2"
    );
  });
  it("should create right signature for vector 13", async () => {
    const signature = await bls.sign("deadbeaf", 12344123n, 888);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "b7915420c961d5e8b002bbaa8859c30f0f602059d485f657034ddee090d57b682db063479e14f3f6ab52003e8f6ac63c0f8416d58fca715922fd4a5650d3e22146881f8010194a9b1210909e9aa48a62f33608d02b4d558df7d00d1f1f7bbda8"
    );
  });
  it("should create right signature for vector 14", async () => {
    const signature = await bls.sign("2498796dfae14fd241a4", 12344123n, 5566);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "8df3456c3dca9bf7fcd0424377092bf1fa9c71773070bc9f8590ab7ccc63e4f9a82c499d139d40fb9cf6d80f31c9d19608c56a0fb06ba1de326b8847aacb4112f196a8ad919675c6b56f21329b215084e9750167f9728ec9d6eb59b41208e178"
    );
  });
  it("should create right signature for vector 15", async () => {
    const signature = await bls.sign("", 12344123n, 21);
    expect(Buffer.from(signature).toString("hex")).toBe(
      "b8eda486330e0acbc74b5a68df5dabf95e73a0ef6959f65b32bd6d593fb0ca206bfc74bc066048225b783210fc37f20c1218caa55af025141acb05991219721c9809240a0fc36d32b7b19d15e6ff97e3f4fb4598d08a766cbc2698dd298b62ec"
    );
  });
  it("should create right aggregated signature for vector 1", async () => {
    const [signature1, signature2] = await Promise.all([
      bls.sign("aabb", 44n, 1),
      bls.sign("deadbeaf", 241234n, 1)
    ]);
    const aggregatedSignature = await bls.aggregateSignatures([
      signature1,
      signature2
    ]);
    expect(Buffer.from(aggregatedSignature).toString("hex")).toBe(
      "8193029ab4832f68657300b85e585c123ab86ef7f244d6cd67197725eb0b08bb54bcd16c815a3d4f763fdb27ae64ad0507799d55edb6084ef203d4c9d24ae8f5804f07943d58bcbaaee356b8874709c609cda4a618026066b42ead87c92f7589"
    );
  });
  it("should create right aggregated signature for vector 2", async () => {
    const [signature1, signature2] = await Promise.all([
      bls.sign("124315", 88005553535n, 1),
      bls.sign(
        "900000",
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        1
      )
    ]);
    const aggregatedSignature = await bls.aggregateSignatures([
      signature1,
      signature2
    ]);
    expect(Buffer.from(aggregatedSignature).toString("hex")).toBe(
      "956097f2937d49b417c407fd7a1f25dfffda5c3eac35b14b52d43b9631f73c8b89b42cdad102040eb473a89605ffb9550f0fcba52e804304128ff41911e01b3c64e76a232b87ad08103136cd5b3dc2f815bff1d0b540979ff8fdcd459ad390b8"
    );
  });
  it("should create right aggregated signature for vector 3", async () => {
    const [signature1, signature2] = await Promise.all([
      bls.sign("124315", 88005553535n, 2),
      bls.sign(
        "900000",
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        2
      )
    ]);
    const aggregatedSignature = await bls.aggregateSignatures([
      signature1,
      signature2
    ]);
    expect(Buffer.from(aggregatedSignature).toString("hex")).toBe(
      "a6bb20a281a9d374321a4908827b6ffac52f7296130cb9c37bd13184f867a07d4658d26c423b8d2d0ca467da7d260b8401a99de059f1918e71efd196c1a71d59e5d53d1c6f6f62a257e0abc8851cfaf1ca24e007a435edfb06c51afd4ef374c5"
    );
  });
  it("should create right aggregated signature for vector 4", async () => {
    const [signature1, signature2, signature3] = await Promise.all([
      bls.sign("124315", 88005553535n, 1),
      bls.sign(
        "900000",
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        1
      ),
      bls.sign("deadbeaf", 241234n, 1)
    ]);
    const aggregatedSignature = await bls.aggregateSignatures([
      signature1,
      signature2,
      signature3
    ]);
    expect(Buffer.from(aggregatedSignature).toString("hex")).toBe(
      "88d34ea8026ede1268065fa29c0c3cfc68555b44d14f3813c72efe90ad94ed19eac69249fdc289d9cd98b5cfe4bc95f70c8d49c7589a45bf9ddab176a12ed88e88f3944a9d3343c172f5153c83f43b3e64a58934176850208af855f7c07e3668"
    );
  });
  it("should create right aggregated signature for vector 5", async () => {
    const signature = await bls.sign("124315", 88005553535n, 1);
    const aggregatedSignature = await bls.aggregateSignatures([signature]);
    expect(Buffer.from(aggregatedSignature).toString("hex")).toBe(
      "93731f6be8ba732fa96348b0856684437248136e55857ab2ccf7f782b6d6cdd12b5f47408069b10b423225433a266c2f0410417ad3e87b7985b35e2221f71cfaf8c3ae000cdd3fd3fef52b0d7be7f656b83014bbb50155579d5e6097afbc8a68"
    );
  });
  it("should create negative G1 pairing", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = bls.pairing(bls.G2, bls.G1.negative());
		expect(p1.multiply(p2)).toEqual(p1.one);
  });
  it("should create negative G2 pairing", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = bls.pairing(bls.G2, bls.G1.negative());
		const p3 = bls.pairing(bls.G2.negative(), bls.G1);
		expect(p2).toEqual(p3);
  });
  it("should create right pairing output order", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = p1.pow(bls.PRIME_ORDER);
		expect(p2).toEqual(p1.one);
  });
  it("should create right pairing with bilinearity on G1", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = bls.pairing(bls.G2, bls.G1.multiply(2n));
		expect(p1.multiply(p1)).toEqual(p2);
  });
  it("pairing should not be degenerate", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = bls.pairing(bls.G2, bls.G1.multiply(2n));
		const p3 = bls.pairing(bls.G2.negative(), bls.G1);
		expect(p1).not.toEqual(p2);
		expect(p1).not.toEqual(p3);
		expect(p2).not.toEqual(p3);
  });
  it("should create right pairing with bilinearity on G2", () => {
		const p1 = bls.pairing(bls.G2, bls.G1);
		const p2 = bls.pairing(bls.G2.multiply(2n), bls.G1);
		expect(p1.multiply(p1)).toEqual(p2);
  });
  it("should create right pairing composite check", () => {
		const p1 = bls.pairing(bls.G2.multiply(27n), bls.G1.multiply(37n));
		const p2 = bls.pairing(bls.G2, bls.G1.multiply(999n));
		expect(p1).toEqual(p2);
  });
});
