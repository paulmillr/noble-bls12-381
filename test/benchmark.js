const { run, mark, logMem } = require('micro-bmark');
let bls;

run(async () => {
  // warm-up
  // await mark(() => {
  //   bls.PointG1.BASE.calcMultiplyPrecomputes(16);
  // });

  logMem();
  //console.log();

  const toHex = (n) =>
    Array.from(n)
      .map((i) => i.toString(16).padStart(2, '0'))
      .join('');
  const msg = new TextEncoder().encode('a');
  // const res = await bls.hash_to_field(MESSAGE, 2);
  // console.log(res.flatMap(toHex));

  // const po = bls.G2.multiply(126794n);
  // const aff = po.toAffine();
  // const repo = new bls.Point(aff[0], aff[1], bls.Fp2.ONE, bls.Fp2);
  // console.log(`compo ${po} ${repo} ${po.equals(repo)}`);
  // const signed = await bls.sign(MESSAGE, 2);
  // console.log(`signed ${toHex(signed)}`);

  //await mark('sign', 1, async () => await bls.hashToG2('0abc', '424c53313233383147325f584d443a5348412d3235365f535357555f524f5f5445535447454e'));
  await mark('init', 1, () => {
    bls = require('..');
  });
  await mark('getPublicKey (1-bit)', 1000, () => bls.getPublicKey('1'));
  await mark('getPublicKey', 1000, () =>
    bls.getPublicKey('28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c')
  );
  await mark(
    'sign',
    10,
    async () =>
      await bls.sign('09', '28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c')
  );
  await mark('aggregateSignatures', 10, () =>
    bls.aggregateSignatures([
      'b8acc4040f3ecf49d3b8921c24296cd9330aaa48706690a9f101ec9b94b83f4a2506988d101a32e2b5e1299f3c4d15d80f5d261df3f89e53c5283594c624bf5241745d9b03853f57a0f30f9d3d12009ae4f6e8b2c5ab6872a2216ce3252e3985',
      '824550360ee39824076558e942725a4da901a49f3214a7bf9e02b86f6f8556899aa835d0fc793288f931af782a31063d09cd002efa15081cb296dc14a6ccab348d6cb371dd8445941d28ce78530ad2d3c50c225b8da3d806141e338c091f9fc0',
    ])
  );
  const pub = bls.getPublicKey('28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c');
  await mark('verify', 20, async () => {
    await bls.verify(
      '8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5',
      '09',
      pub
    );
  });
  const p1 = bls.PointG1.BASE.multiply(
    0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
  );
  const p2 = bls.PointG2.BASE.multiply(
    0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
  );
  await mark('pairing (batch)', 40, () => bls.pairing(p1, p2));
  await mark('pairing (single)', 40, () => {
    p2.clearPairingPrecomputes();
    bls.pairing(p1, p2)
  });
  logMem();
});
