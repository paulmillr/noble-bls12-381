const { run, mark, logMem } = require('micro-bmark');
const bls = require('..');

run(async () => {
  // warm-up
  // await mark(() => {
  //   ed.utils.precompute();
  // });

  //logMem();
  //console.log();

  const toHex = (n) => n.map(i => i.toString(16));
  const MESSAGE = new TextEncoder().encode('a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  // const res = await bls.hash_to_field(MESSAGE, 2);
  // console.log(res.flatMap(toHex));

  // const po = bls.G2.multiply(126794n);
  // const aff = po.toAffine();
  // const repo = new bls.Point(aff[0], aff[1], bls.Fp2.ONE, bls.Fp2);
  // console.log(`compo ${po} ${repo} ${po.equals(repo)}`);
  const curve = await bls.hash_to_curve(MESSAGE);
  // await mark('sign', 1, async () => await bls.hashToG2('0abc', '424c53313233383147325f584d443a5348412d3235365f535357555f524f5f5445535447454e'));

  // await mark('getPublicKey', 1000, () => bls.getPublicKey(0xdeadbeefn));
  // await mark('sign', 10, async () => await bls.sign('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f2', 12344123n, 1));
  // await mark('verify', 5, async () => {
  //   bls.verify(
  //     '2498796dfae14fd241a4',
  //     '93a0a5db2e72bab8408534e6a022ae26ba5d52e1d082be5238876974ec2d8dde1f8bc3bc52fa6bd6c40e3f9a5b381e6c',
  //     '8df3456c3dca9bf7fcd0424377092bf1fa9c71773070bc9f8590ab7ccc63e4f9a82c499d139d40fb9cf6d80f31c9d19608c56a0fb06ba1de326b8847aacb4112f196a8ad919675c6b56f21329b215084e9750167f9728ec9d6eb59b41208e178',
  //     5566
  //   );
  // });
  // await mark('aggregateSignatures', 10, () =>
  //   bls.aggregateSignatures([
  //     'b8acc4040f3ecf49d3b8921c24296cd9330aaa48706690a9f101ec9b94b83f4a2506988d101a32e2b5e1299f3c4d15d80f5d261df3f89e53c5283594c624bf5241745d9b03853f57a0f30f9d3d12009ae4f6e8b2c5ab6872a2216ce3252e3985',
  //     '824550360ee39824076558e942725a4da901a49f3214a7bf9e02b86f6f8556899aa835d0fc793288f931af782a31063d09cd002efa15081cb296dc14a6ccab348d6cb371dd8445941d28ce78530ad2d3c50c225b8da3d806141e338c091f9fc0',
  //   ])
  // );
  // await mark('pairing', 5, () => bls.pairing(bls.G2, bls.G1));
  //logMem();
});
