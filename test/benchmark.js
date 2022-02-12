const { run, mark, logMem } = require('micro-bmark');
const fs = require('fs');
const {join} = require('path');
let bls;
const G2_VECTORS = fs.readFileSync(join(__dirname, 'bls12-381-g2-test-vectors.txt'), 'utf-8')
  .trim()
  .split('\n')
  .map(l => l.split(':'));

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
  let p1, p2;
  await mark('init', 1, () => {
    bls = require('..');
    p1 = bls.PointG1.BASE.multiply(
      0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
    );
    p2 = bls.PointG2.BASE.multiply(
      0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
    );
    bls.pairing(p1, p2);
  });
  const priv = '28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c';
  const pubs = G2_VECTORS.map(v => bls.getPublicKey(v[0]));
  const sigs = G2_VECTORS.map(v => v[2]);

  await mark('getPublicKey (1-bit)', 1000, () => bls.getPublicKey('2'.padStart(64, '0')));
  console.log();
  await mark('getPublicKey', 1000, () =>
    bls.getPublicKey(priv)
  );
  await mark(
    'sign',
    20,
    async () =>
      await bls.sign('09', priv)
  );

  const pub = bls.getPublicKey(priv);
  const pubp = bls.PointG1.fromPrivateKey(priv);
  const msgp = await bls.PointG2.hashToCurve('09');
  const sigp = bls.PointG2.fromSignature(await bls.sign('09', priv));

  await mark('verify', 15, async () => {
    await bls.verify(
      '8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5',
      '09',
      pub
    );
  });

  //await mark('pairing (batch)', 40, () => bls.pairing(p1, p2));
  await mark('pairing', 40, () => bls.pairing(p1, p2));
  await mark('aggregatePublicKeys/8', 60, () => bls.aggregatePublicKeys(pubs.slice(0, 8)));
  await mark('aggregateSignatures/8', 20, () => bls.aggregateSignatures(sigs.slice(0, 8)));

  console.log('');
  console.log('with compression / decompression disabled:');
  const pub512 = pubs.slice(0, 512).map(bls.PointG1.fromHex);
  const pub32 = pub512.slice(0, 32);
  const pub128 = pub512.slice(0, 128);
  const pub2048 = pub512.concat(pub512, pub512, pub512);
  const sig512 = sigs.slice(0, 512).map(bls.PointG2.fromSignature);
  const sig32 = sig512.slice(0, 32);
  const sig128 = sig512.slice(0, 128);
  const sig2048 = sig512.concat(sig512, sig512, sig512);

  await mark('sign/nc', 30,  () => bls.sign(msgp, priv));
  await mark('verify/nc', 30, () => bls.verify(sigp, msgp, pubp));

  await mark('aggregatePublicKeys/32', 500, () => bls.aggregatePublicKeys(pub32));
  await mark('aggregatePublicKeys/128', 350, () => bls.aggregatePublicKeys(pub128));
  await mark('aggregatePublicKeys/512', 150, () => bls.aggregatePublicKeys(pub512));
  await mark('aggregatePublicKeys/2048', 45, () => bls.aggregatePublicKeys(pub2048));

  await mark('aggregateSignatures/32', 250, () => bls.aggregateSignatures(sig32));
  await mark('aggregateSignatures/128', 125, () => bls.aggregateSignatures(sig128));
  await mark('aggregateSignatures/512', 40, () => bls.aggregateSignatures(sig512));
  await mark('aggregateSignatures/2048', 10, () => bls.aggregateSignatures(sig2048));
  logMem();
});
