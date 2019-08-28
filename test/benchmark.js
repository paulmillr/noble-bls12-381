const Benchmark = require("benchmark");
const bls = require("./src");

const suite = new Benchmark.Suite();

suite
  .add("Pairing#test", () => bls.pairing(bls.G2, bls.G1))
  .add("getPublicKey#test", () => bls.getPublicKey(0xdeadbeefn))
  .add("sign#test", {
    defer: true,
    fn: deferred =>
      bls.sign("deadbeef", 0xdeadbeefn, 1).then(() => deferred.resolve())
  })
  .add("verify#test", {
    defer: true,
    fn: deferred =>
      bls
        .verify(
          "2498796dfae14fd241a4",
          "93a0a5db2e72bab8408534e6a022ae26ba5d52e1d082be5238876974ec2d8dde1f8bc3bc52fa6bd6c40e3f9a5b381e6c",
          "8df3456c3dca9bf7fcd0424377092bf1fa9c71773070bc9f8590ab7ccc63e4f9a82c499d139d40fb9cf6d80f31c9d19608c56a0fb06ba1de326b8847aacb4112f196a8ad919675c6b56f21329b215084e9750167f9728ec9d6eb59b41208e178",
          5566
        )
        .then(() => deferred.resolve())
  })
  .add("aggregateSignatures#test", deferred =>
    bls.aggregateSignatures([
      "b8acc4040f3ecf49d3b8921c24296cd9330aaa48706690a9f101ec9b94b83f4a2506988d101a32e2b5e1299f3c4d15d80f5d261df3f89e53c5283594c624bf5241745d9b03853f57a0f30f9d3d12009ae4f6e8b2c5ab6872a2216ce3252e3985",
      "824550360ee39824076558e942725a4da901a49f3214a7bf9e02b86f6f8556899aa835d0fc793288f931af782a31063d09cd002efa15081cb296dc14a6ccab348d6cb371dd8445941d28ce78530ad2d3c50c225b8da3d806141e338c091f9fc0"
    ])
  )
  .on("cycle", event => console.log(String(event.target)))
  .run({ async: true });

