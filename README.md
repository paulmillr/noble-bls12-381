# noble-bls12-381

> [!WARNING]  
> The repository has been merged into [noble-curves](https://github.com/paulmillr/noble-curves). Please head to the new repo for updates:
```js
// npm install @noble/curves
import { bls12_381 } from '@noble/curves/bls12-381';
```

---

[Fastest](#speed) JS implementation of BLS12-381. Auditable, secure, 0-dependency aggregated signatures & pairings.

The pairing-friendly Barreto-Lynn-Scott elliptic curve construction allows to:

- Construct [zk-SNARKs](https://z.cash/technology/zksnarks/) at the 128-bit security
- Use [threshold signatures](https://medium.com/snigirev.stepan/bls-signatures-better-than-schnorr-5a7fe30ea716),
  which allows a user to sign lots of messages with one signature and verify them swiftly in a batch,
  using Boneh-Lynn-Shacham signature scheme.

Compatible with Algorand, Chia, Dfinity, ETH, FIL, ZEC. Matches specs [pairing-curves-10](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-10), [bls-sigs-04](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04), [hash-to-curve-12](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-12). To learn more about internals, navigate to
[utilities](#utilities) section.

### This library belongs to *noble* cryptography

> **noble cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-bls12-381/releases):

> npm install @noble/bls12-381

## License

MIT (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
