# noble-bls12-381

[bls12-381](https://electriccoin.co/blog/new-snark-curve/), a pairing-friendly elliptic curve construction.

This is a Barreto-Lynn-Scott curve with an embedding degree of 12. It's optimal for zk-SNARKs at the 128-bit security level.

It allows simple construction of [threshold signatures](https://medium.com/@snigirev.stepan/bls-signatures-better-than-schnorr-5a7fe30ea716), which allows a user to
sign lots of messages with one signature and verify them swiftly in a batch.

### This library belongs to *noble* crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies
- Easily auditable TypeScript/JS code
- Uses es2019 bigint. Supported in Chrome, Firefox, node 10+
- All releases are signed and trusted
- Check out all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381),
  [ripemd160](https://github.com/paulmillr/noble-ripemd160),
  [secretbox-aes-gcm](https://github.com/paulmillr/noble-secretbox-aes-gcm)

## Usage

> npm install noble-bls12-381

### Sign a message

```js
import * as bls from "bls12-381";

const DOMAIN = 2;
const PRIVATE_KEY = 0xa665a45920422f9d417e4867ef;
const HASH_MESSAGE = new Uint8Array([99, 100, 101, 102, 103]);

(async () => {
  const publicKey = bls.getPublicKey(PRIVATE_KEY);
  const signature = await bls.sign(HASH_MESSAGE, PRIVATE_KEY, DOMAIN);
  const isCorrect = await bls.verify(HASH_MESSAGE, publicKey, signature, DOMAIN);
})();
```

### Sign 1 message 3 times

```js
import * as bls from "bls12-381";

const DOMAIN = 2;
const PRIVATE_KEYS = [81, 455, 19];
const HASH_MESSAGE = new Uint8Array([99, 100, 101, 102, 103]);

(async () => {
  const publicKeys = PRIVATE_KEYS.map(bls.getPublicKey);
  const signatures = await Promise.all(PRIVATE_KEYS.map(p => bls.sign(HASH_MESSAGE, p, DOMAIN)));
  const publicKey = await bls.aggregatePublicKeys(publicKeys);
  const signature = await bls.aggregateSignatures(signatures);
  const isCorrect = await bls.verify(HASH_MESSAGE, publicKey, signature, DOMAIN);
})();
```

### Sign 3 messages with 3 keys

```js
import * as bls from "bls12-381";

const DOMAIN = 2;
const PRIVATE_KEYS = [81, 455, 19];
const HASH_MESSAGES = ["deadbeef", "111111", "aaaaaabbbbbb"];

(async () => {
  const publicKeys = PRIVATE_KEYS.map(bls.getPublicKey);
  const signatures = await Promise.all(PRIVATE_KEYS.map((p, i) => bls.sign(HASH_MESSAGES[i], p, DOMAIN)));
  const signature = await bls.aggregateSignatures(signatures);
  const isCorrect = await bls.verifyMultiple(HASH_MESSAGES, publicKeys, signature, DOMAIN);
})();
```

## API

- [`getPublicKey(privateKey)`](#getpublickeyprivatekey)
- [`sign(hash, privateKey, domain)`](#signhash-privatekey-domain)
- [`verify(hash, publicKey, signature, domain)`](#verifyhash-publickey-signature-domain)
- [`aggregatePublicKeys(publicKeys)`](#aggregatepublickeyspublickeys)
- [`aggregateSignatures(signatures)`](#aggregatesignaturessignatures)
- [`verifyMultiple(hashes, publicKeys, signature, domain)`](#verifymultiplehashes-publickeys-signature-domain)
- [`pairing(4dPoint, 2dPoint)`](#pairing4dpoint-2dpoint)
- [Helpers](#helpers)

##### `getPublicKey(privateKey)`
```typescript
function getPublicKey(privateKey: Uint8Array | string | bigint): Uint8Array;
```
- `privateKey: Uint8Array | string | bigint` will be used to generate public key.
  Public key is generated by executing scalar multiplication of a base Point(x, y) by a fixed
  integer. The result is another `Point(x, y)` which we will by default encode to hex Uint8Array.
- Returns `Uint8Array`: encoded publicKey for signature verification

##### `sign(hash, privateKey, domain)`
```typescript
function sign(
  hash: Uint8Array | string,
  privateKey: Uint8Array | string | bigint,
  domain: Uint8Array | string | bigint
): Promise<Uint8Array>;
```
- `hash: Uint8Array | string` - message hash which would be signed
- `privateKey: Uint8Array | string | bigint` - private key which will sign the hash
- `domain: Uint8Array | string | bigint` - signature version. Different domains will give different signatures. Setting a new domain in an upgraded system prevents it from being affected by the old messages and signatures.
- Returns `Uint8Array`: encoded signature

##### `verify(hash, publicKey, signature, domain)`
```typescript
function verify(
  hash: Uint8Array | string,
  publicKey: Uint8Array | string,
  signature: Uint8Array | string,
  domain: Uint8Array | string | bigint
): Promise<boolean>
```
- `hash: Uint8Array | string` - message hash that needs to be verified
- `publicKey: Uint8Array | string` - e.g. that was generated from `privateKey` by `getPublicKey`
- `signature: Uint8Array | string` - object returned by the `sign` or `aggregateSignatures` function
- Returns `Promise<boolean>`: `true` / `false` whether the signature matches hash

##### `aggregatePublicKeys(publicKeys)`
```typescript
function aggregatePublicKeys(publicKeys: Uint8Array[] | string[]): Uint8Array;
```
- `publicKeys: Uint8Array[] | string[]` - e.g. that have been generated from `privateKey` by `getPublicKey`
- Returns `Uint8Array`: one aggregated public key which calculated from public keys

##### `aggregateSignatures(signatures)`
```typescript
function aggregateSignatures(signatures: Uint8Array[] | string[]): Uint8Array;
```
- `signatures: Uint8Array[] | string[]` - e.g. that have been generated by `sign`
- Returns `Uint8Array`: one aggregated signature which calculated from signatures

##### `verifyMultiple(hashes, publicKeys, signature, domain)`
```typescript
function verifyMultiple(
  hashes: Uint8Array[] | string[],
  publicKeys: Uint8Array[] | string[],
  signature: Uint8Array | string,
  domain: Uint8Array | string | bigint
): Promise<boolean>
```
- `hashes: Uint8Array[] | string[]` - messages hashes that needs to be verified
- `publicKeys: Uint8Array[] | string[]` - e.g. that were generated from `privateKeys` by `getPublicKey`
- `signature: Uint8Array | string` - object returned by the `aggregateSignatures` function
- Returns `Promise<boolean>`: `true` / `false` whether the signature matches hashes

##### `pairing(4dPoint, 2dPoint)`
```typescript
function pairing(
  4dPoint: Point<[bigint, bigint]>,
  2dPoint: Point<bigint>,
  withFinalExponent: boolean = true
): Point<[bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint]>
```
- `4dPoint: Point<[bigint, bigint]>` - 4d point ((`(x, x_1), (y, y_1)`))
- `2dPoint: Point<bigint>` - simple point (`x, y` are encoded in the `bigint`).
- `withFinalExponent: boolean` - if the flag setted as true then result will be powered by curve order else will be not.
- Returns `Point<BigintTwelve>`: paired 12 dimensional point.

##### Helpers

```typescript
// 𝔽p
bls.P // 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn

// Prime order
bls.PRIME_ORDER // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n

// Hash base point (x, y)
bls.G1 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n
// x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
// y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569

// Signature base point ((x_1, x_2), (y_1, y_2))
bls.G2
// x = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758, 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
// y = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582, 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905

// Classes
bls.Fp // Subgroup
bls.Fp2 // 2-dimensional number
bls.Fp12 // 12-dimensional number
bls.Point // Elliptic curve point
```

## Curve Description

BLS12-381 is a pairing-friendly elliptic curve construction from the [BLS family](https://eprint.iacr.org/2002/088), with embedding degree 12. It is built over a 381-bit prime field `GF(p)` with...

* z = `-0xd201000000010000`
* p = (z - 1)<sup>2</sup> ((z<sup>4</sup> - z<sup>2</sup> + 1) / 3) + z
	* = `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`
* q = z<sup>4</sup> - z<sup>2</sup> + 1
	* = `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`

... yielding two **source groups** G<sub>1</sub> and G<sub>2</sub>, each of 255-bit prime order `q`, such that an efficiently computable non-degenerate bilinear pairing function `e` exists into a third **target group** G<sub>T</sub>. Specifically, G<sub>1</sub> is the `q`-order subgroup of E(F<sub>p</sub>) : y^2 = x^3 + 4 and G<sub>2</sub> is the `q`-order subgroup of E'(F<sub>p<sup>2</sup></sub>) : y<sup>2</sup> = x<sup>3</sup> + 4(u + 1) where the extention field F<sub>p<sup>2</sup></sub> is defined as F<sub>p</sub>(u) / (u<sup>2</sup> + 1).

BLS12-381 is chosen so that `z` has small Hamming weight (to improve pairing performance) and also so that `GF(q)` has a large 2<sup>32</sup> primitive root of unity for performing radix-2 fast Fourier transforms for efficient multi-point evaluation and interpolation. It is also chosen so that it exists in a particularly efficient and rigid subfamily of BLS12 curves.

## Speed

The library is pretty slow right now, but it's still good enough for many everyday cases.

```
getPublicKey#test x 1,080 ops/sec ±0.88% (85 runs sampled)
sign#test x 16.32 ops/sec ±1.08% (75 runs sampled)
aggregateSignatures#test x 161 ops/sec ±0.92% (79 runs sampled)
verify#test x 0.48 ops/sec ±0.74% (7 runs sampled)
Pairing#test x 1.05 ops/sec ±1.43% (7 runs sampled)
```

## Security

Noble is production-ready & secure. Our goal is to have it audited by a good security expert.

We're using built-in JS `BigInt`, which is "unsuitable for use in cryptography" as [per official spec](https://github.com/tc39/proposal-bigint#cryptography). This means that the lib is vulnerable to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). But:

1. JIT-compiler and Garbage Collector make "constant time" extremely hard to achieve in a scripting language.
2. Which means *any other JS library doesn't use constant-time bigints*. Including bn.js or anything else. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases.
3. Overall they are quite rare; for our particular usage they're unimportant. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Try LibreSSL & similar low-level libraries & languages.
4. We however consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading rootkits with every `npm install`. Our goal is to minimize this attack vector.

## License

MIT (c) Paul Miller (https://paulmillr.com), see LICENSE file.
