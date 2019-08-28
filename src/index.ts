import { Fp } from "./fp";
import { Point } from "./point";
import { Group } from "./group";
import { BigintTuple, Fp2 } from "./fp2";
import { BigintTwelve, Fp12 } from "./fp12";
import {
  B,
  B2,
  Z1,
  Z2,
  Hash,
  Bytes,
  toBigInt,
  hashToG2,
  toBytesBE,
  PRIME_ORDER,
  DOMAIN_LENGTH,
  publicKeyToG1,
  signatureToG2,
  publicKeyFromG1,
  signatureFromG2,
  P_ORDER_X_12_DIVIDED
} from "./utils";

export { Fp } from "./fp";
export { Fp2 } from "./fp2";
export { Fp12 } from "./fp12";
export { Point } from "./point";
export { P, PRIME_ORDER } from "./utils";

type PrivateKey = Bytes | bigint | number;
type Domain = PrivateKey;
type PublicKey = Bytes;
type Signature = Bytes;

// ## Fixed Generators
// Although any generator produced by hashing to $\mathbb{G}_1$ or $\mathbb{G}_2$ is
// safe to use in a cryptographic protocol, we specify some simple, fixed generators.
//
// In order to derive these generators, we select the lexicographically smallest
// valid $x$-coordinate and the lexicographically smallest corresponding $y$-coordinate,
// and then scale the resulting point by the cofactor, such that the result is not the
// identity. This results in the following fixed generators:

// Generator for curve over Fp
export const G1 = new Point(
  // x
  new Fp(
    3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507n
  ),
  // y
  new Fp(
    1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569n
  ),
  new Fp(1n),
  Fp
);

// Generator for twisted curve over Fp2
export const G2 = new Point(
  // x
  new Fp2(
    352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160n,
    3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758n
  ),
  // y
  new Fp2(
    1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905n,
    927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582n
  ),
  new Fp2(1n, 0n),
  Fp2
);

const G12 = G2.twist();

// Check consistency of the "line function"
const ONE = G1;
const TWO = G1.double();
const THREE = G1.multiply(3);
const NE_ONE = G1.multiply(PRIME_ORDER - 1n);
const NE_TWO = G1.multiply(PRIME_ORDER - 2n);
const NE_THREE = G1.multiply(PRIME_ORDER - 3n);

// Create a function representing the line between P1 and P2, and evaluate it at T
// and evaluate it at T. Returns a numerator and a denominator
// to avoid unneeded divisions
function createLineBetween<T>(p1: Point<T>, p2: Point<T>, n: Point<T>) {
  let mNumerator = p2.y.multiply(p1.z).subtract(p1.y.multiply(p2.z));
  let mDenominator = p2.x.multiply(p1.z).subtract(p1.x.multiply(p2.z));
  if (
    !mNumerator.equals(mNumerator.zero) &&
    mDenominator.equals(mDenominator.zero)
  ) {
    return [
      n.x.multiply(p1.z).subtract(p1.x.multiply(n.z)),
      p1.z.multiply(n.z)
    ];
  } else if (mNumerator.equals(mNumerator.zero)) {
    mNumerator = p1.x.square().multiply(3n);
    mDenominator = p1.y.multiply(p1.z).multiply(2n);
  }
  const numeratorLine = mNumerator.multiply(
    n.x.multiply(p1.z).subtract(p1.x.multiply(n.z))
  );
  const denominatorLine = mDenominator.multiply(
    n.y.multiply(p1.z).subtract(p1.y.multiply(n.z))
  );
  const z = mDenominator.multiply(n.z).multiply(p1.z);
  return [numeratorLine.subtract(denominatorLine), z];
}

function castPointToFp12(pt: Point<bigint>): Point<BigintTwelve> {
  if (pt.isEmpty()) {
    return new Point(new Fp12(), new Fp12(), new Fp12(), Fp12);
  }
  return new Point(
    new Fp12((pt.x as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    new Fp12((pt.y as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    new Fp12((pt.z as Fp).value, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n),
    Fp12
  );
}

// prettier-ignore
const PSEUDO_BINARY_ENCODING = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1
];

// Main miller loop
function millerLoop(
  Q: Point<BigintTwelve>,
  P: Point<BigintTwelve>,
  withFinalExponent: boolean = false
) {
  // prettier-ignore
  const one: Group<BigintTwelve> = new Fp12(
    1n, 0n, 0n, 0n,
    0n, 0n, 0n, 0n,
    0n, 0n, 0n, 0n
  );
  if (Q.isEmpty() || P.isEmpty()) {
    return one;
  }
  let R = Q;
  let fNumerator = one;
  let fDenominator = one;
  for (let i = PSEUDO_BINARY_ENCODING.length - 2; i >= 0n; i--) {
    const [n, d] = createLineBetween(R, R, P);
    fNumerator = fNumerator.square().multiply(n);
    fDenominator = fDenominator.square().multiply(d);
    R = R.double();
    if (PSEUDO_BINARY_ENCODING[i] === 1) {
      const [n, d] = createLineBetween(R, Q, P);
      fNumerator = fNumerator.multiply(n);
      fDenominator = fDenominator.multiply(d);
      R = R.add(Q);
    }
  }
  const f = fNumerator.div(fDenominator);
  return withFinalExponent ? f.pow(P_ORDER_X_12_DIVIDED) : f;
}

function finalExponentiate<T>(p: Group<T>) {
  return p.pow(P_ORDER_X_12_DIVIDED);
}

export function pairing(
  Q: Point<BigintTuple>,
  P: Point<bigint>,
  withFinalExponent: boolean = true
) {
  if (!Q.isOnCurve(B2)) {
    throw new Error("Fisrt point isn't on elliptic curve");
  }
  if (!P.isOnCurve(B)) {
    throw new Error("Second point isn't on elliptic curve");
  }
  return millerLoop(Q.twist(), castPointToFp12(P), withFinalExponent);
}


export function getPublicKey(privateKey: PrivateKey) {
  privateKey = toBigInt(privateKey);
  return publicKeyFromG1(G1.multiply(privateKey));
}

export async function sign(
  message: Hash,
  privateKey: PrivateKey,
  domain: Domain
) {
  domain =
    domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  privateKey = toBigInt(privateKey);
  const messageValue = await hashToG2(message, domain);
  const signature = messageValue.multiply(privateKey);
  return signatureFromG2(signature);
}

export async function verify(
  message: Hash,
  publicKey: PublicKey,
  signature: Signature,
  domain: Domain
) {
  domain =
    domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  const publicKeyPoint = publicKeyToG1(publicKey).negative();
  const signaturePoint = signatureToG2(signature);
  try {
    const signaturePairing = pairing(signaturePoint, G1);
    const hashPairing = pairing(
      await hashToG2(message, domain),
      publicKeyPoint
    );
    const finalExponent = finalExponentiate(
      signaturePairing.multiply(hashPairing)
    );
    return finalExponent.equals(finalExponent.one);
  } catch {
    return false;
  }
}

export function aggregatePublicKeys(publicKeys: PublicKey[]) {
  if (publicKeys.length === 0) {
    throw new Error("Provide public keys which should be aggregated");
  }
  const aggregatedPublicKey = publicKeys.reduce(
    (sum, publicKey) => sum.add(publicKeyToG1(publicKey)),
    Z1
  );
  return publicKeyFromG1(aggregatedPublicKey);
}

export function aggregateSignatures(signatures: Signature[]) {
  if (signatures.length === 0) {
    throw new Error("Provide signatures which should be aggregated");
  }
  const aggregatedSignature = signatures.reduce(
    (sum, signature) => sum.add(signatureToG2(signature)),
    Z2
  );
  return signatureFromG2(aggregatedSignature);
}

export async function verifyMultiple(
  messages: Hash[],
  publicKeys: PublicKey[],
  signature: Signature,
  domain: Domain
) {
  domain =
    domain instanceof Uint8Array ? domain : toBytesBE(domain, DOMAIN_LENGTH);
  if (messages.length === 0) {
    throw new Error("Provide messsages which should be verified");
  }
  if (publicKeys.length !== messages.length) {
    throw new Error("Count of public keys should be the same as messages");
  }
  try {
    let producer = new Fp12().one;
    for (const message of new Set(messages)) {
      const groupPublicKey = messages.reduce(
        (groupPublicKey, m, i) =>
          m !== message
            ? groupPublicKey
            : groupPublicKey.add(publicKeyToG1(publicKeys[i])),
        Z1
      );
      producer = producer.multiply(pairing(
        await hashToG2(message, domain),
        groupPublicKey
      ) as Fp12);
    }
    producer = producer.multiply(pairing(
      signatureToG2(signature),
      G1.negative()
    ) as Fp12);
    const finalExponent = finalExponentiate(producer);
    return finalExponent.equals(finalExponent.one);
  } catch {
    return false;
  }
}
