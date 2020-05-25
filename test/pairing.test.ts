import * as bls from "..";
const G1 = bls.PointG1.BASE;
const G2 = bls.PointG2.BASE;
const CURVE_ORDER = bls.CURVE.r;

describe("pairing", () => {
  it("should create negative G1 pairing", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1.negate(), G2);
		expect(p1.multiply(p2)).toEqual(bls.Fq12.ONE);
  });
  it("should create negative G2 pairing", () => {
		const p2 = bls.pairing(G1.negate(), G2);
		const p3 = bls.pairing(G1, G2.negate());
		expect(p2).toEqual(p3);
  });
  it("should create proper pairing output order", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = p1.pow(CURVE_ORDER);
		expect(p2).toEqual(bls.Fq12.ONE);
  });
  it("should create right pairing with bilinearity on G1", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1.multiply(2n), G2);
		expect(p1.multiply(p1)).toEqual(p2);
  });
  it("pairing should not degenerate", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1.multiply(2n), G2);
		const p3 = bls.pairing(G1, G2.negate());
		expect(p1).not.toEqual(p2);
		expect(p1).not.toEqual(p3);
		expect(p2).not.toEqual(p3);
  });
  it("should create right pairing with bilinearity on G2", () => {
		const p1 = bls.pairing(G1, G2);
		const p2 = bls.pairing(G1, G2.multiply(2n));
		expect(p1.multiply(p1)).toEqual(p2);
  });
  it("should create right pairing composite check", () => {
		const p1 = bls.pairing(G1.multiply(37n), G2.multiply(27n));
		const p2 = bls.pairing(G1.multiply(999n), G2);
		expect(p1).toEqual(p2);
  });
});
