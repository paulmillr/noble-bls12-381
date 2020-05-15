import * as fc from "fast-check";
import { Point } from "../src/fields";
import { B, B2 } from "../src/utils";
import { Fp, Fp2 } from "../src";

const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time

describe("bls12-381 Point", () => {
  describe("Point with Fp coordinats", () => {
    it("Point equality", () => {
      fc.assert(
        fc.property(
          fc.array(fc.bigInt(1n, Fp.ORDER), 3, 3),
          fc.array(fc.bigInt(1n, Fp.ORDER), 3, 3),
          ([x1, y1, z1], [x2, y2, z2]) => {
            const p1 = new Point(new Fp(x1), new Fp(y1), new Fp(z1), Fp);
            const p2 = new Point(new Fp(x2), new Fp(y2), new Fp(z2), Fp);
            expect(p1.equals(p1)).toBe(true);
            expect(p2.equals(p2)).toBe(true);
            expect(p1.equals(p2)).toBe(false);
            expect(p2.equals(p1)).toBe(false);
          }
        ),
        {
          numRuns: NUM_RUNS
        }
      );
    });
    it("should be placed on curve vector 1", () => {
      const a = new Point(new Fp(0n), new Fp(1n), new Fp(0n), Fp);
      expect(a.isOnCurve(B)).toBe(true);
    });
    it("should be placed on curve vector 2", () => {
      const a = new Point(
        new Fp(
          0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn
        ),
        new Fp(
          0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
        ),
        new Fp(1n),
        Fp
      );
      expect(a.isOnCurve(B)).toBe(true);
    });
    it("should be placed on curve vector 3", () => {
      const a = new Point(
        new Fp(
          3924344720014921989021119511230386772731826098545970939506931087307386672210285223838080721449761235230077903044877n
        ),
        new Fp(
          849807144208813628470408553955992794901182511881745746883517188868859266470363575621518219643826028639669002210378n
        ),
        new Fp(
          3930721696149562403635400786075999079293412954676383650049953083395242611527429259758704756726466284064096417462642n
        ),
        Fp
      );
      expect(a.isOnCurve(B)).toBe(true);
    });
    it("should not be placed on curve vector 1", () => {
      const a = new Point(new Fp(0n), new Fp(1n), new Fp(1n), Fp);
      expect(a.isOnCurve(B)).toBe(false);
    });
    it("should not be placed on curve vector 2", () => {
      const a = new Point(
        new Fp(
          0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6ban
        ),
        new Fp(
          0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
        ),
        new Fp(1n),
        Fp
      );
      expect(a.isOnCurve(B)).toBe(false);
    });
    it("should not be placed on curve vector 3", () => {
      const a = new Point(
        new Fp(
          0x034a6fce17d489676fb0a38892584cb4720682fe47c6dc2e058811e7ba4454300c078d0d7d8a147a294b8758ef846ccan
        ),
        new Fp(
          0x14e4b429606d02bc3c604c0410e5fc01d6093a00bb3e2bc9395952af0b6a0dbd599a8782a1bea48a2aa4d8e1b1df7caan
        ),
        new Fp(
          0x1167e903c75541e3413c61dae83b15c9f9ebc12baba015ec01b63196580967dba0798e89451115c8195446528d8bcfcan
        ),
        Fp
      );
      expect(a.isOnCurve(B)).toBe(false);
    });
    it("should be doubled and placed on curve vector 1", () => {
      const a = new Point(
        new Fp(
          0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn
        ),
        new Fp(
          0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
        ),
        new Fp(1n),
        Fp
      );
      const double = a.double();
      expect(double.isOnCurve(B)).toBe(true);
      expect(double).toEqual(
        new Point(
          new Fp(
            0x5dff4ac6726c6cb9b6d4dac3f33e92c062e48a6104cc52f6e7f23d4350c60bd7803e16723f9f1478a13c2b29f4325adn
          ),
          new Fp(
            0x14e4b429606d02bc3c604c0410e5fc01d6093a00bb3e2bc9395952af0b6a0dbd599a8782a1bea48a2aa4d8e1b1df7ca5n
          ),
          new Fp(
            0x430df56ea4aba6928180e61b1f2cb8f962f5650798fdf279a55bee62edcdb27c04c720ae01952ac770553ef06aadf22n
          ),
          Fp
        )
      );
      expect(double).toEqual(a.multiply(2n));
      expect(double).toEqual(a.add(a));
    });
    it("should be pdoubled and laced on curve vector 2", () => {
      const a = new Point(
        new Fp(
          3924344720014921989021119511230386772731826098545970939506931087307386672210285223838080721449761235230077903044877n
        ),
        new Fp(
          849807144208813628470408553955992794901182511881745746883517188868859266470363575621518219643826028639669002210378n
        ),
        new Fp(
          3930721696149562403635400786075999079293412954676383650049953083395242611527429259758704756726466284064096417462642n
        ),
        Fp
      );
      const double = a.double();
      expect(double.isOnCurve(B)).toBe(true);
      expect(double).toEqual(
        new Point(
          new Fp(
            1434314241472461137481482360511979492412320309040868403221478633648864894222507584070840774595331376671376457941809n
          ),
          new Fp(
            1327071823197710441072036380447230598536236767385499051709001927612351186086830940857597209332339198024189212158053n
          ),
          new Fp(
            3846649914824545670119444188001834433916103346657636038418442067224470303304147136417575142846208087722533543598904n
          ),
          Fp
        )
      );
      expect(double).toEqual(a.multiply(2n));
      expect(double).toEqual(a.add(a));
    });
  });
  describe("Point with Fp2 coordinats", () => {
    it("Point equality", () => {
      fc.assert(
        fc.property(
          fc.array(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), 3, 3),
          fc.array(fc.array(fc.bigInt(1n, Fp.ORDER), 2, 2), 3, 3),
          ([x1, y1, z1], [x2, y2, z2]) => {
            const p1 = new Point(
              new Fp2(...x1),
              new Fp2(...y1),
              new Fp2(...z1),
              Fp2
            );
            const p2 = new Point(
              new Fp2(...x2),
              new Fp2(...y2),
              new Fp2(...z2),
              Fp2
            );
            expect(p1.equals(p1)).toBe(true);
            expect(p2.equals(p2)).toBe(true);
            expect(p1.equals(p2)).toBe(false);
            expect(p2.equals(p1)).toBe(false);
          }
        ),
        {
          numRuns: NUM_RUNS
        }
      );
    });
    it("should be placed on curve vector 1", () => {
      const a = new Point(
        new Fp2(0n, 0n),
        new Fp2(1n, 0n),
        new Fp2(0n, 0n),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(true);
    });
    it("should be placed on curve vector 2", () => {
      const a = new Point(
        new Fp2(
          0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
          0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en
        ),
        new Fp2(
          0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
          0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben
        ),
        new Fp2(1n, 0n),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(true);
    });
    it("should be placed on curve vector 3", () => {
      const a = new Point(
        new Fp2(
          1050910533020938551374635094591786195161318899082245208049526631521590440770333461074893697611276887218497078796422n,
          1598996588129879649144273449445099511963892936268948685794588663059536473334389899700849905658337146716739117116278n
        ),
        new Fp2(
          2297925586785011392322632866903098777630933241582428655157725630032766380748347103951287973711001282071754690744592n,
          2722692942832192263619429510118606113750284957310697940719148392728935618099339326005363048966551031941723480961950n
        ),
        new Fp2(
          76217213143079476655331517031477221909850679220115226933444440112284563392888424587575503026751093730973752137345n,
          651517437191775294694379224746298241572865421785132086369822391079440481283732426567988496860904675941017132063964n
        ),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(true);
    });
    it("should not be placed on curve vector 1", () => {
      const a = new Point(
        new Fp2(0n, 0n),
        new Fp2(1n, 0n),
        new Fp2(1n, 0n),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(false);
    });
    it("should not be placed on curve vector 2", () => {
      const a = new Point(
        new Fp2(
          0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4410b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
          0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en
        ),
        new Fp2(
          0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d229a695160d12c923ac9cc3baca289e193548608b82801n,
          0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben
        ),
        new Fp2(1n, 0n),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(false);
    });
    it("should not be placed on curve vector 3", () => {
      const a = new Point(
        new Fp2(
          0x877d52dd65245f8908a03288adcd396f489ef87ae23fe110c5aa48bc208fbd1a0ed403df5b1ac137922b915f1f38ec37n,
          0x0cf8158b9e689553d58194f79863fe02902c5f169f0d4ddf46e23f15bb4f24304a8e26f1e5febc57b750d1c3dc4261d8n
        ),
        new Fp2(
          0x065ae9215806e8a55fd2d9ec4af9d2d448599cdb85d9080b2c9b4766434c33d103730c92c30a69d0602a8804c2a7c65fn,
          0x0e9c342d8a6d4b3a1cbd02c7bdc0e0aa304de41a04569ae33184419e66bbc0271c361c973962955ba6405f0e51beb98bn
        ),
        new Fp2(
          0x19cbaa4ee4fadc2319939b8db45c6a355bfb3755197ba74eda8534d2a2c1a2592475939877594513c326a90c11705002n,
          0x0c0d89405d4e69986559a56057851733967c50fd0b4ec75e4ce92556ae5d33567e6e1a4eb9d83b4355520ebfe0bef37cn
        ),
        Fp2
      );
      expect(a.isOnCurve(B2)).toBe(false);
    });
  });
  it("should be doubled and placed on curve vector 1", () => {
    const a = new Point(
      new Fp2(
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en
      ),
      new Fp2(
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben
      ),
      new Fp2(1n, 0n),
      Fp2
    );
    const double = a.double();
    expect(double.isOnCurve(B2)).toBe(true);
    expect(double).toEqual(
      new Point(
        new Fp2(
          2004569552561385659566932407633616698939912674197491321901037400001042336021538860336682240104624979660689237563240n,
          3955604752108186662342584665293438104124851975447411601471797343177761394177049673802376047736772242152530202962941n
        ),
        new Fp2(
          978142457653236052983988388396292566217089069272380812666116929298652861694202207333864830606577192738105844024927n,
          2248711152455689790114026331322133133284196260289964969465268080325775757898907753181154992709229860715480504777099n
        ),
        new Fp2(
          3145673658656250241340817105688138628074744674635286712244193301767486380727788868972774468795689607869551989918920n,
          968254395890002185853925600926112283510369004782031018144050081533668188797348331621250985545304947843412000516197n
        ),
        Fp2
      )
    );
    expect(double).toEqual(a.multiply(2n));
    expect(double).toEqual(a.add(a));
  });
  it("should be doubled and placed on curve vector 2", () => {
    const a = new Point(
      new Fp2(
        1050910533020938551374635094591786195161318899082245208049526631521590440770333461074893697611276887218497078796422n,
        1598996588129879649144273449445099511963892936268948685794588663059536473334389899700849905658337146716739117116278n
      ),
      new Fp2(
        2297925586785011392322632866903098777630933241582428655157725630032766380748347103951287973711001282071754690744592n,
        2722692942832192263619429510118606113750284957310697940719148392728935618099339326005363048966551031941723480961950n
      ),
      new Fp2(
        76217213143079476655331517031477221909850679220115226933444440112284563392888424587575503026751093730973752137345n,
        651517437191775294694379224746298241572865421785132086369822391079440481283732426567988496860904675941017132063964n
      ),
      Fp2
    );
    const double = a.double();
    expect(double.isOnCurve(B2)).toBe(true);
    expect(double).toEqual(
      new Point(
        new Fp2(
          971534195338026376106694691801988868863420444490100454506033572314651086872437977861235872590578590756720024471469n,
          378014958429131328675394810343769919858050810498061656943526952326849391332443820094459004368687076347500373099156n
        ),
        new Fp2(
          3280997195265200639128448910548139455469442645584276216556357555470480677955454794092224549507347100925189702190894n,
          158426171401258191330058082816753806149755104529779342689180332371855591641984107207983953003313468624083823672075n
        ),
        new Fp2(
          3008329035346660988655239603307628288451385710327841564719334330531972476116399444025767153235631811081036738463342n,
          3341599904620117102667473563202270732934028545405889777934923014103677543378240279263895401928203318430834551303601n
        ),
        Fp2
      )
    );
    expect(double).toEqual(a.multiply(2n));
    expect(double).toEqual(a.add(a));
  });
});
