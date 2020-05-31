"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.PointG1 = exports.hash_to_field = exports.Fq12 = exports.Fq6 = exports.Fq2 = exports.Fq = exports.DST_LABEL = exports.CURVE = void 0;
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    h: 0x396c8c005555e1568c00aaab0000aaabn,
    Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
    b: 4n,
    P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn **
        2n -
        1n,
    h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
    G2x: [
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
    ],
    G2y: [
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
    ],
    b2: [4n, 4n],
    BLS_X: 0xd201000000010000n,
};
const P = exports.CURVE.P;
exports.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
function gen_pow(cls, elm, n) {
    if (n === 0n)
        return cls.ONE;
    if (n === 1n)
        return elm;
    let p = cls.ONE;
    let d = elm;
    while (n > 0n) {
        if (n & 1n)
            p = p.multiply(d);
        n >>= 1n;
        d = d.square();
    }
    return p;
}
function gen_div(elm, rhs) {
    const inv = typeof rhs === 'bigint' ? new Fq(rhs).invert().value : rhs.invert();
    return elm.multiply(inv);
}
function gen_inv_batch(cls, nums) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = cls.ONE;
    for (let i = 0; i < len; i++) {
        if (nums[i].isZero())
            continue;
        scratch[i] = acc;
        acc = acc.multiply(nums[i]);
    }
    acc = acc.invert();
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i].isZero())
            continue;
        let tmp = acc.multiply(nums[i]);
        nums[i] = acc.multiply(scratch[i]);
        acc = tmp;
    }
    return nums;
}
function bitLen(n) {
    let len;
    for (len = 0; n > 0n; n >>= 1n, len += 1)
        ;
    return len;
}
function bitGet(n, pos) {
    return n >> BigInt(pos) & 1n;
}
const BLS_X_LEN = bitLen(exports.CURVE.BLS_X);
let Fq = (() => {
    class Fq {
        constructor(value) {
            this._value = mod(value, Fq.ORDER);
        }
        get value() {
            return this._value;
        }
        isZero() {
            return this._value === 0n;
        }
        equals(rhs) {
            return this._value === rhs._value;
        }
        negate() {
            return new Fq(-this._value);
        }
        invert() {
            let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n];
            let a = Fq.ORDER;
            let b = this.value;
            let q;
            while (a !== 0n) {
                [q, b, a] = [b / a, a, b % a];
                [x0, x1] = [x1, x0 - q * x1];
                [y0, y1] = [y1, y0 - q * y1];
            }
            return new Fq(x0);
        }
        add(rhs) {
            return new Fq(this._value + rhs.value);
        }
        square() {
            return new Fq(this._value * this._value);
        }
        pow(n) {
            return new Fq(powMod(this._value, n, Fq.ORDER));
        }
        subtract(rhs) {
            return new Fq(this._value - rhs._value);
        }
        multiply(rhs) {
            if (rhs instanceof Fq)
                rhs = rhs.value;
            return new Fq(this._value * rhs);
        }
        div(rhs) { return gen_div(this, rhs); }
        toString() {
            const str = this.value.toString(16).padStart(96, '0');
            return str.slice(0, 2) + '.' + str.slice(-2);
        }
    }
    Fq.ORDER = exports.CURVE.P;
    Fq.MAX_BITS = bitLen(exports.CURVE.P);
    Fq.ZERO = new Fq(0n);
    Fq.ONE = new Fq(1n);
    return Fq;
})();
exports.Fq = Fq;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
let Fq2 = (() => {
    class Fq2 {
        constructor(tuple) {
            if (tuple.length !== 2)
                throw new Error(`Expected array with 2 elements`);
            let [c0, c1] = tuple;
            this.c0 = typeof c0 === 'bigint' ? new Fq(c0) : c0;
            this.c1 = typeof c1 === 'bigint' ? new Fq(c1) : c1;
        }
        get real() { return this.c0; }
        get imag() { return this.c1; }
        get value() { return [this.c0.value, this.c1.value]; }
        toString() { return `Fq2(${this.c0} + ${this.c1}×i)`; }
        isZero() { return this.c0.isZero() && this.c1.isZero(); }
        equals(rhs) { return this.c0.equals(rhs.c0) && this.c1.equals(rhs.c1); }
        negate() { return new Fq2([this.c0.negate(), this.c1.negate()]); }
        add(rhs) { return new Fq2([this.c0.add(rhs.c0), this.c1.add(rhs.c1)]); }
        subtract(rhs) { return new Fq2([this.c0.subtract(rhs.c0), this.c1.subtract(rhs.c1)]); }
        conjugate() { return new Fq2([this.c0, this.c1.negate()]); }
        pow(n) { return gen_pow(Fq2, this, n); }
        div(rhs) { return gen_div(this, rhs); }
        multiply(rhs) {
            if (typeof rhs === 'bigint')
                return new Fq2([this.c0.multiply(rhs), this.c1.multiply(rhs)]);
            const [{ c0, c1 }, { c0: r0, c1: r1 }] = [this, rhs];
            let t1 = c0.multiply(r0);
            let t2 = c1.multiply(r1);
            return new Fq2([t1.subtract(t2), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2))]);
        }
        mulByNonresidue() {
            return new Fq2([this.c0.subtract(this.c1), this.c0.add(this.c1)]);
        }
        square() {
            const a = this.real.add(this.imag);
            const b = this.real.subtract(this.imag);
            const c = this.real.add(this.real);
            return new Fq2([a.multiply(b), c.multiply(this.imag)]);
        }
        sqrt() {
            const candidateSqrt = this.pow((Fq2.ORDER + 8n) / 16n);
            const check = candidateSqrt.square().div(this);
            const R = Fq2.ROOTS_OF_UNITY;
            const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
            if (!divisor)
                return undefined;
            const index = R.indexOf(divisor);
            const root = R[index / 2];
            if (!root)
                throw new Error('Invalid root');
            const x1 = candidateSqrt.div(root);
            const x2 = x1.negate();
            const [x1_re, x1_im] = x1.value;
            const [x2_re, x2_im] = x2.value;
            if (x1_im > x2_im || (x1_im == x2_im && x1_re > x2_re))
                return x1;
            return x2;
        }
        invert() {
            const [a, b] = this.value;
            const factor = new Fq(a * a + b * b).invert();
            return new Fq2([factor.multiply(new Fq(a)), factor.multiply(new Fq(-b))]);
        }
        frobeniusMap(power) {
            return new Fq2([this.c0, this.c1.multiply(Fq2.FROBENIUS_COEFFICIENTS[power % 2])]);
        }
        multiplyByB() {
            let { c0, c1 } = this;
            let t0 = c0.multiply(4n);
            let t1 = c1.multiply(4n);
            return new Fq2([t0.subtract(t1), t0.add(t1)]);
        }
    }
    Fq2.ORDER = exports.CURVE.P2;
    Fq2.MAX_BITS = bitLen(exports.CURVE.P2);
    Fq2.ROOT = new Fq(-1n);
    Fq2.ZERO = new Fq2([0n, 0n]);
    Fq2.ONE = new Fq2([1n, 0n]);
    Fq2.COFACTOR = exports.CURVE.h2;
    Fq2.ROOTS_OF_UNITY = [
        new Fq2([1n, 0n]),
        new Fq2([rv1, -rv1]),
        new Fq2([0n, 1n]),
        new Fq2([rv1, rv1]),
        new Fq2([-1n, 0n]),
        new Fq2([-rv1, rv1]),
        new Fq2([0n, -1n]),
        new Fq2([-rv1, -rv1]),
    ];
    Fq2.ETAs = [
        new Fq2([ev1, ev2]),
        new Fq2([-ev2, ev1]),
        new Fq2([ev3, ev4]),
        new Fq2([-ev4, ev3]),
    ];
    Fq2.FROBENIUS_COEFFICIENTS = [
        new Fq(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n),
        new Fq(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan),
    ];
    return Fq2;
})();
exports.Fq2 = Fq2;
let Fq6 = (() => {
    class Fq6 {
        constructor(c0, c1, c2) {
            this.c0 = c0;
            this.c1 = c1;
            this.c2 = c2;
        }
        static from_tuple(t) {
            return new Fq6(new Fq2(t.slice(0, 2)), new Fq2(t.slice(2, 4)), new Fq2(t.slice(4, 6)));
        }
        toString() { return `Fq6(${this.c0} + ${this.c1} * v, ${this.c2} * v^2)`; }
        isZero() { return this.c0.isZero() && this.c1.isZero() && this.c2.isZero(); }
        negate() { return new Fq6(this.c0.negate(), this.c1.negate(), this.c2.negate()); }
        equals(rhs) { return this.c0.equals(rhs.c0) && this.c1.equals(rhs.c1) && this.c2.equals(rhs.c2); }
        add(rhs) { return new Fq6(this.c0.add(rhs.c0), this.c1.add(rhs.c1), this.c2.add(rhs.c2)); }
        subtract(rhs) { return new Fq6(this.c0.subtract(rhs.c0), this.c1.subtract(rhs.c1), this.c2.subtract(rhs.c2)); }
        div(rhs) { return gen_div(this, rhs); }
        pow(n) { return gen_pow(Fq6, this, n); }
        multiply(rhs) {
            if (typeof rhs === 'bigint')
                return new Fq6(this.c0.multiply(rhs), this.c1.multiply(rhs), this.c2.multiply(rhs));
            let [{ c0, c1, c2 }, { c0: r0, c1: r1, c2: r2 }] = [this, rhs];
            let t0 = c0.multiply(r0);
            let t1 = c1.multiply(r1);
            let t2 = c2.multiply(r2);
            return new Fq6(t0.add(c1.add(c2).multiply(r1.add(r2)).subtract(t1.add(t2)).mulByNonresidue()), c0.add(c1).multiply(r0.add(r1)).subtract(t0.add(t1)).add(t2.mulByNonresidue()), t1.add(c0.add(c2).multiply(r0.add(r2)).subtract(t0.add(t2))));
        }
        mulByNonresidue() { return new Fq6(this.c2.mulByNonresidue(), this.c0, this.c1); }
        multiplyBy1(b1) {
            return new Fq6(this.c2.multiply(b1).mulByNonresidue(), this.c0.multiply(b1), this.c1.multiply(b1));
        }
        multiplyBy01(b0, b1) {
            let { c0, c1, c2 } = this;
            let t0 = c0.multiply(b0);
            let t1 = c1.multiply(b1);
            return new Fq6(c1.add(c2).multiply(b1).subtract(t1).mulByNonresidue().add(t0), b0.add(b1).multiply(c0.add(c1)).subtract(t0).subtract(t1), c0.add(c2).multiply(b0).subtract(t0).add(t1));
        }
        square() {
            let { c0, c1, c2 } = this;
            let t0 = c0.square();
            let t1 = c0.multiply(c1).multiply(2n);
            let t3 = c1.multiply(c2).multiply(2n);
            let t4 = c2.square();
            return new Fq6(t3.mulByNonresidue().add(t0), t4.mulByNonresidue().add(t1), t1.add(c0.subtract(c1).add(c2).square()).add(t3).subtract(t0).subtract(t4));
        }
        invert() {
            let { c0, c1, c2 } = this;
            let t0 = c0.square().subtract(c2.multiply(c1).mulByNonresidue());
            let t1 = c2.square().mulByNonresidue().subtract(c0.multiply(c1));
            let t2 = c1.square().subtract(c0.multiply(c2));
            let t4 = c2.multiply(t1).add(c1.multiply(t2)).mulByNonresidue().add(c0.multiply(t0)).invert();
            return new Fq6(t4.multiply(t0), t4.multiply(t1), t4.multiply(t2));
        }
        frobeniusMap(power) {
            return new Fq6(this.c0.frobeniusMap(power), this.c1.frobeniusMap(power).multiply(Fq6.FROBENIUS_COEFFICIENTS_1[power % 6]), this.c2.frobeniusMap(power).multiply(Fq6.FROBENIUS_COEFFICIENTS_2[power % 6]));
        }
    }
    Fq6.ZERO = new Fq6(Fq2.ZERO, Fq2.ZERO, Fq2.ZERO);
    Fq6.ONE = new Fq6(Fq2.ONE, Fq2.ZERO, Fq2.ZERO);
    Fq6.FROBENIUS_COEFFICIENTS_1 = [
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
            0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn]),
        new Fq2([0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n]),
        new Fq2([0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n,
            0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen]),
    ];
    Fq6.FROBENIUS_COEFFICIENTS_2 = [
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
    ];
    return Fq6;
})();
exports.Fq6 = Fq6;
let Fq12 = (() => {
    class Fq12 {
        constructor(c0, c1) {
            this.c0 = c0;
            this.c1 = c1;
        }
        static from_tuple(t) {
            return new Fq12(Fq6.from_tuple(t.slice(0, 6)), Fq6.from_tuple(t.slice(6, 12)));
        }
        get value() { return [this.c0, this.c1]; }
        toString() { return `Fq12(${this.c0} + ${this.c1} * w)`; }
        isZero() { return this.c0.isZero() && this.c1.isZero(); }
        equals(rhs) { return this.c0.equals(rhs.c0) && this.c1.equals(rhs.c1); }
        negate() { return new Fq12(this.c0.negate(), this.c1.negate()); }
        add(rhs) { return new Fq12(this.c0.add(rhs.c0), this.c1.add(rhs.c1)); }
        subtract(rhs) { return new Fq12(this.c0.subtract(rhs.c0), this.c1.subtract(rhs.c1)); }
        conjugate() { return new Fq12(this.c0, this.c1.negate()); }
        pow(n) { return gen_pow(Fq12, this, n); }
        div(rhs) { return gen_div(this, rhs); }
        multiply(rhs) {
            if (typeof rhs === 'bigint')
                return new Fq12(this.c0.multiply(rhs), this.c1.multiply(rhs));
            let [{ c0, c1 }, { c0: r0, c1: r1 }] = [this, rhs];
            let t1 = c0.multiply(r0);
            let t2 = c1.multiply(r1);
            return new Fq12(t1.add(t2.mulByNonresidue()), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)));
        }
        multiplyBy014(o0, o1, o4) {
            let { c0, c1 } = this;
            let [t0, t1] = [c0.multiplyBy01(o0, o1), c1.multiplyBy1(o4)];
            return new Fq12(t1.mulByNonresidue().add(t0), c1.add(c0).multiplyBy01(o0, o1.add(o4)).subtract(t0).subtract(t1));
        }
        square() {
            let { c0, c1 } = this;
            let ab = c0.multiply(c1);
            return new Fq12(c1.mulByNonresidue().add(c0).multiply(c0.add(c1)).subtract(ab).subtract(ab.mulByNonresidue()), ab.add(ab));
        }
        invert() {
            let { c0, c1 } = this;
            let t = c0.square().subtract(c1.square().mulByNonresidue()).invert();
            return new Fq12(c0.multiply(t), c1.multiply(t).negate());
        }
        frobeniusMap(power) {
            const { c0, c1 } = this;
            let r0 = c0.frobeniusMap(power);
            let { c0: c1_0, c1: c1_1, c2: c1_2 } = c1.frobeniusMap(power);
            return new Fq12(r0, new Fq6(c1_0.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12]), c1_1.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12]), c1_2.multiply(Fq12.FROBENIUS_COEFFICIENTS[power % 12])));
        }
        Fq4Square(a, b) {
            const a2 = a.square(), b2 = b.square();
            return [
                b2.mulByNonresidue().add(a2),
                a.add(b).square().subtract(a2).subtract(b2)
            ];
        }
        cyclotomicSquare() {
            const { c0: { c0: c0c0, c1: c0c1, c2: c0c2 }, c1: { c0: c1c0, c1: c1c1, c2: c1c2 } } = this;
            let [t3, t4] = this.Fq4Square(c0c0, c1c1);
            let [t5, t6] = this.Fq4Square(c1c0, c0c2);
            let [t7, t8] = this.Fq4Square(c0c1, c1c2);
            let t9 = t8.mulByNonresidue();
            return new Fq12(new Fq6(t3.subtract(c0c0).multiply(2n).add(t3), t5.subtract(c0c1).multiply(2n).add(t5), t7.subtract(c0c2).multiply(2n).add(t7)), new Fq6(t9.add(c1c0).multiply(2n).add(t9), t4.add(c1c1).multiply(2n).add(t4), t6.add(c1c2).multiply(2n).add(t6)));
        }
        cyclotomicExp(n) {
            let z = Fq12.ONE;
            for (let i = BLS_X_LEN - 1; i >= 0; i--) {
                z = z.cyclotomicSquare();
                if (bitGet(n, i))
                    z = z.multiply(this);
            }
            return z;
        }
        finalExponentiate() {
            let t0 = this.frobeniusMap(6).div(this);
            let t1 = t0.frobeniusMap(2).multiply(t0);
            let t2 = t1.cyclotomicExp(exports.CURVE.BLS_X).conjugate();
            let t3 = t1.cyclotomicSquare().conjugate().multiply(t2);
            let t4 = t3.cyclotomicExp(exports.CURVE.BLS_X).conjugate();
            let t5 = t4.cyclotomicExp(exports.CURVE.BLS_X).conjugate();
            let t6 = t5.cyclotomicExp(exports.CURVE.BLS_X).conjugate().multiply(t2.cyclotomicSquare());
            return t2.multiply(t5).frobeniusMap(2)
                .multiply(t4.multiply(t1).frobeniusMap(3))
                .multiply(t6.multiply(t1.conjugate()).frobeniusMap(1))
                .multiply(t6.cyclotomicExp(exports.CURVE.BLS_X).conjugate())
                .multiply(t3.conjugate())
                .multiply(t1);
        }
    }
    Fq12.ZERO = new Fq12(Fq6.ZERO, Fq6.ZERO);
    Fq12.ONE = new Fq12(Fq6.ONE, Fq6.ZERO);
    Fq12.FROBENIUS_COEFFICIENTS = [
        new Fq2([0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
            0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n]),
        new Fq2([0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
            0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n]),
        new Fq2([0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
            0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n]),
        new Fq2([0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
            0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n]),
        new Fq2([0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
            0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n]),
        new Fq2([0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
            0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n]),
        new Fq2([0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
            0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n]),
    ];
    return Fq12;
})();
exports.Fq12 = Fq12;
class ProjectivePoint {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    isZero() {
        return this.z.isZero();
    }
    getPoint(x, y, z) {
        return new this.constructor(x, y, z);
    }
    getZero() {
        return this.getPoint(this.C.ONE, this.C.ONE, this.C.ZERO);
    }
    equals(rhs) {
        if (this.constructor != rhs.constructor)
            throw new Error(`ProjectivePoint#equals: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const a = this;
        const b = rhs;
        const xe = a.x.multiply(b.z).equals(b.x.multiply(a.z));
        const ye = a.y.multiply(b.z).equals(b.y.multiply(a.z));
        return xe && ye;
    }
    negate() {
        return this.getPoint(this.x, this.y.negate(), this.z);
    }
    toString(isAffine = true) {
        if (!isAffine) {
            return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
        }
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
    }
    fromAffineTuple(xy) {
        return this.getPoint(xy[0], xy[1], this.C.ONE);
    }
    toAffine(invZ = this.z.invert()) {
        return [this.x.multiply(invZ), this.y.multiply(invZ)];
    }
    toAffineBatch(points) {
        const toInv = gen_inv_batch(this.C, points.map(p => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    normalizeZ(points) {
        return this.toAffineBatch(points).map(t => this.fromAffineTuple(t));
    }
    double() {
        const { x, y, z } = this;
        const W = x.multiply(x).multiply(3n);
        const S = y.multiply(z);
        const SS = S.multiply(S);
        const SSS = SS.multiply(S);
        const B = x.multiply(y).multiply(S);
        const H = W.multiply(W).subtract(B.multiply(8n));
        const X3 = H.multiply(S).multiply(2n);
        const Y3 = W.multiply(B.multiply(4n).subtract(H)).subtract(y.multiply(y).multiply(8n).multiply(SS));
        const Z3 = SSS.multiply(8n);
        return this.getPoint(X3, Y3, Z3);
    }
    add(rhs) {
        if (this.constructor != rhs.constructor)
            throw new Error(`ProjectivePoint#add: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const p1 = this;
        const p2 = rhs;
        if (p1.isZero())
            return p2;
        if (p2.isZero())
            return p1;
        const X1 = p1.x;
        const Y1 = p1.y;
        const Z1 = p1.z;
        const X2 = p2.x;
        const Y2 = p2.y;
        const Z2 = p2.z;
        const U1 = Y2.multiply(Z1);
        const U2 = Y1.multiply(Z2);
        const V1 = X2.multiply(Z1);
        const V2 = X1.multiply(Z2);
        if (V1.equals(V2) && U1.equals(U2))
            return this.double();
        if (V1.equals(V2))
            return this.getZero();
        const U = U1.subtract(U2);
        const V = V1.subtract(V2);
        const VV = V.multiply(V);
        const VVV = VV.multiply(V);
        const V2VV = V2.multiply(VV);
        const W = Z1.multiply(Z2);
        const A = U.multiply(U).multiply(W).subtract(VVV).subtract(V2VV.multiply(2n));
        const X3 = V.multiply(A);
        const Y3 = U.multiply(V2VV.subtract(A)).subtract(VVV.multiply(U2));
        const Z3 = VVV.multiply(W);
        return this.getPoint(X3, Y3, Z3);
    }
    subtract(rhs) {
        if (this.constructor != rhs.constructor)
            throw new Error(`ProjectivePoint#subtract: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        return this.add(rhs.negate());
    }
    multiplyUnsafe(scalar) {
        let n = scalar;
        if (n instanceof Fq)
            n = n.value;
        if (typeof n === 'number')
            n = BigInt(n);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        let p = this.getZero();
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }
    maxBits() {
        return this.C.MAX_BITS;
    }
    precomputeWindow(W) {
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        let points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < windowSize; i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    calcMultiplyPrecomputes(W) {
        if (this.multiply_precomputes)
            throw new Error('This point already has precomputes');
        this.multiply_precomputes = [W, this.normalizeZ(this.precomputeWindow(W))];
    }
    clearMultiplyPrecomputes() {
        this.multiply_precomputes = undefined;
    }
    wNAF(n) {
        let W, precomputes;
        if (this.multiply_precomputes) {
            [W, precomputes] = this.multiply_precomputes;
        }
        else {
            W = 1;
            precomputes = this.precomputeWindow(W);
        }
        let [p, f] = [this.getZero(), this.getZero()];
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += 1n;
            }
            if (wbits === 0) {
                f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
            }
            else {
                const cached = precomputes[offset + Math.abs(wbits) - 1];
                p = p.add(wbits < 0 ? cached.negate() : cached);
            }
        }
        return [p, f];
    }
    multiply(scalar) {
        let n = scalar;
        if (n instanceof Fq)
            n = n.value;
        if (typeof n === 'number')
            n = BigInt(n);
        if (n <= 0)
            throw new Error('ProjectivePoint#multiply: invalid scalar, expected positive integer');
        if (bitLen(n) > this.maxBits())
            throw new Error("ProjectivePoint#multiply: scalar has more bits than maxBits, shoulnd't happen");
        return this.wNAF(n)[0];
    }
}
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32n;
async function sha256(message) {
    if (typeof window == 'object' && 'crypto' in window) {
        const buffer = await window.crypto.subtle.digest('SHA-256', message.buffer);
        return new Uint8Array(buffer);
    }
    else if (typeof process === 'object' && 'node' in process.versions) {
        const { createHash } = require('crypto');
        const hash = createHash('sha256');
        hash.update(message);
        return Uint8Array.from(hash.digest());
    }
    else {
        throw new Error("The environment doesn't have sha256 function");
    }
}
function fromHexBE(hex) {
    return BigInt(`0x${hex}`);
}
function fromBytesBE(bytes) {
    if (typeof bytes === 'string') {
        return fromHexBE(bytes);
    }
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function padStart(bytes, count, element) {
    if (bytes.length >= count) {
        return bytes;
    }
    const diff = count - bytes.length;
    const elements = Array(diff)
        .fill(element)
        .map((i) => i);
    return concatTypedArrays(new Uint8Array(elements), bytes);
}
function toBytesBE(num, padding = 0) {
    let hex = typeof num === 'string' ? num : num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length && i < len * 2; i += 2, j++) {
        u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return padStart(u8, padding, 0);
}
function toBigInt(num) {
    if (typeof num === 'string') {
        return fromHexBE(num);
    }
    if (typeof num === 'number') {
        return BigInt(num);
    }
    if (num instanceof Uint8Array) {
        return fromBytesBE(num);
    }
    return num;
}
function hexToArray(hex) {
    if (!hex.length)
        return new Uint8Array([]);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
        result[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return result;
}
function concatTypedArrays(...bytes) {
    return new Uint8Array(bytes.reduce((res, bytesView) => {
        bytesView = bytesView instanceof Uint8Array ? bytesView : hexToArray(bytesView);
        return [...res, ...bytesView];
    }, []));
}
function mod(a, b) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
function powMod(a, power, m) {
    let res = 1n;
    while (power > 0n) {
        if (power & 1n) {
            res = mod(res * a, m);
        }
        power >>= 1n;
        a = mod(a * a, m);
    }
    return res;
}
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}
function os2ip(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result;
}
function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}
function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
    }
    return arr;
}
const xnum = [
    new Fq2([
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    ]),
    new Fq2([
        0x0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
    ]),
    new Fq2([
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
    ]),
    new Fq2([
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0x0n,
    ]),
];
const xden = [
    new Fq2([
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
    ]),
    new Fq2([
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
    ]),
    Fq2.ONE,
    Fq2.ZERO,
];
const ynum = [
    new Fq2([
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    ]),
    new Fq2([
        0x0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
    ]),
    new Fq2([
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
    ]),
    new Fq2([
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0x0n,
    ]),
];
const yden = [
    new Fq2([
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    ]),
    new Fq2([
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
    ]),
    new Fq2([
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
    ]),
    new Fq2([0x1n, 0x0n]),
];
const isoCoefficients = [xnum, xden, ynum, yden];
function isogenyMapG2(xyz) {
    const [x, y, z] = xyz;
    const mapped = [Fq2.ZERO, Fq2.ZERO, Fq2.ZERO, Fq2.ZERO];
    const zPowers = [z, z.pow(2n), z.pow(3n)];
    for (let i = 0; i < isoCoefficients.length; i++) {
        const k_i = isoCoefficients[i];
        mapped[i] = k_i.slice(-1)[0];
        const arr = k_i.slice(0, -1).reverse();
        for (let j = 0; j < arr.length; j++) {
            const k_i_j = arr[j];
            mapped[i] = mapped[i].multiply(x).add(zPowers[j].multiply(k_i_j));
        }
    }
    mapped[2] = mapped[2].multiply(y);
    mapped[3] = mapped[3].multiply(z);
    const z2 = mapped[1].multiply(mapped[3]);
    const x2 = mapped[0].multiply(mapped[3]);
    const y2 = mapped[1].multiply(mapped[2]);
    return new PointG2(x2, y2, z2);
}
async function expand_message_xmd(msg, DST, len_in_bytes) {
    const H = sha256;
    const b_in_bytes = Number(SHA256_DIGEST_SIZE);
    const r_in_bytes = b_in_bytes * 2;
    const ell = Math.ceil(len_in_bytes / b_in_bytes);
    if (ell > 255)
        throw new Error('Invalid xmd length');
    const DST_prime = concatTypedArrays(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(len_in_bytes, 2);
    const b = new Array(ell);
    const b_0 = await H(concatTypedArrays(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = await H(concatTypedArrays(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = await H(concatTypedArrays(...args));
    }
    const pseudo_random_bytes = concatTypedArrays(...b);
    return pseudo_random_bytes.slice(0, len_in_bytes);
}
async function hash_to_field(msg, degree, isRandomOracle = true) {
    const count = isRandomOracle ? 2 : 1;
    const m = degree;
    const L = 64;
    const len_in_bytes = count * m * L;
    const DST = stringToBytes(exports.DST_LABEL);
    const pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes);
    const u = new Array(count);
    for (let i = 0; i < count; i++) {
        const e = new Array(m);
        for (let j = 0; j < m; j++) {
            const elm_offset = L * (j + i * m);
            const tv = pseudo_random_bytes.slice(elm_offset, elm_offset + L);
            e[j] = mod(os2ip(tv), exports.CURVE.P);
        }
        u[i] = e;
    }
    return u;
}
exports.hash_to_field = hash_to_field;
function sgn0(x) {
    const [x0, x1] = x.value;
    const sign_0 = x0 % 2n;
    const zero_0 = x0 === 0n;
    const sign_1 = x1 % 2n;
    return BigInt(sign_0 || (zero_0 && sign_1));
}
const P_MINUS_9_DIV_16 = (P ** 2n - 9n) / 16n;
function sqrt_div_fq2(u, v) {
    const uv7 = u.multiply(v.pow(7n));
    const uv15 = uv7.multiply(v.pow(8n));
    const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
    let success = false;
    let result = gamma;
    const positiveRootsOfUnity = Fq2.ROOTS_OF_UNITY.slice(0, 4);
    for (const root of positiveRootsOfUnity) {
        const candidate = root.multiply(gamma);
        if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
            success = true;
            result = candidate;
        }
    }
    return [success, result];
}
function map_to_curve_SSWU_G2(t) {
    const iso_3_a = new Fq2([0n, 240n]);
    const iso_3_b = new Fq2([1012n, 1012n]);
    const iso_3_z = new Fq2([-2n, -1n]);
    if (Array.isArray(t))
        t = new Fq2(t);
    const t2 = t.pow(2n);
    const iso_3_z_t2 = iso_3_z.multiply(t2);
    const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
    let denominator = iso_3_a.multiply(ztzt).negate();
    let numerator = iso_3_b.multiply(ztzt.add(Fq2.ONE));
    if (denominator.isZero())
        denominator = iso_3_z.multiply(iso_3_a);
    let v = denominator.pow(3n);
    let u = numerator
        .pow(3n)
        .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
        .add(iso_3_b.multiply(v));
    const [success, sqrtCandidateOrGamma] = sqrt_div_fq2(u, v);
    let y;
    if (success)
        y = sqrtCandidateOrGamma;
    const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));
    u = iso_3_z_t2.pow(3n).multiply(u);
    let success2 = false;
    for (const eta of Fq2.ETAs) {
        const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
        const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
        if (temp.isZero() && !success && !success2) {
            y = etaSqrtCandidate;
            success2 = true;
        }
    }
    if (!success && !success2)
        throw new Error('Hash to Curve - Optimized SWU failure');
    if (success2)
        numerator = numerator.multiply(iso_3_z_t2);
    y = y;
    if (sgn0(t) !== sgn0(y))
        y = y.negate();
    y = y.multiply(denominator);
    return [numerator, y, denominator];
}
function normalizePrivKey(privateKey) {
    return new Fq(toBigInt(privateKey));
}
let PointG1 = (() => {
    class PointG1 extends ProjectivePoint {
        constructor(x, y, z) {
            super(x, y, z, Fq);
        }
        static fromCompressedHex(hex) {
            const compressedValue = fromBytesBE(hex);
            const bflag = mod(compressedValue, POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = mod(compressedValue, POW_2_381);
            const fullY = mod(x ** 3n + new Fq(exports.CURVE.b).value, P);
            let y = powMod(fullY, (P + 1n) / 4n, P);
            if (powMod(y, 2n, P) !== fullY) {
                throw new Error('The given point is not on G1: y**2 = x**3 + b');
            }
            const aflag = mod(compressedValue, POW_2_382) / POW_2_381;
            if ((y * 2n) / P !== aflag) {
                y = P - y;
            }
            const p = new PointG1(new Fq(x), new Fq(y), new Fq(1n));
            return p;
        }
        static fromPrivateKey(privateKey) {
            return this.BASE.multiply(normalizePrivKey(privateKey));
        }
        toCompressedHex() {
            let hex;
            if (this.equals(PointG1.ZERO)) {
                hex = POW_2_383 + POW_2_382;
            }
            else {
                const [x, y] = this.toAffine();
                const flag = (y.value * 2n) / P;
                hex = x.value + flag * POW_2_381 + POW_2_383;
            }
            return toBytesBE(hex, PUBLIC_KEY_LENGTH);
        }
        assertValidity() {
            const b = new Fq(exports.CURVE.b);
            if (this.isZero())
                return;
            const { x, y, z } = this;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq');
        }
        millerLoop(P) {
            const ell = P.pairingPrecomputes();
            let f12 = Fq12.ONE;
            let [x, y] = this.toAffine();
            let [Px, Py] = [x, y];
            for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
                f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
                if (bitGet(exports.CURVE.BLS_X, i)) {
                    j += 1;
                    f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
                }
                if (i != 0)
                    f12 = f12.square();
            }
            return f12.conjugate();
        }
    }
    PointG1.BASE = new PointG1(new Fq(exports.CURVE.Gx), new Fq(exports.CURVE.Gy), Fq.ONE);
    PointG1.ZERO = new PointG1(Fq.ONE, Fq.ONE, Fq.ZERO);
    return PointG1;
})();
exports.PointG1 = PointG1;
const H_EFF = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;
function clearCofactorG2(P) {
    return P.multiplyUnsafe(H_EFF);
}
let PointG2 = (() => {
    class PointG2 extends ProjectivePoint {
        constructor(x, y, z) {
            super(x, y, z, Fq2);
        }
        static async hashToCurve(msg) {
            if (typeof msg === 'string')
                msg = hexToArray(msg);
            const u = await hash_to_field(msg, 2);
            const Q0 = isogenyMapG2(map_to_curve_SSWU_G2(u[0]));
            const Q1 = isogenyMapG2(map_to_curve_SSWU_G2(u[1]));
            const R = Q0.add(Q1);
            const P = clearCofactorG2(R);
            return P;
        }
        static fromSignature(hex) {
            const half = hex.length / 2;
            const z1 = fromBytesBE(hex.slice(0, half));
            const z2 = fromBytesBE(hex.slice(half));
            const bflag1 = mod(z1, POW_2_383) / POW_2_382;
            if (bflag1 === 1n)
                return this.ZERO;
            const x1 = z1 % POW_2_381;
            const x2 = z2;
            const x = new Fq2([x2, x1]);
            let y = x.pow(3n).add(new Fq2(exports.CURVE.b2)).sqrt();
            if (!y)
                throw new Error('Failed to find a square root');
            const [y0, y1] = y.value;
            const aflag1 = (z1 % POW_2_382) / POW_2_381;
            const isGreater = y1 > 0n && (y1 * 2n) / P !== aflag1;
            const isZero = y1 === 0n && (y0 * 2n) / P !== aflag1;
            if (isGreater || isZero)
                y = y.multiply(-1n);
            const point = new PointG2(x, y, Fq2.ONE);
            point.assertValidity();
            return point;
        }
        static fromPrivateKey(privateKey) {
            return this.BASE.multiply(normalizePrivKey(privateKey));
        }
        toSignature() {
            if (this.equals(PointG2.ZERO)) {
                const sum = POW_2_383 + POW_2_382;
                return concatTypedArrays(toBytesBE(sum, PUBLIC_KEY_LENGTH), toBytesBE(0n, PUBLIC_KEY_LENGTH));
            }
            this.assertValidity();
            const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.value);
            const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
            const aflag1 = tmp / exports.CURVE.P;
            const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
            const z2 = x0;
            return concatTypedArrays(toBytesBE(z1, PUBLIC_KEY_LENGTH), toBytesBE(z2, PUBLIC_KEY_LENGTH));
        }
        assertValidity() {
            const b = new Fq2(exports.CURVE.b2);
            if (this.isZero())
                return;
            const { x, y, z } = this;
            const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
            const right = b.multiply(z.pow(3n));
            if (!left.equals(right))
                throw new Error('Invalid point: not on curve over Fq2');
        }
        calculatePrecomputes() {
            const [x, y] = this.toAffine();
            const [Qx, Qy, Qz] = [x, y, Fq2.ONE];
            let [Rx, Ry, Rz] = [Qx, Qy, Qz];
            let ell_coeff = [];
            for (let i = BLS_X_LEN - 2; i >= 0; i--) {
                let t0 = Ry.square();
                let t1 = Rz.square();
                let t2 = t1.multiply(3n).multiplyByB();
                let t3 = t2.multiply(3n);
                let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0);
                ell_coeff.push([
                    t2.subtract(t0),
                    Rx.square().multiply(3n),
                    t4.negate()
                ]);
                Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n);
                Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n));
                Rz = t0.multiply(t4);
                if (bitGet(exports.CURVE.BLS_X, i)) {
                    let t0 = Ry.subtract(Qy.multiply(Rz));
                    let t1 = Rx.subtract(Qx.multiply(Rz));
                    ell_coeff.push([
                        t0.multiply(Qx).subtract(t1.multiply(Qy)),
                        t0.negate(),
                        t1
                    ]);
                    let t2 = t1.square();
                    let t3 = t2.multiply(t1);
                    let t4 = t2.multiply(Rx);
                    let t5 = t3.subtract(t4.multiply(2n)).add(t0.square().multiply(Rz));
                    Rx = t1.multiply(t5);
                    Ry = t4.subtract(t5).multiply(t0).subtract(t3.multiply(Ry));
                    Rz = Rz.multiply(t3);
                }
            }
            return ell_coeff;
        }
        clearPairingPrecomputes() {
            this.pair_precomputes = undefined;
        }
        pairingPrecomputes() {
            if (this.pair_precomputes)
                return this.pair_precomputes;
            return (this.pair_precomputes = this.calculatePrecomputes());
        }
    }
    PointG2.BASE = new PointG2(new Fq2(exports.CURVE.G2x), new Fq2(exports.CURVE.G2y), Fq2.ONE);
    PointG2.ZERO = new PointG2(Fq2.ONE, Fq2.ONE, Fq2.ZERO);
    return PointG2;
})();
exports.PointG2 = PointG2;
function pairing(P, Q, withFinalExponent = true) {
    if (P.isZero() || Q.isZero())
        throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    let res = P.millerLoop(Q);
    return withFinalExponent ? res.finalExponentiate() : res;
}
exports.pairing = pairing;
function getPublicKey(privateKey) {
    return PointG1.fromPrivateKey(privateKey).toCompressedHex();
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    const msgPoint = await PointG2.hashToCurve(message);
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    return sigPoint.toSignature();
}
exports.sign = sign;
async function verify(signature, message, publicKey) {
    const P = PointG1.fromCompressedHex(publicKey).negate();
    const Hm = await PointG2.hashToCurve(message);
    const G = PointG1.BASE;
    const S = PointG2.fromSignature(signature);
    const ePHm = pairing(P, Hm, false);
    const eGS = pairing(G, S, false);
    const exp = eGS.multiply(ePHm).finalExponentiate();
    return exp.equals(Fq12.ONE);
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    return publicKeys.reduce((sum, publicKey) => sum.add(PointG1.fromCompressedHex(publicKey)), PointG1.ZERO);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (!signatures.length)
        throw new Error('Expected non-empty array');
    const aggregatedSignature = signatures.reduce((sum, signature) => sum.add(PointG2.fromSignature(signature)), PointG2.ZERO);
    return aggregatedSignature.toSignature();
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(messages, publicKeys, signature) {
    if (!messages.length)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    try {
        let producer = Fq12.ONE;
        for (const message of new Set(messages)) {
            const groupPublicKey = messages.reduce((groupPublicKey, m, i) => m !== message
                ? groupPublicKey
                : groupPublicKey.add(PointG1.fromCompressedHex(publicKeys[i])), PointG1.ZERO);
            const msg = await PointG2.hashToCurve(message);
            producer = producer.multiply(pairing(groupPublicKey, msg, false));
        }
        const sig = PointG2.fromSignature(signature);
        producer = producer.multiply(pairing(PointG1.BASE.negate(), sig, false));
        const finalExponent = producer.finalExponentiate();
        return finalExponent.equals(Fq12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
PointG1.BASE.calcMultiplyPrecomputes(4);
