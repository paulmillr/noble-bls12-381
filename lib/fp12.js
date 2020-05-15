"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Fp12 = void 0;
const fp_1 = require("./fp");
const group_1 = require("./group");
const FP12_DEFAULT = [
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n,
    0n, 1n, 0n, 1n
];
let Fp12 = (() => {
    class Fp12 {
        constructor(...args) {
            this.coefficients = FP12_DEFAULT.map(a => new fp_1.Fp(a));
            args =
                args.length === 0 ? FP12_DEFAULT : args.slice(0, 12);
            this.coefficients = args[0] instanceof fp_1.Fp ? args : args.map(a => new fp_1.Fp(a));
        }
        get value() {
            return this.coefficients.map(c => c.value);
        }
        get zero() {
            return new Fp12(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        get one() {
            return new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
        }
        normalize(v) {
            if (typeof v === "bigint") {
                return v;
            }
            return v instanceof Fp12 ? v : new Fp12(...v);
        }
        isEmpty() {
            return this.coefficients.every(a => a.isEmpty());
        }
        equals(rhs) {
            return this.coefficients.every((a, i) => a.equals(rhs.coefficients[i]));
        }
        negative() {
            return new Fp12(...this.coefficients.map(a => a.negative()));
        }
        add(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.add(rhs.coefficients[i])));
        }
        subtract(rhs) {
            return new Fp12(...this.coefficients.map((a, i) => a.subtract(rhs.coefficients[i])));
        }
        multiply(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp12(...this.coefficients.map(a => a.multiply(otherValue)));
            }
            const LENGTH = this.coefficients.length;
            const filler = Array(LENGTH * 2 - 1)
                .fill(null)
                .map(() => new fp_1.Fp());
            for (let i = 0; i < LENGTH; i++) {
                for (let j = 0; j < LENGTH; j++) {
                    filler[i + j] = filler[i + j].add(this.coefficients[i].multiply(otherValue.coefficients[j]));
                }
            }
            for (let exp = LENGTH - 2; exp >= 0; exp--) {
                const top = filler.pop();
                if (top === undefined) {
                    break;
                }
                for (const [i, value] of Fp12.ENTRY_COEFFICIENTS) {
                    filler[exp + i] = filler[exp + i].subtract(top.multiply(value));
                }
            }
            return new Fp12(...filler);
        }
        square() {
            return this.multiply(this);
        }
        pow(n) {
            if (n === 1n) {
                return this;
            }
            let result = new Fp12(1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);
            let value = this;
            while (n > 0n) {
                if ((n & 1n) === 1n) {
                    result = result.multiply(value);
                }
                n >>= 1n;
                value = value.square();
            }
            return result;
        }
        degree(nums) {
            let degree = nums.length - 1;
            while (nums[degree] === 0n && degree !== 0) {
                degree--;
            }
            return degree;
        }
        primeNumberInvariant(num) {
            return new fp_1.Fp(num).invert().value;
        }
        optimizedRoundedDiv(coefficients, others) {
            const tmp = [...coefficients];
            const degreeThis = this.degree(tmp);
            const degreeOthers = this.degree(others);
            const zeros = Array.from(tmp).fill(0n);
            const edgeInvariant = this.primeNumberInvariant(others[degreeOthers]);
            for (let i = degreeThis - degreeOthers; i >= 0; i--) {
                zeros[i] = zeros[i] + tmp[degreeOthers + i] * edgeInvariant;
                for (let c = 0; c < degreeOthers; c++) {
                    tmp[c + i] = tmp[c + i] - zeros[c];
                }
            }
            return new Fp12(...zeros.slice(0, this.degree(zeros) + 1));
        }
        invert() {
            const LENGTH = this.coefficients.length;
            let lm = [...this.one.coefficients.map(a => a.value), 0n];
            let hm = [...this.zero.coefficients.map(a => a.value), 0n];
            let low = [...this.coefficients.map(a => a.value), 0n];
            let high = [...Fp12.MODULE_COEFFICIENTS, 1n];
            while (this.degree(low) !== 0) {
                const { coefficients } = this.optimizedRoundedDiv(high, low);
                const zeros = Array(LENGTH + 1 - coefficients.length)
                    .fill(null)
                    .map(() => new fp_1.Fp());
                const roundedDiv = coefficients.concat(zeros);
                let nm = [...hm];
                let nw = [...high];
                for (let i = 0; i <= LENGTH; i++) {
                    for (let j = 0; j <= LENGTH - i; j++) {
                        nm[i + j] -= lm[i] * roundedDiv[j].value;
                        nw[i + j] -= low[i] * roundedDiv[j].value;
                    }
                }
                nm = nm.map(a => new fp_1.Fp(a).value);
                nw = nw.map(a => new fp_1.Fp(a).value);
                hm = lm;
                lm = nm;
                high = low;
                low = nw;
            }
            const result = new Fp12(...lm);
            return result.div(low[0]);
        }
        div(otherValue) {
            if (typeof otherValue === "bigint") {
                return new Fp12(...this.coefficients.map(a => a.div(otherValue)));
            }
            return this.multiply(otherValue.invert());
        }
    }
    Fp12.MODULE_COEFFICIENTS = [
        2n, 0n, 0n, 0n, 0n, 0n, -2n, 0n, 0n, 0n, 0n, 0n
    ];
    Fp12.ENTRY_COEFFICIENTS = [
        [0, 2n],
        [6, -2n]
    ];
    __decorate([
        group_1.normalized
    ], Fp12.prototype, "equals", null);
    __decorate([
        group_1.normalized
    ], Fp12.prototype, "add", null);
    __decorate([
        group_1.normalized
    ], Fp12.prototype, "subtract", null);
    __decorate([
        group_1.normalized
    ], Fp12.prototype, "multiply", null);
    __decorate([
        group_1.normalized
    ], Fp12.prototype, "div", null);
    return Fp12;
})();
exports.Fp12 = Fp12;
