"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
const fp_1 = require("./fp");
const group_1 = require("./group");
class Fp2 {
    constructor(coef1 = 0n, coef2 = 0n) {
        this.coeficient1 = new fp_1.Fp(0n);
        this.coeficient2 = new fp_1.Fp(0n);
        this.coeficient1 = coef1 instanceof fp_1.Fp ? coef1 : new fp_1.Fp(coef1);
        this.coeficient2 = coef2 instanceof fp_1.Fp ? coef2 : new fp_1.Fp(coef2);
    }
    static set ORDER(order) {
        this._order = order;
        this.DIV_ORDER = (order + 8n) / 16n;
        const one = new Fp2(1n, 1n);
        const orderEightPart = order / 8n;
        const roots = Array(8)
            .fill(null)
            .map((_, i) => one.pow(BigInt(i) * orderEightPart));
        this.EIGHTH_ROOTS_OF_UNITY = roots;
    }
    static get ORDER() {
        return this._order;
    }
    get value() {
        return [this.coeficient1.value, this.coeficient2.value];
    }
    get zero() {
        return new Fp2(0n, 0n);
    }
    get one() {
        return new Fp2(1n, 0n);
    }
    normalize(v) {
        if (typeof v === "bigint") {
            return v;
        }
        return v instanceof Fp2 ? v : new Fp2(...v);
    }
    isEmpty() {
        return this.coeficient1.isEmpty() && this.coeficient2.isEmpty();
    }
    equals(rhs) {
        return (this.coeficient1.equals(rhs.coeficient1) &&
            this.coeficient2.equals(rhs.coeficient2));
    }
    negative() {
        return new Fp2(this.coeficient1.negative(), this.coeficient2.negative());
    }
    add(rhs) {
        return new Fp2(this.coeficient1.add(rhs.coeficient1), this.coeficient2.add(rhs.coeficient2));
    }
    subtract(rhs) {
        return new Fp2(this.coeficient1.subtract(rhs.coeficient1), this.coeficient2.subtract(rhs.coeficient2));
    }
    multiply(otherValue) {
        if (typeof otherValue === "bigint") {
            return new Fp2(this.coeficient1.multiply(otherValue), this.coeficient2.multiply(otherValue));
        }
        const v0 = this.coeficient1.multiply(otherValue.coeficient1);
        const v1 = this.coeficient2.negative().multiply(otherValue.coeficient2);
        const c0 = v0.add(v1);
        const c1 = this.coeficient1
            .add(this.coeficient2)
            .multiply(otherValue.coeficient1.add(otherValue.coeficient2))
            .subtract(v0)
            .add(v1);
        return new Fp2(c0, c1);
    }
    mulByNonresidue() {
        return new Fp2(this.coeficient1.subtract(this.coeficient2), this.coeficient1.add(this.coeficient2));
    }
    square() {
        const a = this.coeficient1.add(this.coeficient2);
        const b = this.coeficient1.subtract(this.coeficient2);
        const c = this.coeficient1.add(this.coeficient1);
        return new Fp2(a.multiply(b), c.multiply(this.coeficient2));
    }
    modularSquereRoot() {
        const candidateSquareroot = this.pow(Fp2.DIV_ORDER);
        const check = candidateSquareroot.square().div(this);
        const rootIndex = Fp2.EIGHTH_ROOTS_OF_UNITY.findIndex(a => a.equals(check));
        if (rootIndex === -1 || (rootIndex & 1) === 1) {
            return null;
        }
        const x1 = candidateSquareroot.div(Fp2.EIGHTH_ROOTS_OF_UNITY[rootIndex >> 1]);
        const x2 = x1.negative();
        const isImageGreater = x1.coeficient2.value > x2.coeficient2.value;
        const isReconstructedGreater = x1.coeficient2.equals(x2.coeficient2) &&
            x1.coeficient1.value > x2.coeficient1.value;
        return isImageGreater || isReconstructedGreater ? x1 : x2;
    }
    pow(n) {
        if (n === 1n) {
            return this;
        }
        let result = new Fp2(1n, 0n);
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
    invert() {
        const t = this.coeficient1
            .square()
            .add(this.coeficient2.square())
            .invert();
        return new Fp2(this.coeficient1.multiply(t), this.coeficient2.multiply(t.negative()));
    }
    div(otherValue) {
        if (typeof otherValue === "bigint") {
            return new Fp2(this.coeficient1.div(otherValue), this.coeficient2.div(otherValue));
        }
        return this.multiply(otherValue.invert());
    }
}
Fp2._order = 1n;
Fp2.DIV_ORDER = 1n;
Fp2.EIGHTH_ROOTS_OF_UNITY = Array(8)
    .fill(null)
    .map(() => new Fp2());
Fp2.COFACTOR = 1n;
__decorate([
    group_1.normalized
], Fp2.prototype, "equals", null);
__decorate([
    group_1.normalized
], Fp2.prototype, "add", null);
__decorate([
    group_1.normalized
], Fp2.prototype, "subtract", null);
__decorate([
    group_1.normalized
], Fp2.prototype, "multiply", null);
__decorate([
    group_1.normalized
], Fp2.prototype, "div", null);
exports.Fp2 = Fp2;
