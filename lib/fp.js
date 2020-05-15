"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Fp = void 0;
const group_1 = require("./group");
let Fp = (() => {
    class Fp {
        constructor(value = 0n) {
            this._value = 0n;
            this._value = this.mod(value, Fp.ORDER);
        }
        get value() {
            return this._value;
        }
        get zero() {
            return new Fp(0n);
        }
        get one() {
            return new Fp(1n);
        }
        mod(a, b) {
            const result = a % b;
            return result >= 0n ? result : b + result;
        }
        normalize(v) {
            return v instanceof Fp ? v : new Fp(v);
        }
        isEmpty() {
            return this._value === 0n;
        }
        equals(other) {
            return this._value === other._value;
        }
        negative() {
            return new Fp(-this._value);
        }
        invert() {
            const v = this._value;
            let lm = 1n;
            let hm = 0n;
            let low = v;
            let high = Fp.ORDER;
            let ratio = 0n;
            let nm = v;
            let enew = 0n;
            while (low > 1n) {
                ratio = high / low;
                nm = hm - lm * ratio;
                enew = high - low * ratio;
                hm = lm;
                lm = nm;
                high = low;
                low = enew;
            }
            return new Fp(nm);
        }
        add(other) {
            return new Fp(other._value + this._value);
        }
        square() {
            return new Fp(this._value * this._value);
        }
        pow(n) {
            let result = 1n;
            let value = this._value;
            while (n > 0) {
                if ((n & 1n) === 1n) {
                    result = this.mod(result * value, Fp.ORDER);
                }
                n >>= 1n;
                value = this.mod(value * value, Fp.ORDER);
            }
            return new Fp(result);
        }
        subtract(other) {
            return new Fp(this._value - other._value);
        }
        multiply(other) {
            return new Fp(other._value * this._value);
        }
        div(other) {
            return this.multiply(other.invert());
        }
    }
    Fp.ORDER = 1n;
    __decorate([
        group_1.normalized
    ], Fp.prototype, "equals", null);
    __decorate([
        group_1.normalized
    ], Fp.prototype, "add", null);
    __decorate([
        group_1.normalized
    ], Fp.prototype, "subtract", null);
    __decorate([
        group_1.normalized
    ], Fp.prototype, "multiply", null);
    __decorate([
        group_1.normalized
    ], Fp.prototype, "div", null);
    return Fp;
})();
exports.Fp = Fp;
