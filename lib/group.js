"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalized = void 0;
function normalized(target, propertyKey, descriptor) {
    const propertyValue = target[propertyKey];
    if (typeof propertyValue !== "function") {
        return descriptor;
    }
    const previousImplementation = propertyValue;
    descriptor.value = function (arg) {
        const modifiedArgument = target.normalize(arg);
        return previousImplementation.call(this, modifiedArgument);
    };
    return descriptor;
}
exports.normalized = normalized;
