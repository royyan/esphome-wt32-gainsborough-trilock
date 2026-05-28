"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Volume = exports.LockStates = void 0;
var LockStates;
(function (LockStates) {
    LockStates["UNLOCKED"] = "UNLOCKED";
    LockStates["LOCKED_PRIVACY"] = "LOCKED_PRIVACY";
    LockStates["LOCKED_DEADLOCK"] = "LOCKED_DEADLOCK";
})(LockStates || (exports.LockStates = LockStates = {}));
var Volume;
(function (Volume) {
    Volume["LOW"] = "LOW";
    Volume["MEDIUM"] = "MEDIUM";
    Volume["HIGH"] = "HIGH";
})(Volume || (exports.Volume = Volume = {}));
