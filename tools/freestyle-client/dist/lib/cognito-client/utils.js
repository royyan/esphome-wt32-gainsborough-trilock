"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateSecretHash = exports.formatTimestamp = exports.randomBytes = exports.decodeJwt = exports.calculateSignature = exports.getPasswordAuthenticationKey = exports.calculateHKDF = exports.calculateS = exports.calculateU = exports.generateA = exports.generateSmallA = exports.hashBuffer = exports.hashHexString = exports.padHex = void 0;
const hash_js_1 = __importDefault(require("hash.js"));
const jsbn_1 = require("jsbn");
const buffer_1 = require("buffer");
const formatInTimeZone_1 = __importDefault(require("date-fns-tz/formatInTimeZone"));
const initN = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
const N = new jsbn_1.BigInteger(initN, 16);
const g = new jsbn_1.BigInteger('2', 16);
const k = new jsbn_1.BigInteger(hashHexString(`${padHex(N)}${padHex(g)}`), 16);
function padHex(bigInt) {
    const HEX_MSB_REGEX = /^[89a-f]/i;
    const isNegative = bigInt.compareTo(jsbn_1.BigInteger.ZERO) < 0;
    let hexStr = bigInt.abs().toString(16);
    hexStr = hexStr.length % 2 !== 0 ? `0${hexStr}` : hexStr;
    hexStr = HEX_MSB_REGEX.test(hexStr) ? `00${hexStr}` : hexStr;
    if (isNegative) {
        const invertedNibbles = hexStr
            .split('')
            .map(x => {
            const invertedNibble = ~parseInt(x, 16) & 0xf;
            return '0123456789ABCDEF'.charAt(invertedNibble);
        })
            .join('');
        const flippedBitsBI = new jsbn_1.BigInteger(invertedNibbles, 16).add(jsbn_1.BigInteger.ONE);
        hexStr = flippedBitsBI.toString(16);
        if (hexStr.toUpperCase().startsWith('FF8')) {
            hexStr = hexStr.substring(2);
        }
    }
    return hexStr;
}
exports.padHex = padHex;
function hashHexString(str) {
    return hashBuffer(buffer_1.Buffer.from(str, 'hex'));
}
exports.hashHexString = hashHexString;
function hashBuffer(buffer) {
    const hash = hash_js_1.default.sha256().update(buffer).digest('hex');
    return new Array(64 - hash.length).join('0') + hash;
}
exports.hashBuffer = hashBuffer;
async function generateSmallA() {
    return new jsbn_1.BigInteger((await randomBytes(128)).toString('hex'), 16);
}
exports.generateSmallA = generateSmallA;
function generateA(smallA) {
    const A = g.modPow(smallA, N);
    return A;
}
exports.generateA = generateA;
function calculateU(A, B) {
    return new jsbn_1.BigInteger(hashHexString(padHex(A) + padHex(B)), 16);
}
exports.calculateU = calculateU;
function calculateS(X, B, U, smallA) {
    const gModPowXN = g.modPow(X, N);
    const bMinusKMult = B.subtract(k.multiply(gModPowXN));
    return bMinusKMult.modPow(smallA.add(U.multiply(X)), N).mod(N);
}
exports.calculateS = calculateS;
function calculateHKDF(ikm, salt) {
    const infoBitsBuffer = buffer_1.Buffer.concat([
        buffer_1.Buffer.from('Caldera Derived Key', 'utf8'),
        buffer_1.Buffer.from(String.fromCharCode(1), 'utf8')
    ]);
    const prk = hash_js_1.default
        .hmac(hash_js_1.default.sha256, salt)
        .update(ikm)
        .digest();
    const hmacResult = hash_js_1.default
        .hmac(hash_js_1.default.sha256, prk)
        .update(infoBitsBuffer)
        .digest();
    return hmacResult.slice(0, 16);
}
exports.calculateHKDF = calculateHKDF;
function getPasswordAuthenticationKey(poolName, username, password, B, U, smallA, salt) {
    const usernamePassword = `${poolName}${username}:${password}`;
    const usernamePasswordHash = hashBuffer(buffer_1.Buffer.from(usernamePassword, 'utf-8'));
    const X = new jsbn_1.BigInteger(hashHexString(padHex(salt) + usernamePasswordHash), 16);
    const S = calculateS(X, B, U, smallA);
    return calculateHKDF(buffer_1.Buffer.from(padHex(S), 'hex'), buffer_1.Buffer.from(padHex(U), 'hex'));
}
exports.getPasswordAuthenticationKey = getPasswordAuthenticationKey;
function calculateSignature(poolName, userId, secretBlock, hkdf, date = new Date()) {
    const timeStamp = formatTimestamp(date);
    const concatBuffer = buffer_1.Buffer.concat([
        buffer_1.Buffer.from(poolName, 'utf8'),
        buffer_1.Buffer.from(userId, 'utf8'),
        buffer_1.Buffer.from(secretBlock, 'base64'),
        buffer_1.Buffer.from(timeStamp, 'utf8')
    ]);
    const signature = buffer_1.Buffer.from(hash_js_1.default
        .hmac(hash_js_1.default.sha256, hkdf)
        .update(concatBuffer)
        .digest()).toString('base64');
    return {
        signature,
        timeStamp
    };
}
exports.calculateSignature = calculateSignature;
function decodeJwt(jwt) {
    const [header, payload, signature] = jwt.split('.');
    return {
        header: JSON.parse(buffer_1.Buffer.from(header, 'base64').toString('utf-8')),
        payload: JSON.parse(buffer_1.Buffer.from(payload, 'base64').toString('utf-8')),
        signature: signature
    };
}
exports.decodeJwt = decodeJwt;
async function randomBytes(num) {
    let crypto = globalThis.crypto;
    if (!crypto) {
        const nodeCrypto = await Promise.resolve().then(() => __importStar(require('node:crypto')));
        crypto = nodeCrypto.webcrypto;
    }
    return buffer_1.Buffer.from(crypto.getRandomValues(new Uint8Array(num)));
}
exports.randomBytes = randomBytes;
function formatTimestamp(date) {
    return (0, formatInTimeZone_1.default)(date, 'UTC', "EEE MMM d HH:mm:ss 'UTC' yyyy");
}
exports.formatTimestamp = formatTimestamp;
function calculateSecretHash(clientSecret, userPoolClientId, username) {
    const message = `${username}${userPoolClientId}`;
    const hash = buffer_1.Buffer.from(hash_js_1.default
        .hmac(hash_js_1.default.sha256, clientSecret)
        .update(message)
        .digest()).toString('base64');
    return hash;
}
exports.calculateSecretHash = calculateSecretHash;
