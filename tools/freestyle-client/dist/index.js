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
const events_1 = __importDefault(require("events"));
const undici_1 = require("undici");
const cognito_client_1 = require("./lib/cognito-client");
const Constants = __importStar(require("./constants"));
const types_1 = require("./types");
class PubEmitter extends events_1.default {
}
;
class Freestyle {
    constructor(username, password) {
        this.userPoolId = Constants.userPoolId;
        this.userPoolClientId = Constants.userPoolClientId;
        this.watchFrequency = 25000;
        this.username = username;
        this.password = password;
        this.client = new cognito_client_1.CognitoClient({
            userPoolId: this.userPoolId,
            userPoolClientId: this.userPoolClientId,
            clientSecret: Constants.clientSecret,
        });
        this.emitter = new PubEmitter();
        this.agent = new undici_1.Agent({
            pipelining: 1,
            keepAliveTimeout: 30,
            keepAliveMaxTimeout: 600,
        });
    }
    async authenticate() {
        this.session = await this.client.authenticateUserSrp(this.username, this.password);
    }
    async authRefresh() {
        if (!this.session) {
            throw new Error('Missing session');
        }
        this.session = await this.client.refreshSession(this.session.refreshToken);
    }
    watch() {
        if (this.timer) {
            throw new Error("watch already running");
        }
        this.timer = setInterval(async () => {
            await this.poll().catch(e => console.error(e));
        }, this.watchFrequency);
    }
    set frequency(interval) {
        this.watchFrequency = interval;
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = undefined;
            this.watch();
        }
    }
    async poll() {
        if (!this.session || !this.lock) {
            throw new Error('Missing session');
        }
        const lastLock = Object.assign({}, this.lock);
        await this.getHome();
        const changes = lockDiff(lastLock, this.lock);
        if (changes.length > 0) {
            this.emitter.emit('change', {
                previous: lastLock,
                changes: changes
            });
            changes.forEach((property) => {
                const key = Object.keys(property)[0];
                this.emitter.emit(key, property[key]);
            });
        }
        // check session expiry
        const timeNow = new Date().getTime();
        if (timeNow > (this.session.expiresIn - 60000 - this.watchFrequency)) {
            console.log('session expired, refreshing');
            await this.authRefresh();
        }
    }
    on(event, callback) {
        this.emitter.on(event, (props) => {
            return callback(props);
        });
    }
    async getProperty() {
        if (!this.session) {
            throw new Error('Missing session');
        }
        const properties = await this.apiGet(`${Constants.endpoint}/properties`);
        this.property = properties[0];
        return this.property;
    }
    async getHome() {
        if (!this.session || !this.property) {
            throw new Error('Missing session');
        }
        const home = await this.apiGet(`${Constants.endpoint}/properties/${this.property.propertyId}`);
        this.home = home;
        this.lock = home.locks[0];
        return this.home;
    }
    async getHomeCb(callback) {
        await this.getHome();
        callback();
    }
    printStatus() {
        if (!this.lock) {
            throw new Error('Missing lock data');
        }
        console.log(`lock ${this.lock.bleMac}:`);
        console.log(`  State: ${this.lock.reportedState}`);
        console.log(`  Desired State: ${this.lock.desiredState}`);
        console.log(`  Door: ${this.lock.doorClosed ? "Closed" : "Open"}`);
        console.log(`  Battery: ${this.lock.batteryPercent}%`);
        console.log("");
    }
    async init() {
        await this.authenticate();
        await this.getProperty();
        await this.getHome();
    }
    async unlock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(`${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`, {
            desiredLockStateTimeoutSeconds: 12.0,
            desiredState: types_1.LockStates.UNLOCKED,
            desiredStateToken: {
                data: 605271687314696
            }
        });
    }
    async deadLock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(`${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`, {
            desiredLockStateTimeoutSeconds: 12.0,
            desiredState: types_1.LockStates.LOCKED_DEADLOCK,
            desiredStateToken: {
                data: 605271687314696
            }
        });
    }
    async privacyLock() {
        if (!this.session || !this.property || !this.lock) {
            throw new Error('Missing session');
        }
        return await this.apiPut(`${Constants.endpoint}/properties/${this.property.propertyId}/locks/${this.lock.bleMac}`, {
            desiredLockStateTimeoutSeconds: 12.0,
            desiredState: types_1.LockStates.LOCKED_PRIVACY,
            desiredStateToken: {
                data: 605271687314696
            }
        });
    }
    async apiGet(url) {
        if (!this.session) {
            throw new Error('Missing session');
        }
        console.log(`[Freestyle Request] GET: ${url}`);
        const response = await (0, undici_1.fetch)(url, {
            dispatcher: this.agent,
            headers: {
                'authorization': this.session.idToken,
                'user-agent': 'okhttp/4.9.3'
            },
            method: 'GET',
        });
        if (response && response.status < 300) {
            const json = await response.json();
            console.log(`[Freestyle Response] GET: ${url}, Body:`, JSON.stringify(json, null, 2));
            return json;
        }
        const body = await response.json();
        console.log(`[Freestyle Error Response] GET: ${url}, Body:`, JSON.stringify(body, null, 2));
        return body;
    }
    async apiPut(url, data) {
        if (!this.session) {
            throw new Error('Missing session');
        }
        console.log(`[Freestyle Request] PUT: ${url}, Body:`, JSON.stringify(data, null, 2));
        const response = await (0, undici_1.fetch)(url, {
            dispatcher: this.agent,
            headers: {
                'authorization': this.session.idToken,
                'user-agent': 'okhttp/4.9.3'
            },
            method: 'PUT',
            body: JSON.stringify(data)
        });
        if (response?.status == 204) {
            console.log(`[Freestyle Response] PUT: ${url}, Status: 204`);
            return response.status;
        }
        if (response && response.status < 300) {
            const json = await response.json();
            console.log(`[Freestyle Response] PUT: ${url}, Body:`, JSON.stringify(json, null, 2));
            return json;
        }
        const body = await response.json();
        console.log(`[Freestyle Error Response] PUT: ${url}, Body:`, JSON.stringify(body, null, 2));
        return body;
    }
}
exports.default = Freestyle;
function lockDiff(a, b) {
    const delta = [];
    if (a.bleMac !== b.bleMac)
        delta.push({ bleMac: b.bleMac });
    if (a.serial !== b.serial)
        delta.push({ serial: b.serial });
    if (a.displayName !== b.displayName)
        delta.push({ displayName: b.displayName });
    if (a.reportedState !== b.reportedState)
        delta.push({ reportedState: b.reportedState });
    if (a.desiredState !== b.desiredState)
        delta.push({ desiredState: b.desiredState });
    if (a.doorSensorDetected !== b.doorSensorDetected)
        delta.push({ doorSensorDetected: b.doorSensorDetected });
    if (a.autoRelockTimeSeconds !== b.autoRelockTimeSeconds)
        delta.push({ autoRelockTimeSeconds: b.autoRelockTimeSeconds });
    if (a.audioVolume !== b.audioVolume)
        delta.push({ audioVolume: b.audioVolume });
    if (a.resyncRequested !== b.resyncRequested)
        delta.push({ resyncRequested: b.resyncRequested });
    if (a.doorClosed !== b.doorClosed)
        delta.push({ doorClosed: b.doorClosed });
    if (a.tamperActive !== b.tamperActive)
        delta.push({ tamperActive: b.tamperActive });
    if (a.keypadLockoutActive !== b.keypadLockoutActive)
        delta.push({ keypadLockoutActive: b.keypadLockoutActive });
    if (a.batteryLow !== b.batteryLow)
        delta.push({ batteryLow: b.batteryLow });
    if (a.batteryPercent !== b.batteryPercent)
        delta.push({ batteryPercent: b.batteryPercent });
    if (a.lastSyncUnixTimestamp !== b.lastSyncUnixTimestamp)
        delta.push({ lastSyncUnixTimestamp: b.lastSyncUnixTimestamp });
    if (a.diagnosticEnabled !== b.diagnosticEnabled)
        delta.push({ diagnosticEnabled: b.diagnosticEnabled });
    if (a.firmwareVersion !== b.firmwareVersion)
        delta.push({ firmwareVersion: b.firmwareVersion });
    return delta;
}
