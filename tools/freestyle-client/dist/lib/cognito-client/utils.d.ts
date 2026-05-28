/// <reference types="node" />
import { BigInteger } from 'jsbn';
import { Buffer } from 'buffer';
export declare function padHex(bigInt: BigInteger): string;
export declare function hashHexString(str: string): string;
export declare function hashBuffer(buffer: Buffer): string;
export declare function generateSmallA(): Promise<BigInteger>;
export declare function generateA(smallA: BigInteger): BigInteger;
export declare function calculateU(A: BigInteger, B: BigInteger): BigInteger;
export declare function calculateS(X: BigInteger, B: BigInteger, U: BigInteger, smallA: BigInteger): BigInteger;
export declare function calculateHKDF(ikm: Buffer, salt: Buffer): number[];
export declare function getPasswordAuthenticationKey(poolName: string, username: string, password: string, B: BigInteger, U: BigInteger, smallA: BigInteger, salt: BigInteger): number[];
export declare function calculateSignature(poolName: string, userId: string, secretBlock: string, hkdf: number[], date?: Date): {
    signature: string;
    timeStamp: string;
};
export declare function decodeJwt<T = unknown>(jwt: string): {
    header: any;
    payload: T;
    signature: string;
};
export declare function randomBytes(num: number): Promise<Buffer>;
export declare function formatTimestamp(date: Date): string;
export declare function calculateSecretHash(clientSecret: string, userPoolClientId: string, username: string): string;
