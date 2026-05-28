#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const COGNITO_ENDPOINT =
  process.env.FREESTYLE_COGNITO_ENDPOINT || "https://cognito-idp.ap-southeast-2.amazonaws.com";
const DEFAULT_USER_POOL_ID = "ap-southeast-2_WSJBAl6hB";
const DEFAULT_CLIENT_ID = "56bpopumtgnheqfchknuchdhvt";
const DEFAULT_CLIENT_SECRET = "1l82hrk9jtu3irer8iouf4sgrof6f43j91i4dgrc9i3hcna2ttmu";
const API_ENDPOINT = process.env.FREESTYLE_API_ENDPOINT || "https://api-s.gainsboroughhardware.cloud/v0";
const SRP_N_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

function loadAppConfig() {
  const configPath = path.resolve(__dirname, "freestyle-app-config.json");
  if (!fs.existsSync(configPath)) return {};
  return JSON.parse(fs.readFileSync(configPath, "utf8"));
}

function configValue(envName, appConfig, configName) {
  return process.env[envName] || appConfig[configName] || "";
}

function secretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(`${username}${clientId}`)
    .digest("base64");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

function hexToBigInt(hex) {
  return BigInt(`0x${hex}`);
}

function bigIntToHex(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return hex;
}

function padHex(value) {
  let hex = typeof value === "bigint" ? bigIntToHex(value) : value;
  if (hex.length % 2) hex = `0${hex}`;
  if ("89ABCDEFabcdef".includes(hex[0])) hex = `00${hex}`;
  return hex;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function srpTimestamp(date = new Date()) {
  const weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${weekdays[date.getUTCDay()]} ${months[date.getUTCMonth()]} ${date.getUTCDate()} ` +
    `${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(2, "0")}:` +
    `${String(date.getUTCSeconds()).padStart(2, "0")} UTC ${date.getUTCFullYear()}`;
}

function hkdf(ikm, salt) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from("Caldera Derived Key\x01"), 16));
}

function computeSrpProof({ userPoolId, username, password, clientId, clientSecret, srpA, smallA, challenge }) {
  const poolName = userPoolId.split("_")[1];
  const bigN = hexToBigInt(SRP_N_HEX);
  const g = 2n;
  const k = hexToBigInt(sha256(Buffer.from(padHex(SRP_N_HEX) + padHex(g), "hex")).toString("hex"));
  const bigB = hexToBigInt(challenge.SRP_B);
  if (bigB % bigN === 0n) throw new Error("Invalid SRP_B from Cognito");

  const u = hexToBigInt(
    sha256(Buffer.from(padHex(srpA) + padHex(bigB), "hex")).toString("hex")
  );
  if (u === 0n) throw new Error("Invalid SRP scrambling parameter");

  const userIdForSrp = challenge.USER_ID_FOR_SRP || username;
  const userPasswordHash = sha256(Buffer.from(`${poolName}${userIdForSrp}:${password}`, "utf8"));
  const salt = hexToBigInt(challenge.SALT);
  const x = hexToBigInt(
    sha256(Buffer.from(padHex(salt) + userPasswordHash.toString("hex"), "hex")).toString("hex")
  );
  const gModPowX = modPow(g, x, bigN);
  const intValue2 = mod(bigB - k * gModPowX, bigN);
  const s = modPow(intValue2, smallA + u * x, bigN);
  const key = hkdf(Buffer.from(padHex(s), "hex"), Buffer.from(padHex(u), "hex"));
  const secretBlock = Buffer.from(challenge.SECRET_BLOCK, "base64");
  const timestamp = srpTimestamp();
  const signature = crypto
    .createHmac("sha256", key)
    .update(Buffer.concat([Buffer.from(poolName, "utf8"), Buffer.from(userIdForSrp, "utf8"), secretBlock,
      Buffer.from(timestamp, "utf8")]))
    .digest("base64");

  return {
    USERNAME: userIdForSrp,
    PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
    TIMESTAMP: timestamp,
    PASSWORD_CLAIM_SIGNATURE: signature,
    SECRET_HASH: secretHash(userIdForSrp, clientId, clientSecret),
  };
}

async function postJson(url, body, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`POST ${url} failed: HTTP ${response.status} ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

async function getJson(url, idToken) {
  const response = await fetch(url, {
    headers: {
      authorization: idToken,
      "user-agent": "okhttp/4.9.3",
    },
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`GET ${url} failed: HTTP ${response.status} ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

async function cognitoReferenceLogin(username, password) {
  const referencePaths = [
    path.resolve(__dirname, "freestyle-client", "dist"),
    path.resolve(__dirname, "..", "..", "external", "freestyle-client", "dist"),
  ];
  const referencePath = referencePaths.find((candidate) => fs.existsSync(candidate));
  if (!referencePath) return null;

  const reference = require(referencePath);
  const Freestyle = reference.default || reference;
  const freestyle = new Freestyle(username, password);
  await freestyle.authenticate();
  if (!freestyle.session || !freestyle.session.idToken) {
    throw new Error("Reference Freestyle client did not return a Cognito session");
  }
  if (process.env.FREESTYLE_DEBUG_AUTH === "1") {
    console.error(`Cognito auth accepted reference client at ${referencePath}`);
  }
  return {
    idToken: freestyle.session.idToken,
    refreshToken: freestyle.session.refreshToken || "",
    expiresIn: freestyle.session.expiresIn || 0,
  };
}

async function cognitoSrpLogin({ userPoolId, username, password, clientId, clientSecret }) {
  const bigN = hexToBigInt(SRP_N_HEX);
  const g = 2n;
  const smallA = hexToBigInt(crypto.randomBytes(128).toString("hex")) % bigN;
  const srpA = modPow(g, smallA, bigN);

  const init = await postJson(
    COGNITO_ENDPOINT,
    {
      AuthFlow: "USER_SRP_AUTH",
      ClientId: clientId,
      AuthParameters: {
        USERNAME: username,
        SRP_A: srpA.toString(16),
        SECRET_HASH: secretHash(username, clientId, clientSecret),
      },
      ClientMetadata: {},
    },
    {
      "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }
  );

  if (init.ChallengeName !== "PASSWORD_VERIFIER" || !init.ChallengeParameters) {
    throw new Error(`Unexpected SRP challenge: ${JSON.stringify(init)}`);
  }

  const challenge = init.ChallengeParameters;
  if (process.env.FREESTYLE_DEBUG_AUTH === "1") {
    console.error(
      `SRP challenge USERNAME=${challenge.USERNAME || ""} USER_ID_FOR_SRP=${challenge.USER_ID_FOR_SRP || ""}`
    );
  }

  const challengeResponses = computeSrpProof({
    userPoolId,
    username,
    password,
    clientId,
    clientSecret,
    srpA,
    smallA,
    challenge,
  });

  const result = await postJson(
    COGNITO_ENDPOINT,
    {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: clientId,
      ChallengeResponses: challengeResponses,
      Session: init.Session,
      ClientMetadata: {},
    },
    {
      "x-amz-target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
    }
  );

  if (process.env.FREESTYLE_DEBUG_AUTH === "1") {
    console.error("Cognito auth accepted USER_SRP_AUTH");
  }
  return result;
}

async function cognitoRefreshLogin({ username, refreshToken, clientId, clientSecret }) {
  const authParameters = {
    REFRESH_TOKEN: refreshToken,
  };
  if (username) {
    authParameters.SECRET_HASH = secretHash(username, clientId, clientSecret);
  } else {
    authParameters.SECRET_HASH = clientSecret;
  }

  return postJson(
    COGNITO_ENDPOINT,
    {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: clientId,
      AuthParameters: authParameters,
      ClientMetadata: {},
    },
    {
      "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }
  );
}

async function cognitoLogin({ userPoolId, username, password, refreshToken, clientId, clientSecret }) {
  if (process.env.FREESTYLE_ID_TOKEN) {
    return {
      idToken: process.env.FREESTYLE_ID_TOKEN,
      refreshToken: refreshToken || "",
      expiresIn: 0,
    };
  }

  let result;
  if (refreshToken) {
    try {
      result = await cognitoRefreshLogin({ username, refreshToken, clientId, clientSecret });
      if (process.env.FREESTYLE_DEBUG_AUTH === "1") {
        console.error("Cognito auth accepted REFRESH_TOKEN_AUTH");
      }
    } catch (err) {
      throw new Error(`Refresh-token auth failed: ${err.message || err}`);
    }
  } else {
    if (process.env.FREESTYLE_STANDALONE_AUTH !== "1") {
      const referenceSession = await cognitoReferenceLogin(username, password);
      if (referenceSession) return referenceSession;
    }
    result = await cognitoSrpLogin({ userPoolId, username, password, clientId, clientSecret });
  }

  const auth = result.AuthenticationResult;
  if (!auth || !auth.IdToken) {
    throw new Error(`Cognito response did not contain an IdToken: ${JSON.stringify(result)}`);
  }

  return {
    idToken: auth.IdToken,
    refreshToken: auth.RefreshToken || refreshToken || "",
    expiresIn: auth.ExpiresIn || 0,
  };
}

function findLock(propertiesResponse, requestedPropertyId, requestedBleMac) {
  const properties = Array.isArray(propertiesResponse)
    ? propertiesResponse
    : Array.isArray(propertiesResponse.properties)
      ? propertiesResponse.properties
      : [propertiesResponse];

  for (const property of properties) {
    if (!property) continue;
    if (requestedPropertyId && property.propertyId !== requestedPropertyId && property.id !== requestedPropertyId)
      continue;

    const locks = Array.isArray(property.locks) ? property.locks : [];
    for (const lock of locks) {
      if (!lock || !lock.bleMac) continue;
      if (!requestedBleMac || normalizeMac(lock.bleMac) === normalizeMac(requestedBleMac)) {
        return { property, lock };
      }
    }
  }

  return { property: null, lock: null };
}

function normalizeMac(value) {
  return String(value || "")
    .replace(/[^0-9a-fA-F]/g, "")
    .toUpperCase();
}

function printNonce(status) {
  if (!status || !status.doAiNonce) return;

  const nonceBytes = Array.from(Buffer.from(status.doAiNonce, "base64"));
  console.log("");
  console.log("GWASM status:");
  console.log(JSON.stringify(status, null, 2));
  console.log("");
  console.log("Nonce bytes:");
  console.log(`msg_id: ${status.doAiMsgId}`);
  console.log(`nonce: ${status.doAiNonce}`);
  console.log(nonceBytes.map((value, index) => `b${index}: ${value}`).join("\n"));
}

function printRequiredSecrets({ session, propertyId, bleMac, clientId, clientSecret }) {
  const redactClientSecret = process.env.FREESTYLE_REDACT_CLIENT_SECRET === "1";
  const refreshToken = session.refreshToken || "";

  console.log("");
  console.log("secrets.yaml values for ESPHome:");
  console.log("```yaml");
  if (refreshToken) {
    console.log(`freestyle_refresh_token: "${refreshToken}"`);
  } else {
    console.log('freestyle_refresh_token: "<not returned by this auth flow; keep existing refresh token>"');
  }
  console.log(`freestyle_property_id: "${propertyId}"`);
  console.log(`freestyle_cloud_ble_mac: "${bleMac}"`);
  console.log(`freestyle_client_id: "${clientId}"`);
  console.log(`freestyle_client_secret: "${redactClientSecret ? "<redacted>" : clientSecret}"`);
  console.log("```");
}

async function main() {
  const appConfig = loadAppConfig();
  const username = configValue("FREESTYLE_USERNAME", appConfig, "username");
  const password = configValue("FREESTYLE_PASSWORD", appConfig, "password");
  const refreshToken = configValue("FREESTYLE_REFRESH_TOKEN", appConfig, "refreshToken");
  const userPoolId = configValue("FREESTYLE_USER_POOL_ID", appConfig, "userPoolId") || DEFAULT_USER_POOL_ID;
  const clientId = configValue("FREESTYLE_CLIENT_ID", appConfig, "clientId") || DEFAULT_CLIENT_ID;
  const clientSecret = configValue("FREESTYLE_CLIENT_SECRET", appConfig, "clientSecret") || DEFAULT_CLIENT_SECRET;
  const requestedPropertyId = configValue("FREESTYLE_PROPERTY_ID", appConfig, "propertyId");
  const requestedBleMac = configValue("FREESTYLE_BLE_MAC", appConfig, "bleMac");

  if (!process.env.FREESTYLE_ID_TOKEN && !username && !refreshToken) {
    throw new Error("Set FREESTYLE_USERNAME, FREESTYLE_REFRESH_TOKEN, or FREESTYLE_ID_TOKEN");
  }
  if (!process.env.FREESTYLE_ID_TOKEN && !refreshToken && !password) {
    throw new Error("Set FREESTYLE_PASSWORD for login, or FREESTYLE_REFRESH_TOKEN for refresh-token auth");
  }
  if (process.env.FREESTYLE_DEBUG_AUTH === "1") {
    console.error(`Using Cognito user pool ${userPoolId} and client ${clientId}`);
  }

  const session = await cognitoLogin({
    userPoolId,
    username,
    password,
    refreshToken,
    clientId,
    clientSecret,
  });

  if (session.expiresIn) {
    console.log(`Cognito session refreshed; expires in ${session.expiresIn}s`);
  }
  if (process.env.FREESTYLE_PRINT_REFRESH_TOKEN === "1" && session.refreshToken) {
    console.log(`refreshToken=${session.refreshToken}`);
  }

  const propertyUrl = requestedPropertyId
    ? `${API_ENDPOINT}/properties/${requestedPropertyId}`
    : `${API_ENDPOINT}/properties`;
  const propertiesResponse = await getJson(propertyUrl, session.idToken);
  const { property, lock } = findLock(propertiesResponse, requestedPropertyId, requestedBleMac);
  if (!property || !lock) {
    throw new Error("Could not find a property/lock. Set FREESTYLE_PROPERTY_ID and FREESTYLE_BLE_MAC if needed.");
  }

  const propertyId = property.propertyId || property.id;
  const bleMac = lock.bleMac;

  console.log(`propertyId=${propertyId}`);
  console.log(`bleMac=${bleMac}`);
  console.log(`doorClosed=${lock.doorClosed}`);
  console.log(`batteryPercent=${lock.batteryPercent}`);
  console.log(`batteryLow=${lock.batteryLow}`);

  const statusUrl = `${API_ENDPOINT}/gwasm/${propertyId}/${bleMac}/status`;
  const status = await getJson(statusUrl, session.idToken);
  printNonce(status);
  printRequiredSecrets({ session, propertyId, bleMac, clientId, clientSecret });
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
