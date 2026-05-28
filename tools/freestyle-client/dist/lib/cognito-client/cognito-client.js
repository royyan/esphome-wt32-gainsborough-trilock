"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CognitoClient = exports.cognitoRequest = exports.authResultToSession = exports.CognitoIdentityProvider = exports.CognitoServiceTarget = void 0;
const hash_js_1 = __importDefault(require("hash.js"));
const jsbn_1 = require("jsbn");
const buffer_1 = require("buffer");
const error_js_1 = require("./error.js");
const utils_js_1 = require("./utils.js");
/**
 * List of used and supported Cognito API calls.
 * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html for more details
 */
var CognitoServiceTarget;
(function (CognitoServiceTarget) {
    CognitoServiceTarget["InitiateAuth"] = "InitiateAuth";
    CognitoServiceTarget["RespondToAuthChallenge"] = "RespondToAuthChallenge";
    CognitoServiceTarget["SignUp"] = "SignUp";
    CognitoServiceTarget["ConfirmSignUp"] = "ConfirmSignUp";
    CognitoServiceTarget["ChangePassword"] = "ChangePassword";
    CognitoServiceTarget["RevokeToken"] = "RevokeToken";
    CognitoServiceTarget["ForgotPassword"] = "ForgotPassword";
    CognitoServiceTarget["ConfirmForgotPassword"] = "ConfirmForgotPassword";
    CognitoServiceTarget["ResendConfirmationCode"] = "ResendConfirmationCode";
    CognitoServiceTarget["UpdateUserAttributes"] = "UpdateUserAttributes";
    CognitoServiceTarget["VerifyUserAttribute"] = "VerifyUserAttribute";
})(CognitoServiceTarget || (exports.CognitoServiceTarget = CognitoServiceTarget = {}));
/**
 * Cognito supported federated identities public providers.
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html for more information.
 */
var CognitoIdentityProvider;
(function (CognitoIdentityProvider) {
    CognitoIdentityProvider["Cognito"] = "COGNITO";
    CognitoIdentityProvider["Google"] = "Google";
    CognitoIdentityProvider["Facebook"] = "Facebook";
    CognitoIdentityProvider["Amazon"] = "LoginWithAmazon";
    CognitoIdentityProvider["Apple"] = "SignInWithApple";
})(CognitoIdentityProvider || (exports.CognitoIdentityProvider = CognitoIdentityProvider = {}));
function authResultToSession(authenticationResult) {
    return {
        accessToken: authenticationResult.AccessToken,
        idToken: authenticationResult.IdToken,
        expiresIn: new Date().getTime() + authenticationResult.ExpiresIn * 1000,
        refreshToken: authenticationResult.RefreshToken
    };
}
exports.authResultToSession = authResultToSession;
async function cognitoRequest(body, serviceTarget, cognitoEndpoint) {
    console.log(`[Cognito Request] Target: ${serviceTarget}, Body:`, JSON.stringify(body, null, 2));
    const cognitoResponse = await fetch(cognitoEndpoint, {
        headers: {
            'x-amz-target': `AWSCognitoIdentityProviderService.${serviceTarget}`,
            'content-type': 'application/x-amz-json-1.1'
        },
        method: 'POST',
        body: JSON.stringify(body)
    });
    if (cognitoResponse && cognitoResponse.status < 300) {
        const json = await cognitoResponse.json();
        console.log(`[Cognito Response] Target: ${serviceTarget}, Body:`, JSON.stringify(json, null, 2));
        return json;
    }
    const cognitoResponseBody = await cognitoResponse.json();
    console.log(`[Cognito Error Response] Target: ${serviceTarget}, Body:`, JSON.stringify(cognitoResponseBody, null, 2));
    /**
     * The whole error handling and value sanitization was inspired
     * by @see https://github.com/aws-amplify/amplify-js/blob/1f5eefd9c40285eb99e57764ac8fca1f9519e2c6/packages/core/src/clients/serde/json.ts#L14
     */
    const sanitizeErrorType = (rawValue) => {
        const [cleanValue] = rawValue.toString().split(/[,:]+/);
        if (cleanValue.includes('#')) {
            return cleanValue.split('#')[1];
        }
        return cleanValue;
    };
    const errorMessage = cognitoResponse.headers.get('X-Amzn-ErrorMessage') ??
        cognitoResponseBody.message ??
        cognitoResponseBody.Message ??
        'Unknown error';
    const cognitoException = sanitizeErrorType(cognitoResponse.headers.get('X-Amzn-ErrorType') ??
        cognitoResponseBody.code ??
        cognitoResponseBody.__type ??
        error_js_1.CognitoCommonException.Unknown);
    throw new error_js_1.CognitoError(errorMessage, cognitoException);
}
exports.cognitoRequest = cognitoRequest;
/**
 * Lightweight AWS Cogito client without any AWS SDK dependencies.
 */
class CognitoClient {
    constructor({ userPoolId, userPoolClientId, endpoint, oAuth2: oAuth, clientSecret }) {
        const [cognitoPoolRegion, cognitoPoolName] = userPoolId.split('_');
        this.cognitoEndpoint = (endpoint || `https://cognito-idp.${cognitoPoolRegion}.amazonaws.com`).replace(/\/$/, '');
        this.cognitoPoolName = cognitoPoolName;
        this.userPoolClientId = userPoolClientId;
        this.oAuth = oAuth;
        this.clientSecret = clientSecret;
    }
    static getDecodedTokenFromSession(session) {
        const { payload: idToken } = (0, utils_js_1.decodeJwt)(session.idToken);
        const { payload: accessToken } = (0, utils_js_1.decodeJwt)(session.accessToken);
        return {
            idToken,
            accessToken
        };
    }
    /**
     *
     * Performs user authentication with username and password through ALLOW_USER_SRP_AUTH .
     * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
     *
     * @param username Username
     * @param password Password
     *
     * @throws {InitiateAuthException}
     */
    async authenticateUserSrp(username, password) {
        const smallA = await (0, utils_js_1.generateSmallA)();
        const A = (0, utils_js_1.generateA)(smallA);
        const initiateAuthPayload = {
            AuthFlow: 'USER_SRP_AUTH',
            ClientId: this.userPoolClientId,
            AuthParameters: {
                USERNAME: username,
                SRP_A: A.toString(16),
                ...(this.clientSecret) &&
                    {
                        SECRET_HASH: (0, utils_js_1.calculateSecretHash)(this.clientSecret, this.userPoolClientId, username)
                    },
            },
            ClientMetadata: {}
        };
        const challenge = (await cognitoRequest(initiateAuthPayload, CognitoServiceTarget.InitiateAuth, this.cognitoEndpoint));
        const B = new jsbn_1.BigInteger(challenge.ChallengeParameters.SRP_B, 16);
        const salt = new jsbn_1.BigInteger(challenge.ChallengeParameters.SALT, 16);
        const U = (0, utils_js_1.calculateU)(A, B);
        const hkdf = (0, utils_js_1.getPasswordAuthenticationKey)(this.cognitoPoolName, challenge.ChallengeParameters.USER_ID_FOR_SRP, password, B, U, smallA, salt);
        const { signature, timeStamp } = (0, utils_js_1.calculateSignature)(this.cognitoPoolName, challenge.ChallengeParameters.USER_ID_FOR_SRP, challenge.ChallengeParameters.SECRET_BLOCK, hkdf);
        const respondToAuthChallengePayload = {
            ChallengeName: 'PASSWORD_VERIFIER',
            ClientId: this.userPoolClientId,
            ChallengeResponses: {
                PASSWORD_CLAIM_SECRET_BLOCK: challenge.ChallengeParameters.SECRET_BLOCK,
                PASSWORD_CLAIM_SIGNATURE: signature,
                USERNAME: challenge.ChallengeParameters.USER_ID_FOR_SRP,
                TIMESTAMP: timeStamp,
                ...(this.clientSecret) && {
                    SECRET_HASH: (0, utils_js_1.calculateSecretHash)(this.clientSecret, this.userPoolClientId, challenge.ChallengeParameters.USER_ID_FOR_SRP)
                },
            },
            ClientMetadata: {}
        };
        const { AuthenticationResult } = await cognitoRequest(respondToAuthChallengePayload, CognitoServiceTarget.RespondToAuthChallenge, this.cognitoEndpoint);
        return authResultToSession(AuthenticationResult);
    }
    /**
     *
     * Performs user authentication with username and password through USER_PASSWORD_AUTH .
     * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
     *
     * @param username Username
     * @param password Password
     * @throws {InitiateAuthException}
     */
    async authenticateUser(username, password) {
        const initiateAuthPayload = {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: this.userPoolClientId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password
            },
            ClientMetadata: {}
        };
        const { AuthenticationResult } = (await cognitoRequest(initiateAuthPayload, CognitoServiceTarget.InitiateAuth, this.cognitoEndpoint));
        const session = authResultToSession(AuthenticationResult);
        return session;
    }
    /**
     * Returns a new session based on the given refresh token.
     *
     * @param refreshToken
     * @returns @see Session
     * @throws {InitiateAuthException}
     */
    async refreshSession(refreshToken) {
        const refreshTokenPayload = {
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: this.userPoolClientId,
            AuthParameters: {
                REFRESH_TOKEN: refreshToken,
                ...(this.clientSecret) &&
                    {
                        SECRET_HASH: this.clientSecret
                    },
            },
            ClientMetadata: {}
        };
        const { AuthenticationResult } = (await cognitoRequest(refreshTokenPayload, CognitoServiceTarget.InitiateAuth, this.cognitoEndpoint));
        if (!AuthenticationResult.RefreshToken) {
            AuthenticationResult.RefreshToken = refreshToken;
        }
        return authResultToSession(AuthenticationResult);
    }
    /**
     *
     * @param username Username
     * @param password Password
     *
     * @throws {SignUpException}
     */
    async signUp(username, password, userAttributes) {
        const signUpPayload = {
            ClientId: this.userPoolClientId,
            Username: username,
            Password: password,
            UserAttributes: userAttributes
        };
        const data = await cognitoRequest(signUpPayload, CognitoServiceTarget.SignUp, this.cognitoEndpoint);
        return {
            id: data.UserSub,
            confirmed: data.UserConfirmed
        };
    }
    /**
     * Confirms the user registration via verification code.
     *
     * @param username Username
     * @param code Confirmation code the user gets through the registration E-Mail
     *
     * @throws {ConfirmSignUpException}
     */
    async confirmSignUp(username, code) {
        const confirmSignUpPayload = {
            ClientId: this.userPoolClientId,
            ConfirmationCode: code,
            Username: username
        };
        await cognitoRequest(confirmSignUpPayload, CognitoServiceTarget.ConfirmSignUp, this.cognitoEndpoint);
    }
    /**
     *
     * @param currentPassword Current user password.
     * @param newPassword  New user password.
     *
     * @throws {ChangePasswordException}
     */
    async changePassword(currentPassword, newPassword, accessToken) {
        const changePasswordPayload = {
            PreviousPassword: currentPassword,
            ProposedPassword: newPassword,
            AccessToken: accessToken
        };
        await cognitoRequest(changePasswordPayload, CognitoServiceTarget.ChangePassword, this.cognitoEndpoint);
    }
    /**
     * Updates the user attributes.
     *
     * @param userAttributes List of user attributes to update.
     * @param accessToken Access token of the current user.
     *
     * @throws {UpdateUserAttributesException}
     */
    async updateUserAttributes(userAttributes, accessToken) {
        const updateUserAttributesPayload = {
            UserAttributes: userAttributes,
            AccessToken: accessToken
        };
        await cognitoRequest(updateUserAttributesPayload, CognitoServiceTarget.UpdateUserAttributes, this.cognitoEndpoint);
    }
    /**
     * Verifies a given user attribute
     *
     * @param attributeName Name of the attribute to verify
     * @param code  Verification code
     * @param accessToken Access token of the current user.
     *
     * @throws {VerifyUserAttributeException}
     */
    async verifyUserAttribute(attributeName, code, accessToken) {
        const verifyUserAttributePayload = {
            AttributeName: attributeName,
            Code: code,
            AccessToken: accessToken
        };
        await cognitoRequest(verifyUserAttributePayload, CognitoServiceTarget.VerifyUserAttribute, this.cognitoEndpoint);
    }
    /**
     * Sign out the user and remove the current user session.
     *
     * @throws {RevokeTokenException}
     */
    async signOut(refreshToken) {
        const revokeTokenPayload = {
            Token: refreshToken,
            ClientId: this.userPoolClientId
        };
        await cognitoRequest(revokeTokenPayload, CognitoServiceTarget.RevokeToken, this.cognitoEndpoint);
    }
    /**
     * Request forgot password.
     * @param username Username
     *
     * @throws {ForgotPasswordException}
     */
    async forgotPassword(username) {
        const forgotPasswordPayload = {
            ClientId: this.userPoolClientId,
            Username: username
        };
        await cognitoRequest(forgotPasswordPayload, CognitoServiceTarget.ForgotPassword, this.cognitoEndpoint);
    }
    /**
     * Confirms the new password via the given code send via cognito triggered by @see forgotPassword .
     *
     * @param username Username
     * @param newPassword New password
     * @param confirmationCode Confirmation code which the user got through E-mail
     *
     * @throws {ConfirmForgotPasswordException}
     */
    async confirmForgotPassword(username, newPassword, confirmationCode) {
        const confirmForgotPasswordPayload = {
            ClientId: this.userPoolClientId,
            Username: username,
            ConfirmationCode: confirmationCode,
            Password: newPassword
        };
        await cognitoRequest(confirmForgotPasswordPayload, CognitoServiceTarget.ConfirmForgotPassword, this.cognitoEndpoint);
    }
    /**
     * Triggers cognito to resend the confirmation code
     * @param username Username
     *
     * @throws {ResendConfirmationCodeException}
     */
    async resendConfirmationCode(username) {
        const resendConfirmationCodePayLoad = {
            ClientId: this.userPoolClientId,
            Username: username
        };
        await cognitoRequest(resendConfirmationCodePayLoad, CognitoServiceTarget.ResendConfirmationCode, this.cognitoEndpoint);
    }
    /**
     * Returns a link to Cognito`s Hosted UI for OAuth2 authentication.
     * This method works in conjunction with @see handleCodeFlow .
     *
     * @param identityProvider When provided, this will generate a link which
     * tells Cognito`s Hosted UI to redirect to the given federated identity provider.
     *
     * @throws {Error}
     */
    async generateOAuthSignInUrl(identityProvider) {
        if (this.oAuth === undefined) {
            throw Error('You have to define oAuth options to use generateFederatedSignUrl');
        }
        const state = (await (0, utils_js_1.randomBytes)(32)).toString('hex');
        const pkce = (await (0, utils_js_1.randomBytes)(128)).toString('hex');
        const code_challenge = buffer_1.Buffer.from(hash_js_1.default.sha256().update(pkce).digest())
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        const queryParams = new URLSearchParams();
        queryParams.append('redirect_uri', this.oAuth.redirectUrl);
        queryParams.append('response_type', this.oAuth.responseType);
        queryParams.append('client_id', this.userPoolClientId);
        identityProvider && queryParams.append('identity_provider', identityProvider);
        queryParams.append('scope', this.oAuth.scopes.join(' '));
        queryParams.append('state', state);
        queryParams.append('code_challenge', code_challenge);
        queryParams.append('code_challenge_method', 'S256');
        return {
            url: `${this.oAuth.cognitoDomain}/oauth2/authorize?${queryParams.toString()}`,
            state,
            pkce
        };
    }
    /**
     *
     * Handles Cognito`s OAuth2 code flow after redirection from Cognito`s Hosted UI.
     * The method call assumes that @see generateOAuthSignInUrl was used to
     * generated the link to the Hosted UI.
     *
     * @param returnUrl The full return URL from redirection after a successful OAuth2
     * authentication.
     *
     * @throws {Error}
     */
    async handleCodeFlow(returnUrl, pkce) {
        if (this.oAuth === undefined) {
            throw Error('You have to define oAuth options to use handleCodeFlow');
        }
        const url = new URL(returnUrl);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        if (code === null || state === null) {
            throw Error('code or state parameter is missing from return url.');
        }
        const urlParams = new URLSearchParams();
        urlParams.append('grant_type', 'authorization_code');
        urlParams.append('code', code);
        urlParams.append('client_id', this.userPoolClientId);
        urlParams.append('redirect_uri', this.oAuth.redirectUrl);
        urlParams.append('code_verifier', pkce);
        const tokenEndpoint = `${this.oAuth.cognitoDomain}/oauth2/token`;
        const response = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: urlParams.toString()
        });
        const { access_token, refresh_token, id_token, expires_in, error } = await response.json();
        if (error) {
            throw new Error(error);
        }
        const session = authResultToSession({
            AccessToken: access_token,
            RefreshToken: refresh_token,
            IdToken: id_token,
            ExpiresIn: expires_in
        });
        return session;
    }
}
exports.CognitoClient = CognitoClient;
