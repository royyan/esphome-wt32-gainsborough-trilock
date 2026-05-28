export interface UserAttribute {
    Name: string;
    Value: string;
}
/**
 * Cognito related OAuth props.
 */
export interface OAuth2Props {
    /**
     * Cognito domain for OAuth2 token endpoints.
     */
    cognitoDomain: string;
    /**
     * Requested OAuth scopes
     * @example ['email', 'openid']
     */
    scopes: string[];
    /**
     * Redirect URL after a successful OAuth2 authentication.
     */
    redirectUrl: string;
    /**
     * Response type.
     */
    responseType: 'code';
}
export interface CognitoClientProps {
    /**
     * Cognito User Pool ID
     * @example eu-central-1_lv6wixN9f
     */
    userPoolId: string;
    /**
     * Cognito User Pool Client ID
     */
    userPoolClientId: string;
    /**
     * Optional Cognito endpoint. Useful for local testing.
     * If not defined the endpoint will be determined by @see userPoolId .
     */
    endpoint?: string;
    /**
     * Cognito OAuth related options. See @see OAuthProps .
     */
    oAuth2?: OAuth2Props;
    /**
     * Cognito Client Secret
     */
    clientSecret?: string;
}
/**
 * Cognito User Session
 */
export interface Session {
    /**
     * JWT Access Token
     */
    accessToken: string;
    /**
     * JWT ID Token
     */
    idToken: string;
    /**
     * JWT refresh token
     */
    refreshToken: string;
    /**
     * Validity of the session in time stamp as milliseconds.
     */
    expiresIn: number;
}
/**
 * Represents the decoded values from a JWT ID token.
 */
export interface IdToken extends Record<string, string | string[] | number | boolean> {
    'cognito:username': string;
    'cognito:groups': string[];
    email_verified: boolean;
    email: string;
    iss: string;
    origin_jti: string;
    aud: string;
    event_id: string;
    token_use: 'id';
    auth_time: number;
    exp: number;
    iat: number;
    jti: string;
    sub: string;
}
export interface AccessToken extends Record<string, string | string[] | number | boolean> {
    auth_time: number;
    client_id: string;
    event_id: string;
    exp: number;
    iat: number;
    iss: string;
    jti: string;
    origin_jti: string;
    scope: string;
    sub: string;
    token_use: 'access';
    username: string;
}
export interface DecodedTokens {
    idToken: IdToken;
    accessToken: AccessToken;
}
/**
 * List of used and supported Cognito API calls.
 * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html for more details
 */
export declare enum CognitoServiceTarget {
    InitiateAuth = "InitiateAuth",
    RespondToAuthChallenge = "RespondToAuthChallenge",
    SignUp = "SignUp",
    ConfirmSignUp = "ConfirmSignUp",
    ChangePassword = "ChangePassword",
    RevokeToken = "RevokeToken",
    ForgotPassword = "ForgotPassword",
    ConfirmForgotPassword = "ConfirmForgotPassword",
    ResendConfirmationCode = "ResendConfirmationCode",
    UpdateUserAttributes = "UpdateUserAttributes",
    VerifyUserAttribute = "VerifyUserAttribute"
}
/**
 * Cognito supported federated identities public providers.
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html for more information.
 */
export declare enum CognitoIdentityProvider {
    Cognito = "COGNITO",
    Google = "Google",
    Facebook = "Facebook",
    Amazon = "LoginWithAmazon",
    Apple = "SignInWithApple"
}
export interface AuthenticationResult {
    AccessToken: string;
    ExpiresIn: number;
    IdToken: string;
    RefreshToken: string;
}
export interface AuthenticationResponse {
    AuthenticationResult: AuthenticationResult;
}
export interface ChallengeResponse {
    ChallengeName: 'PASSWORD_VERIFIER';
    ChallengeParameters: {
        SALT: string;
        SECRET_BLOCK: string;
        SRP_B: string;
        USERNAME: string;
        USER_ID_FOR_SRP: string;
    };
}
export declare function authResultToSession(authenticationResult: AuthenticationResult): Session;
export declare function cognitoRequest(body: object, serviceTarget: CognitoServiceTarget, cognitoEndpoint: string): Promise<any>;
/**
 * Lightweight AWS Cogito client without any AWS SDK dependencies.
 */
export declare class CognitoClient {
    private readonly cognitoEndpoint;
    private readonly cognitoPoolName;
    private readonly userPoolClientId;
    private readonly clientSecret?;
    private readonly oAuth?;
    constructor({ userPoolId, userPoolClientId, endpoint, oAuth2: oAuth, clientSecret }: CognitoClientProps);
    static getDecodedTokenFromSession(session: Session): DecodedTokens;
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
    authenticateUserSrp(username: string, password: string): Promise<Session>;
    /**
     *
     * Performs user authentication with username and password through USER_PASSWORD_AUTH .
     * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
     *
     * @param username Username
     * @param password Password
     * @throws {InitiateAuthException}
     */
    authenticateUser(username: string, password: string): Promise<Session>;
    /**
     * Returns a new session based on the given refresh token.
     *
     * @param refreshToken
     * @returns @see Session
     * @throws {InitiateAuthException}
     */
    refreshSession(refreshToken: string): Promise<Session>;
    /**
     *
     * @param username Username
     * @param password Password
     *
     * @throws {SignUpException}
     */
    signUp(username: string, password: string, userAttributes?: UserAttribute[]): Promise<{
        id: string;
        confirmed: boolean;
    }>;
    /**
     * Confirms the user registration via verification code.
     *
     * @param username Username
     * @param code Confirmation code the user gets through the registration E-Mail
     *
     * @throws {ConfirmSignUpException}
     */
    confirmSignUp(username: string, code: string): Promise<void>;
    /**
     *
     * @param currentPassword Current user password.
     * @param newPassword  New user password.
     *
     * @throws {ChangePasswordException}
     */
    changePassword(currentPassword: string, newPassword: string, accessToken: string): Promise<void>;
    /**
     * Updates the user attributes.
     *
     * @param userAttributes List of user attributes to update.
     * @param accessToken Access token of the current user.
     *
     * @throws {UpdateUserAttributesException}
     */
    updateUserAttributes(userAttributes: UserAttribute[], accessToken: string): Promise<void>;
    /**
     * Verifies a given user attribute
     *
     * @param attributeName Name of the attribute to verify
     * @param code  Verification code
     * @param accessToken Access token of the current user.
     *
     * @throws {VerifyUserAttributeException}
     */
    verifyUserAttribute(attributeName: string, code: string, accessToken: string): Promise<void>;
    /**
     * Sign out the user and remove the current user session.
     *
     * @throws {RevokeTokenException}
     */
    signOut(refreshToken: string): Promise<void>;
    /**
     * Request forgot password.
     * @param username Username
     *
     * @throws {ForgotPasswordException}
     */
    forgotPassword(username: string): Promise<void>;
    /**
     * Confirms the new password via the given code send via cognito triggered by @see forgotPassword .
     *
     * @param username Username
     * @param newPassword New password
     * @param confirmationCode Confirmation code which the user got through E-mail
     *
     * @throws {ConfirmForgotPasswordException}
     */
    confirmForgotPassword(username: string, newPassword: string, confirmationCode: string): Promise<void>;
    /**
     * Triggers cognito to resend the confirmation code
     * @param username Username
     *
     * @throws {ResendConfirmationCodeException}
     */
    resendConfirmationCode(username: string): Promise<void>;
    /**
     * Returns a link to Cognito`s Hosted UI for OAuth2 authentication.
     * This method works in conjunction with @see handleCodeFlow .
     *
     * @param identityProvider When provided, this will generate a link which
     * tells Cognito`s Hosted UI to redirect to the given federated identity provider.
     *
     * @throws {Error}
     */
    generateOAuthSignInUrl(identityProvider?: CognitoIdentityProvider): Promise<{
        url: string;
        state: string;
        pkce: string;
    }>;
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
    handleCodeFlow(returnUrl: string, pkce: string): Promise<Session>;
}
