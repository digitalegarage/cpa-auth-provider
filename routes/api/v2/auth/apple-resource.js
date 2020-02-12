const appleSignin = require('apple-signin');
const config = require('../../../../config');
const callbackHelper = require('../../../../lib/callback-helper');
const apiErrorHelper = require('../../../../lib/api-error-helper');
const appleHelper  = require('../../../../lib/apple-helper');

// build client secret
let clientSecret = null;

if (config.identity_providers.apple && config.identity_providers.apple.enabled) {
    clientSecret = appleSignin.getClientSecret({
        clientID: config.identity_providers.apple.client_id, //'ch.rts.marts.dev', // identifier of Apple Service ID.
        teamId: config.identity_providers.apple.teamId,//'8779C367VK', // Apple Developer Team ID.
        privateKeyPath: config.identity_providers.apple.privateKeyPath, //'./AuthKey_MB8JH97AHJ.p8', // path to private key associated with your client ID.
        keyIdentifier: config.identity_providers.apple.keyIdentifier //'MB8JH97AHJ' // identifier of the private key.
    });
}

module.exports = function(app, options) {

    // retrieve a token from code (retrieved by oAuth flow from authorizationUrl)

    /**
     * @swagger
     * definitions:
     *   AppleCodeData:
     *      type: "object"
     *      properties:
     *           code:
     *               type: "string"
     *               example: "AQDubYxjE3f9eKc5giY5rT1m8Cfumx3Fyb-UVwrHglj_R..."
     *               description: "A apple oAuth code"
     *           state:
     *               type: "string"
     *               example: "%7B%27afterLoginRedirect%27%3A%27http%3A%2F%2Fhost%2Fa%2Fb%2Fc%27%7D"
     *               description: "En url encode string containing the redirect uri"
     *
     *   AppleTokenData:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "aaa..."
     *               description: "An Apple JWT token"
     *
     */

    /**
     * @swagger
     * /api/v2/auth/apple/callback:
     *   post:
     *     description: "log user (session) using Apple code."
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Apple code"
     *            description: "Apple code data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/AppleCodeData"
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "400":
     *            description: "Possible errors are: CODE_MISSING, AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL, UNEXPECTED_ERROR"
     *            schema:
     *              $ref: '#/definitions/error'
     *          "401":
     *            description: "cannot authenticate with provided code"
     *            schema:
     *              $ref: '#/definitions/error'
     */
    app.post('/api/v2/auth/apple/callback', (req, res, next) => {
        var code = req.body.code;
        var state = req.body.state;

        req.session.loginRedirect = state;

        const options = {
            clientID: config.identity_providers.apple.client_id,// identifier of Apple Service ID.
            redirectUri: callbackHelper.getURL('/api/v2/auth/apple/callback'), // use the same value which you passed to authorisation URL.
            clientSecret: clientSecret
        };
        return appleSignin.getAuthorizationToken(code, options).then(tokenResponse => {
            return appleHelper.verifyIdToken(tokenResponse.id_token, config.identity_providers.apple.client_id).then(
                function(result) {
                    return appleHelper.handleAppleToken(result, req, next, res);
                }).catch((err) => {
                next(err);
            });
        }).catch((err) => {
            next(err);
        });
    });

    /**
     * @swagger
     * /api/v2/auth/apple/token:
     *   post:
     *     description: "log user (session) using Apple token."
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Apple token"
     *            description: "Apple token data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/AppleTokenData"
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "400":
     *            description: "Possible errors are: CODE_MISSING, AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL, UNEXPECTED_ERROR"
     *            schema:
     *              $ref: '#/definitions/error'
     *          "401":
     *            description: "cannot authenticate with provided code"
     *            schema:
     *              $ref: '#/definitions/error'
     */

    app.post('/api/v2/auth/apple/token', (req, res, next) => {

        var idToken = req.body.token;

        if (!idToken){
            apiErrorHelper.throwError(400, 'TOKEN_MISSING', 'Expected Apple token is missing');
        }

        appleHelper.verifyIdToken(idToken, config.identity_providers.apple.client_id).then(
            function(result) {
                return appleHelper.handleAppleToken(result, req, next, res);
            }).catch((err) => {
            next(err);
        });
    });

};