"use strict";

const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const socialLoginHelper = require('../../../../lib/social-login-helper');
const googleHelper = require('../../../../lib/google-helper');
const afterLoginHelper = require('../../../../lib/afterlogin-helper');
const db = require('../../../../models/index');
const logger = require('../../../../lib/logger');
const errorHelper = require('../../../../lib/error-helper');

const passport = require('passport');


const GOOGLE_STRATEGY_NAME = 'googleRedirect';

passport.use(GOOGLE_STRATEGY_NAME, googleHelper.getGoogleStrategy('/api/v2/auth/google/callback'));


module.exports = function (app, options) {

    app.options('/api/v2/auth/google', cors);
    app.get('/api/v2/auth/google', passport.authenticate(GOOGLE_STRATEGY_NAME, {scope: ['profile', 'email'], prompt: 'select_account'}));

    app.options('/api/v2/auth/google/callback', cors);
    app.get('/api/v2/auth/google/callback', passport.authenticate(GOOGLE_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/login?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_GOOGLE'}), function (req, res) {

        socialLoginHelper.afterSocialLoginSucceed(req, res);

    });

    /**
     * @swagger
     * definitions:
     *  error:
     *      properties:
     *          error:
     *              type: object
     *              properties:
     *                  code:
     *                      type: string
     *                      example: INVALID_SIGNUP_DATA
     *                      description: error code
     *                      required: true
     *                  hint:
     *                      type: string
     *                      example: signup process requires that user choose a untaken email
     *                      description: an optional hint given to the developer. THIS IS NOT SUPPOSED TO BE RETURNED TO END USER!
     *                  traceId:
     *                      type: string
     *                      example: https://error-tracking.ebu.io/broadcaster/prod/issues/1234/
     *                      description: an optional trace id to get more information in error tracking system
     *                  causes:
     *                      type: array
     *                      description: list of possible causes when applicable
     *                      items:
     *                          type: object
     *                          properties:
     *                              code:
     *                                  type: string
     *                                  example: EMAIL_ALREADY_TAKEN
     *                                  description: error code
     *                                  required: true
     *                              hint:
     *                                  type: string
     *                                  example: signup process requires that user choose a untaken email
     *                                  description: an optional hint given to the developer. THIS IS NOT SUPPOSED TO BE RETURNED TO END USER!
     */

    /**
     * @swagger
     * definitions:
     *   GoogleTokenData:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmYjA1Zjc0MjM2NmVlNGNmNGJjZjQ5Zjk4NGM0OD..."
     *               description: "A google oAuth code"
     *   GoogleCodeData:
     *      type: "object"
     *      properties:
     *           code:
     *               type: "string"
     *               example: "AQDubYxjE3f9eKc5giY5rT1m8Cfumx3Fyb-UVwrHglj_R..."
     *               description: "A google oAuth code"
     *           redirect_uri:
     *               type: "string"
     *               example: "http://demo-peach.ebu.io/idp/api/v2/auth/google/callback"
     *               description: "Redirect uri that had been used to get the code"
     *
     */


    /**
     * @swagger
     * /api/v2/auth/google/token:
     *   post:
     *     description: log user (session) using Google code
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Google token"
     *            description: "Google token data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/GoogleTokenData"
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "400":
     *            description: "missing token in request body"
     *            schema:
     *              $ref: '#/definitions/error'
     *          "401":
     *            description: "cannot authenticate with provided code"
     *            schema:
     *              $ref: '#/definitions/error'
     */
    app.options('/api/v2/auth/google/token', cors);
    app.post('/api/v2/auth/google/token', function(req, res) {
        if (!req.body.token) {
            return res.status(400).json(errorHelper.buildError("TOKEN_MISSING", "missing token in request body")).send();
        }
        authViaToken(req.body.token, req, res);

    });


    /**
     * @swagger
     * /api/v2/auth/google/code:
     *   post:
     *     description: log user (session) using Google code
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Google token"
     *            description: "Google token data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/GoogleCodeData"
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "400":
     *            description: "missing code and/or redirect_uri in request body"
     *          "401":
     *            description: "cannot authenticate with provided code"
     */
    app.options('/api/v2/auth/google/code', cors);
    app.post('/api/v2/auth/google/code', function(req, res) {
        // To test that endpoint you can get a code in the callback url you have when login via
        // https://accounts.google.com/o/oauth2/auth?approval_prompt=force&client_id=<client_id&redirect_uri=<redirect_uri>&response_type=code&scope=https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/userinfo.profile&state=%257Bredirect%3Dhttps%253A%252F%252Flocalhost.rts.ch%253A8443%252F,source%3Dnull%257D
        // client_id could be 428910240917-u18132kf0qrp347gjb5ddnsco6mp8u3g.apps.googleusercontent.com (it has to be the same as the one in config.identity_providers.google.client_id)
        // redirect_uri could be http://localhost
        if (!req.body.code || !req.body.redirect_uri) {
            return res.status(400).json({error: 'missing code and/or redirect_uri in request body'}).send();
        }
        authViaCode(req.body.code, req.body.redirect_uri, req, res);
    });

    function authViaCode(code, redirectUri, req, res) {
        googleHelper.getGoogleToken(code, redirectUri).then(function(token) {
            if (!token) {
                return res.status(401).json({error: 'Cannot authenticate with google'}).send();
            } else {
                authViaToken(token, req, res);
            }
        });
    }


    function authViaToken(token, req, res) {
        // Step 1: verify token
        return googleHelper.verifyGoogleIdToken(token).then((gmailUser) => {

            // Step 2: find or create user in IDP Db
            socialLoginHelper.findOrCreateSocialLoginUser(
                socialLoginHelper.GOOGLE,
                gmailUser.email,
                gmailUser.provider_uid,
                gmailUser.display_name,
                null,
                null,
                null,
                null).then(function(user) {
                if (user) {
                    db.SocialLogin.findOne({
                        where: {
                            user_id: user.id,
                            name: socialLoginHelper.GOOGLE
                        }
                    }).then(function(socialLogin) {
                        // Step 3: Log last login
                        socialLogin.logLogin(user);
                        afterLoginHelper.afterLogin(user, gmailUser.email, res);

                        // Step 4: Finally log the user
                        req.logIn(user, function() {
                            res.sendStatus(204);
                        });
                    });
                } else {
                    return res.status(412).json(errorHelper.buildError("AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL",
                        "It's not allowed to login with a gmail account on an account using the same email as local login if the local login is not validated.")).send();
                }
            }).catch(function(err) {
                logger.info('An error occurred while saving user in IDP db', err);
                return res.status(401).json({error: 'An error occurred while saving user in IDP db'}).send();

            });
        }).catch(function(err) {
            logger.info('An error occurred while verifying google token', err);
            return res.status(401).json({error: 'An error occurred while verifying google token'}).send();
        });
    }

};
