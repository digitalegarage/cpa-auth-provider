'use strict';

const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const socialLoginHelper = require('../../../../lib/social-login-helper');
const afterLoginHelper = require('../../../../lib/afterlogin-helper');
const facebookHelper = require('../../../../lib/facebook-helper');
const request = require('request-promise');
const logger = require('../../../../lib/logger');
const db = require('../../../../models');
const passport = require('passport');
const apiErrorHelper = require('../../../../lib/api-error-helper');

var REQUESTED_PERMISSIONS = ['email'];

const FACEBOOK_STRATEGY_NAME = 'facebookRedirect';
passport.use(FACEBOOK_STRATEGY_NAME, facebookHelper.getFacebookStrategy('/api/v2/auth/facebook/callback'));

module.exports = function(app, options) {

    app.options('/api/v2/auth/facebook', cors);
    app.get('/api/v2/auth/facebook', passport.authenticate(FACEBOOK_STRATEGY_NAME, {scope: REQUESTED_PERMISSIONS}));

    app.options('/api/v2/auth/facebook/callback', cors);
    app.get('/api/v2/auth/facebook/callback',
        passport.authenticate(FACEBOOK_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/login?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB'}), function(req, res) {

            socialLoginHelper.afterSocialLoginSucceed(req, res);

        });

    /**
     * @swagger
     * definitions:
     *   FBCodeData:
     *      type: "object"
     *      properties:
     *           code:
     *               type: "string"
     *               example: "AQDubYxjE3f9eKc5giY5rT1m8Cfumx3Fyb-UVwrHglj_RfNpfbMbdNcDj8DtUN3l4dIvC_NIzAGI9KebNKJ1H3sqLJq8QZg9nnJvKxfWglN6dmL7Ysk98kvVQ9wHvTcF50CZZ6F-9wUz59-q-Z5MlgcJgwPm_zvu_MpNabewH6-Nn9xOgPOs2FQVHqZcdRppZ2GQ8PIQliRNjZ2kYUn6xqBoBMSRoffzkeTBvFUpTMKRfxlBIe2u9MpJ_L9awQi_usA4GRx6V5uJUmBdhefDyFLThynYnHq7AWuA3k1hkIGVbweZkeFZW76rfoO0WodHuVn7cfniCy6iWYnmgnPqXm1a"
     *               description: "A facebook oAuth code"
     *           redirect_uri:
     *               type: "string"
     *               example: "http://demo-peach.ebu.io/idp/api/v2/auth/facebook/callback"
     *               description: "Redirect uri that had been used to get the code"
     *
     *   FBTokenData:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "EAAeu393hv5gBAO7eEHXZBo24SJCUbgUZBuMgO69GvGQriNQ03ePFqMBf9o9JwAa8tlTwyQHKSqsOAZBsZAAzWnlCyDz57ZBSbGfBgPX8CaK3fkb6LAqzILrXyGF43gCtZB88kBxAZCK3AmW0ECqgRaaiDznDb88XCNaZCsQJIL98mrk63bivI3Oe"
     *               description: "A facebook oAuth token"
     *
     */

    /**
     * @swagger
     * /api/v2/auth/facebook/code:
     *   post:
     *     description: "log user (session) using FB code. Possible errors are: CODE_MISSING, AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL, UNEXPECTED_ERROR"
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Facebook code"
     *            description: "FB code data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/FBCodeData"
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
    app.options('/api/v2/auth/facebook/code', cors);
    app.post('/api/v2/auth/facebook/code', function(req, res, next) {
        if (!req.body.code || !req.body.redirect_uri) {
            next(apiErrorHelper.buildError(400, "CODE_MISSING", "missing code in request body"));
        }

        // Request an access token from the code
        let options = {
            uri: 'https://graph.facebook.com/v3.2/oauth/access_token?' +
                'redirect_uri=' + req.body.redirect_uri +
                '&client_id=' + config.identity_providers.facebook.client_id +
                '&client_secret=' + config.identity_providers.facebook.client_secret +
                '&code=' + req.body.code,
            json: true,
        };

        request(options)
        .then(function(tokenJsonResponse) {
            return validateTokenAndLog(tokenJsonResponse.access_token, res, req);
        }).then(()=> {
            res.sendStatus(204);
        }).catch(function(err) {
            logger.info('An error occurred while requesting the token', err);
            next(apiErrorHelper.buildError(401, "UNEXPECTED_ERROR", "An error occurred while requesting the token"));
        });

    });

    /**
     * @swagger
     * /api/v2/auth/facebook/token:
     *   post:
     *     description: "log user (session) using FB token. Possible errors are: TOKEN_MISSING, AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL, UNEXPECTED_ERROR"
     *     tags: [AUTH]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Facebook token"
     *            description: "FB token data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/FBTokenData"
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
    app.options('/api/v2/auth/facebook/token', cors);
    app.post('/api/v2/auth/facebook/token', function(req, res, next) {
        if (!req.body.token) {
            next(apiErrorHelper.buildError(400, "TOKEN_MISSING", "missing token in request body"));
        } else {
            validateTokenAndLog(req.body.token, res, req)
            .then(()=>{
                res.sendStatus(204);
            })
            .catch((err)=> {
                next (err);
            });
        }
    });

};

function validateTokenAndLog(accessToken, res, req) {

    return new Promise((resolve, reject) => {

        // Step 1: validate access token

        let options = {
            uri: 'https://graph.facebook.com/debug_token?' +
                'input_token=' + accessToken +
                '&access_token=' + config.identity_providers.facebook.client_id + '|' + config.identity_providers.facebook.client_secret,
            json: true,
        };
        return request(options).then(function(jsonResponse) {

            if (!jsonResponse.data || !jsonResponse.data.user_id) {
                reject(apiErrorHelper.buildError(401, "UNEXPECTED_ERROR", "An error occured while validating the token with facebook"));
            } else {

                // Step 2: request user profile to graph API

                let options = {
                    uri: 'https://graph.facebook.com/v3.2/me?' +
                        'fields=id,name,email,first_name,last_name,gender' +
                        '&access_token=' + accessToken,
                    json: true,
                };
                return request(options).then(function(profile) {

                    // Step 3: find or create user in IDP Db

                    return socialLoginHelper.findOrCreateSocialLoginUser(
                        socialLoginHelper.FB,
                        profile.email,
                        jsonResponse.data.user_id,
                        profile.name,
                        profile.first_name,
                        profile.last_name,
                        profile.gender,
                        null) // Gender is null "The field 'birthday' is only accessible on the User object after the user grants the 'user_birthday' permission."
                    .then(function(user) {
                        if (user) {
                            return db.SocialLogin.findOne({
                                where: {
                                    user_id: user.id,
                                    name: socialLoginHelper.FB,
                                },
                            }).then(function(socialLogin) {
                                // Step 4: Log last login
                                return socialLogin.logLogin(user);
                            }).then(()=> {
                                return afterLoginHelper.afterLogin(user, profile.email, res);
                            }).then(()=>{
                                // Step 5: Finally log the user
                                return req.logIn(user, function() {
                                    resolve();
                                });
                            });
                        } else {
                            reject(apiErrorHelper.buildError(412, "AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL",
                                "It's not allowed to login with a facebook account on an account using the same email as local login if the local login is not validated."));
                        }
                    }).catch(function(err) {
                        logger.info('An error occurred while saving user in IDP db', err);
                        reject(apiErrorHelper.buildError(401, "UNEXPECTED_ERROR", "An error occurred while saving user in IDP db"));
                    });
                }).catch(function(err) {
                    logger.info('An error occurred while retrieving user data using the token', err);
                    reject(apiErrorHelper.buildError(401, "UNEXPECTED_ERROR", "An error occurred while verifying facebook token"));
                });
            }
        }).catch(function(err) {
            logger.info('An error occured while validating the token', err);
            reject(apiErrorHelper.buildError(401, "UNEXPECTED_ERROR", "An error occurred while verifying facebook token"));
        });
    });

}