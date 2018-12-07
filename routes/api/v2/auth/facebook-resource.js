'use strict';

const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const socialLoginHelper = require('../../../../lib/social-login-helper');
const facebookHelper = require('../../../../lib/facebook-helper');
const request = require('request-promise');
const logger = require('../../../../lib/logger');
const db = require('../../../../models');
const passport = require('passport');

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
     *     description: log user (session) using FB code
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
     */
    app.options('/api/v2/auth/facebook/code', cors);
    app.post('/api/v2/auth/facebook/code', function(req, res) {
        if (!req.body.code || !req.body.redirect_uri) {
            return res.status(400).json({error: 'missing code and/or redirect_uri in request body'}).send();
        }

        var options = {
            uri: 'https://graph.facebook.com/v3.2/oauth/access_token?' +
                'redirect_uri=' + 'https://localhost.ebu.io/unexistingurl' + //FIXME <===============================
                '&client_id=' + config.identity_providers.facebook.client_id +
                '&client_secret=' + config.identity_providers.facebook.client_secret +
                '&code=' + req.body.code,
            json: true,
        };

        return request(options).then(function(tokenJsonResponse) {
            validateTokenAndLog(tokenJsonResponse.access_token, res, req);
        }).catch(function(err) {
            logger.info('An error occured while requesting the token', err);
            return res.status(401).json({error: 'An error occured while requesting the token'}).send();
        });

    });

    /**
     * @swagger
     * /api/v2/auth/facebook/token:
     *   post:
     *     description: log user (session) using FB token
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
     */
    app.options('/api/v2/auth/facebook/token', cors);
    app.post('/api/v2/auth/facebook/token', function(req, res) {
        if (!req.body.token) {
            return res.status(400).json({error: 'missing token in request body'}).send();
        }
        validateTokenAndLog(req.body.token, res, req);

    });

};

function validateTokenAndLog(accessToken, res, req) {

    // Step 1: validate access token

    let options = {
        uri: 'https://graph.facebook.com/debug_token?' +
            'input_token=' + accessToken +
            '&access_token=' + config.identity_providers.facebook.client_id + '|' + config.identity_providers.facebook.client_secret,
        json: true,
    };
    request(options).then(function(jsonResponse) {

        if (!jsonResponse.data || !jsonResponse.data.user_id) {
            return res.status(401).json({error: 'An error occured while validating the token'}).send();
        } else {

            // Step 2: request user profile to graph API

            let options = {
                uri: 'https://graph.facebook.com/v3.2/me?' +
                    'fields=id,name,email,first_name,last_name,gender' +
                    '&access_token=' + accessToken,
                json: true,
            };
            request(options).then(function(profile) {

                // Step 3: find or create user in IDP Db

                socialLoginHelper.findOrCreateSocialLoginUser(
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
                        db.SocialLogin.findOne({
                            where: {
                                user_id: user.id,
                                name: socialLoginHelper.FB,
                            },
                        }).then(function(socialLogin) {
                            // Step 4: Log last login
                            socialLogin.logLogin(user);

                            // Step 5: Finally log the user
                            req.logIn(user, function() {
                                res.sendStatus(204);
                            });
                        });
                    } else {
                        return res.status(401).json({error: 'An error occurred while validating the token'}).send();
                    }
                }).catch(function(err) {
                    logger.info('An error occurred while saving user in IDP db', err);
                    return res.status(401).json({error: 'An error occurred while saving user in IDP db'}).send();

                });
            }).catch(function(err) {
                logger.info('An error occurred while retrieving user data using the token', err);
                return res.status(401).json({error: 'An error occurred while retrieving user data using the token'}).send();

            });
        }
    }).catch(function(err) {
        logger.info('An error occured while validating the token', err);
        return res.status(401).json({error: 'An error occured while validating the token'}).send();

    });
}