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

    app.post('/api/v2/auth/facebook/code', function(req, res) {
        if (!req.body.code) {
            return res.json({error: 'missing code in request body'}).status(400).send();
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
            const accessToken = tokenJsonResponse.access_token;

            validateTokenAndLog(accessToken, res, req);
        }).
        catch(function(err) {
            logger.info('An error occured while requesting the token', err);
            return res.json({error: 'An error occured while requesting the token'}).status(401).send();
        });

    });

    app.post('/api/v2/auth/facebook/token', function(req, res) {
        if (!req.body.token) {
            return res.json({error: 'missing token in request body'}).status(400).send();
        }
        validateTokenAndLog(req.body.token, res, req);

    });

};

function validateTokenAndLog(accessToken, res, req) {
    var options = {
        uri: 'https://graph.facebook.com/debug_token?' +
            'input_token=' + accessToken +
            '&access_token=' + config.identity_providers.facebook.client_id + '|' + config.identity_providers.facebook.client_secret,
        json: true,
    };
    request(options).then(function(jsonResponse) {

        if (!jsonResponse.data || !jsonResponse.data.user_id) {
            return res.json({error: 'An error occured while validating the token'}).status(401).send();
        } else {
            socialLoginHelper.findOrCreateSocialLoginUser(socialLoginHelper.FB, null, jsonResponse.data.user_id, null, null, null, null, null)  //FIXME <===============================
            .then(function(user) {
                if (user) {
                    db.SocialLogin.findOne({
                        where: {
                            user_id: user.id,
                            name: socialLoginHelper.FB,
                        },
                    }).then(function() {
                        req.logIn(user, function() {
                            res.sendStatus(204);
                        });
                    });
                } else {
                    return res.json({error: 'An error occured while validating the token'}).status(401).send();
                }
            });
        }
    }).catch(function(err) {
        logger.info('An error occured while validating the token', err);
        return res.json({error: 'An error occured while validating the token'}).status(401).send();

    });
}