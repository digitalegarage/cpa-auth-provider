"use strict";

const cors = require('../../../../lib/cors');
var config = require('../../../../config');
var socialLoginHelper = require('../../../../lib/social-login-helper');
var googleHelper = require('../../../../lib/google-helper');

var passport = require('passport');


const GOOGLE_STRATEGY_NAME = 'googleRedirect';

passport.use(GOOGLE_STRATEGY_NAME, googleHelper.getGoogleStrategy('/api/v2/auth/google/callback'));


module.exports = function (app, options) {

    app.options('/api/v2/auth/google', cors);
    app.get('/api/v2/auth/google', passport.authenticate(GOOGLE_STRATEGY_NAME, {scope: ['profile', 'email'], prompt: 'select_account'}));

    app.options('/api/v2/auth/google/callback', cors);
    app.get('/api/v2/auth/google/callback', passport.authenticate(GOOGLE_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/login?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_GOOGLE'}), function (req, res) {

        socialLoginHelper.afterSocialLoginSucceed(req, res);

    });
};
