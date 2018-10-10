"use strict";

var config = require('../../../../config');
var socialLoginHelper = require('../../../../lib/social-login-helper');
var facebookHelper = require('../../../../lib/facebook-helper');

var passport = require('passport');

var REQUESTED_PERMISSIONS = ['email'];

const FACEBOOK_STRATEGY_NAME = 'facebookRedirect';
passport.use(FACEBOOK_STRATEGY_NAME, facebookHelper.getFacebookStrategy('/api/v2/auth/facebook/callback'));

module.exports = function (app, options) {
    app.get('/api/v2/auth/facebook', passport.authenticate(FACEBOOK_STRATEGY_NAME, {scope: REQUESTED_PERMISSIONS}));

    app.get('/api/v2/auth/facebook/callback', passport.authenticate(FACEBOOK_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/login?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB'}), function (req, res) {

        socialLoginHelper.afterSocialLoginSucceed(req, res);

    });
};
