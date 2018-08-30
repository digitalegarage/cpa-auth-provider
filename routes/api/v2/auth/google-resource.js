"use strict";

var config = require('../../../../config');
var requestHelper = require('../../../../lib/request-helper');
var googleHelper = require('../../../../lib/google-helper');

var passport = require('passport');


const GOOGLE_STRATEGY_NAME = 'googleRedirect';

passport.use(GOOGLE_STRATEGY_NAME, googleHelper.getGoogleStrategy('/api/v2/auth/google/callback'));

module.exports = function (app, options) {
    app.get('/api/v2/auth/google', passport.authenticate(GOOGLE_STRATEGY_NAME, {scope: ['profile', 'email']}));

    app.get('/api/v2/auth/google/callback', passport.authenticate(GOOGLE_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/auth?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_GOOGLE'}), function (req, res) {

        return res.redirect(requestHelper.getPath('/api/v2/session/cookie?redirect=' + config.baseUrl + '/user/profile'));

    });
};
