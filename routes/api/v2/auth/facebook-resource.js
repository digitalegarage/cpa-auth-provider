"use strict";

var config = require('../../../../config');
var requestHelper = require('../../../../lib/request-helper');
var facebookHelper = require('../../../../lib/facebook-helper');

var passport = require('passport');

var REQUESTED_PERMISSIONS = ['email', 'user_birthday'];

const FACEBOOK_STRATEGY_NAME = 'facebookRedirect';
passport.use(FACEBOOK_STRATEGY_NAME, facebookHelper.getFacebookStrategy('/api/v2/auth/facebook/callback'));

module.exports = function (app, options) {
    app.get('/api/v2/auth/facebook', passport.authenticate(FACEBOOK_STRATEGY_NAME, {scope: REQUESTED_PERMISSIONS}));

    app.get('/api/v2/auth/facebook/callback', passport.authenticate(FACEBOOK_STRATEGY_NAME, {failureRedirect: config.urlPrefix + '/auth?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB'}), function (req, res) {

        return res.redirect(requestHelper.getPath('/api/v2/session/cookie?redirect=' + config.baseUrl + '/user/profile'));

    });
};

