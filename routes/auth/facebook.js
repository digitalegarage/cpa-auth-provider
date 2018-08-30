"use strict";

var config = require('../../config');
var requestHelper = require('../../lib/request-helper');
var facebookHelper = require('../../lib/facebook-helper');

var passport = require('passport');

var REQUESTED_PERMISSIONS = ['email', 'user_birthday'];

passport.use(facebookHelper.getFacebookStrategy('/auth/facebook/callback'));

module.exports = function (app, options) {
    app.get('/auth/facebook', passport.authenticate('facebook', {scope: REQUESTED_PERMISSIONS}));

    app.get('/auth/facebook/callback',
        passport.authenticate('facebook', {failureRedirect: config.urlPrefix + '/auth?error=LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB'}),
        function (req, res) {

            var redirectUri = req.session.auth_origin;
            delete req.session.auth_origin;

            req.session.save(
                function () {
                    if (redirectUri) {
                        return res.redirect(redirectUri);
                    }
                    // Successful authentication, redirect home.
                    requestHelper.redirect(res, '/');
                }
            );

        });
};

