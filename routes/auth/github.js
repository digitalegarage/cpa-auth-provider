"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');

var passport = require('passport');
var GithubStrategy = require('passport-github').Strategy;

passport.use(new GithubStrategy({
        clientID: config.identity_providers.github.client_id,
        clientSecret: config.identity_providers.github.client_secret,
        callbackURL: config.identity_providers.github.url_callback
    },
    function (accessToken, refreshToken, profile, done) {
        db.User.findOrCreate({
            where: {
                provider_uid: "github:" + profile.id,
                display_name: profile.displayName
            }
        }).spread(function (user) {
            user.logLogin().then(function () {
            }, function () {
            });
            return done(null, user);
        }).catch(function (err) {
            done(err, null);
        });
    }
));

module.exports = function (app, options) {
    app.get('/auth/github',
        passport.authenticate('github'));

    app.get('/auth/github/callback', passport.authenticate('github', {
        failureRedirect: '/?error=login_failed'
    }), function (req, res, next) {

        var redirectUri = req.session.auth_origin;
        delete req.session.auth_origin;

        req.session.save(
            function () {
                if (redirectUri) {
                    return res.redirect(redirectUri);
                }

                requestHelper.redirect(res, '/');
            }
        );
    });
};
