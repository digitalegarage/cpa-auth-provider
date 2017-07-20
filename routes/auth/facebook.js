"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');

var passport = require('passport');
var FacebookStrategy = require('passport-facebook').Strategy;

function findOrCreateExternalUser(email, defaults) {
    return new Promise(function (resolve, reject) {
        db.User.find(
            {
                where: {
                    email: email
                }
            }
        ).then(
            function (user) {
                if (!user) {
                    return db.User.findOrCreate(
                        {
                            where: {
                                email: email
                            },
                            defaults: defaults
                        }
                    ).spread(
                        function (user, created) {
                            return resolve(user);
                        }
                    ).catch(reject);
                }
                if (!user.verified) {
                    return reject(new Error('NOT_VERIFIED'));
                }
                return user.updateAttributes(
                    defaults
                ).then(resolve, reject);
            },
            reject
        )
    });
}

passport.use(new FacebookStrategy({
        clientID: config.identity_providers.facebook.client_id,
        clientSecret: config.identity_providers.facebook.client_secret,
        callbackURL: config.identity_providers.facebook.callback_url,
        profileFields: ['id', 'emails', 'displayName']
    },
    function (accessToken, refreshToken, profile, done) {
        var email = '';
        if(profile.emails !== undefined) {
            email = profile.emails[0].value;
        }

        if (email === '') {
            // how to react to such an error!?
            return done(new Error('NO_EMAIL', null));
        }

        var providerUid = 'fb:' + profile.id;

        return findOrCreateExternalUser(
            email,
            {
                provider_uid: providerUid,
                display_name: profile.displayName,
                verified: true
            }
        ).then(
            function(u) {
                u.logLogin();
                return done(null, u);
            }
        ).catch(
            done
        );

        db.User.findOrCreate({
            where: {
                provider_uid: "fb:" + profile.id
            }
        }).spread(function (user) {
            if(!user.verified && email !== '') {
                user.updateAttributes({
                    display_name: user.displayName,
                    email: email,
                    verified: true
                }).then(function () {
                    user.logLogin();
                });
            } else {
                user.logLogin();
            }

            return done(null, user);
        }).catch(function (err) {
            done(err, null);
        });
    }
));

module.exports = function (app, options) {
    app.get('/auth/facebook', passport.authenticate('facebook', { scope : ['email'] }));

    app.get('/auth/facebook/callback', passport.authenticate('facebook', {
        failureRedirect: '/?error=login_failed'
    }), function (req, res, next) {

        var redirectUri = req.session.auth_origin;
        delete req.session.auth_origin;

        if (redirectUri) {
            return res.redirect(redirectUri);
        }

        requestHelper.redirect(res, '/');
    });
};
