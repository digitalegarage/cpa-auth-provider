"use strict";

var config = require('../config');

var {GoogleAuth} = require('google-auth-library');
var auth = new GoogleAuth({scopes: 'https://www.googleapis.com/auth/cloud-platform'});
var client = auth.getClient().then(function(c){return c;});
var logger = require('./logger');
var GoogleStrategy = require('passport-google-oauth20');
var callbackHelper = require('../lib/callback-helper');
var socialLoginHelper = require ('../lib/social-login-helper');
var db = require('../models/index');


function getGoogleStrategy(callbackUrl) {
    return new GoogleStrategy({
            clientID: config.identity_providers.google.client_id,
            clientSecret: config.identity_providers.google.client_secret,
            callbackURL: callbackHelper.getURL(callbackUrl)
        },
        function (accessToken, refreshToken, profile, done) {
            var email = '';
            if (profile.emails !== undefined) {
                email = profile.emails[0].value;
            }

            if (email === '') {
                return done(new Error('NO_EMAIL'));
            }

            var providerUid = buildGoogleId(profile.id);

            return socialLoginHelper.findOrCreateSocialLoginUser(socialLoginHelper.GOOGLE, email, providerUid, profile.displayName, profile.name.givenName, profile.name.familyName, profile.gender, null).then(
                function (user) {
                    if (user) {
                        db.SocialLogin.findOne({
                            where: {
                                user_id: user.id,
                                name: socialLoginHelper.GOOGLE
                            }
                        }).then(function (socialLogin) {
                            socialLogin.logLogin(user);
                        });
                    }
                    return done(null, user);
                }
            ).catch(
                function (err) {
                    done(err);
                }
            );
        });
}

function getGoogleToken(code, redirectUri){
    return new Promise(function (resolve, reject) {
        return new auth.OAuth2(config.identity_providers.google.client_id, config.identity_providers.google.client_secret, redirectUri).getToken(code, function (err, tokens, response){
            if (err){
                return reject(err);
            }
            resolve(tokens.id_token);
        });
    });
}

function verifyGoogleIdToken(token) {
    return new Promise(function (resolve, reject) {
        client.verifyIdToken(token, config.identity_providers.google.client_id, function (e, login) {
            if (e) {
                logger.debug('unexpected error', e);
                return reject({message: 'unexpected error see logs'});
            }
            var payload = login.getPayload();
            var data = payload;

            if (data) {
                var user = {
                    provider_uid: data.sub,
                    display_name: data.name,
                    email: data.email
                };
                return resolve(user);
            } else {
                return reject({message: 'No user with this google id were found'});
            }
        });
    });
}

function buildGoogleId(id) {
    return 'google:' + id;
}

module.exports = {
    verifyGoogleIdToken: verifyGoogleIdToken,
    buildGoogleId: buildGoogleId,
    getGoogleStrategy: getGoogleStrategy,
    getGoogleToken: getGoogleToken
};