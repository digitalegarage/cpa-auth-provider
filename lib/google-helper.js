"use strict";

var config = require('../config');

const {OAuth2Client} = require('google-auth-library');
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
    var client = new OAuth2Client(config.identity_providers.google.client_id,
        config.identity_providers.google.client_secret,
        redirectUri
    );
    return new Promise(function (resolve, reject) {
        client.getToken(code, function(err, token){
            if(err){
                reject(err);
            }
            resolve(token);
        });
    });
}

async function verifyGoogleIdToken(token) {
    var client = new OAuth2Client(
        config.identity_providers.google.client_id,
        config.identity_providers.google.client_secret
    );
    let tokeninfo = await client.getTokenInfo(token);

    return new Promise(function (resolve, reject) {
        
        if(tokeninfo.sub && tokeninfo.email){
            var user = {
                provider_uid: tokeninfo.sub,
                // NOT AVAIABLE IN THIS VERSION display_name: tokeninfo.name,
                email: tokeninfo.email
            };
            resolve(user);
        }
        
        // reject({message: 'No user with this google id were found'});
        logger.debug('unexpected error', tokeninfo);
        reject({message: 'unexpected error see logs'});
        
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