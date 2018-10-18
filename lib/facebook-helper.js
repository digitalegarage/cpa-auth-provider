"use strict";

var FacebookStrategy = require('passport-facebook').Strategy;
var callbackHelper = require('../lib/callback-helper');
var socialLoginHelper = require('../lib/social-login-helper');
var config = require('../config');
var db = require('../models/index');

// Fields to import: Email, First and Last Name, Gender, Birthdate
// birthday => This is a fixed format string, like MM/DD/YYYY. However, people can control who can see the year they were born separately from the month and day so this string can be only the year (YYYY) or the month + day (MM/DD)
// gender =>  male or female
var REQUESTED_FIELDS = ['id', 'email', 'displayName', 'first_name', 'last_name', 'gender', 'birthday'];

// This is a fixed format string, like MM/DD/YYYY. However, people can control who can see the year they were born separately
// from the month and day so this string can be only the year (YYYY) or the month + day (MM/DD)
function fbDateOfBirthToTimestamp(fbDateOfBirth) {

    if (!fbDateOfBirth) {
        return null;
    }

    var year;
    var month;
    var day;
    var datePart = fbDateOfBirth.split("/");
    if (datePart.length === 3) {
        year = datePart[2];
        month = datePart[0];
        day = datePart[1];
    } else if (datePart.length === 2) {
        //year = new Date().getFullYear();
        month = datePart[0];
        day = datePart[1];
        // Cannot do anything without year
        return null;
    } else {
        throw "Unexpected data format on " + fbDateOfBirth + ". Format should be  MM/DD/YYYY or  MM/DD";
    }


    return new Date(Date.UTC(year, month - 1, day)).getTime();
}

function buildFBId(id) {
    return "fb:" + id;
}


function getFacebookStrategy(callBackUrl) {
    const fbConfig = {
        clientID: config.identity_providers.facebook.client_id,
        clientSecret: config.identity_providers.facebook.client_secret,
        callbackURL: callbackHelper.getURL(callBackUrl),
        profileFields: REQUESTED_FIELDS
    };
    console.log('reauthenticate with config', config);
    if (config.identity_providers && config.identity_providers.facebook && config.identity_providers.facebook.reauthenticate) {
        fbConfig.auth_type = "reauthenticate";
        console.log('while reauthenticate since value is', config.identity_providers.facebook.reauthenticate);

    }
    return new FacebookStrategy(fbConfig,
        function (accessToken, refreshToken, profile, done) {
            var email = '';
            if (profile.emails !== undefined) {
                email = profile.emails[0].value;
            }

            var providerUid = buildFBId(profile.id);

            return socialLoginHelper.findOrCreateSocialLoginUser(socialLoginHelper.FB, email, providerUid, profile.displayName, profile.name.givenName, profile.name.familyName, profile.gender, fbDateOfBirthToTimestamp(profile._json.birthday)).then(
                function (user) {
                    if (user) {
                        db.SocialLogin.findOne({
                            where: {
                                user_id: user.id,
                                name: socialLoginHelper.FB
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


module.exports = {
    fbDateOfBirthToTimestamp: fbDateOfBirthToTimestamp,
    buildFBId: buildFBId,
    getFacebookStrategy: getFacebookStrategy,

};