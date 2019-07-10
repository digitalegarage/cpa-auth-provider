"use strict";

var db = require('../../models');
var socialLoginHelper = require('../../lib/social-login-helper');
var request = require('request');
var cors = require('../../lib/cors');
var facebookHelper = require('../../lib/facebook-helper');
var apiErrorHelper = require('../../lib/api-error-helper');

module.exports = function (app, options) {

    app.post('/api/facebook/signup', cors, function (req, res, next) {
        facebookSignup(req, res, next);
    });
};

function verifyFacebookUserAccessToken(token, done) {
    var path = 'https://graph.facebook.com/me?fields=id,email,name,first_name,last_name,gender,birthday&access_token=' + token;
    request(path, function (error, response, body) {
        var data = JSON.parse(body);
        if (!error && response && response.statusCode && response.statusCode === 200) {
            var remoteProfile = socialLoginHelper.buildRemoteProfile(facebookHelper.buildFBId(data.id), data.name, data.email, data.first_name, data.last_name, data.gender, facebookHelper.fbDateOfBirthToTimestamp(data.birthday));
            done(null, remoteProfile);
        } else {
            done({code: response.statusCode, message: data.error.message}, null);
        }
    });
}

function facebookSignup(req, res, next) {
    var facebookAccessToken = req.body.fbToken;
    if (facebookAccessToken && facebookAccessToken.length > 0) {
        // Get back user object from Facebook
        verifyFacebookUserAccessToken(facebookAccessToken, function (err, remoteProfile) {
            if (remoteProfile) {
                // If the user already exists and his account is not validated
                // i.e.: there is a user in the database with the same id and this user email is not validated
                db.LocalLogin.find({
                    where: {
                        login: remoteProfile.email
                    }
                }).then(function (localLoginInDb) {
                    if (localLoginInDb && !localLoginInDb.verified) {
                        next(apiErrorHelper.buildError(400, 'LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB', 'Login invalid by facebook.', req.__("LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_FB")));
                    } else {
                        socialLoginHelper.performLogin(remoteProfile, socialLoginHelper.FB, req.body.client_id, function (error, response) {

                            if (response) {
                                res.status(200).json(response);
                            } else {
                                next(500, 'INTERNAL_SERVER_ERROR.FACEBOOK_LOGIN', 'Facebook login error.', '', [], error.message);
                            }
                        });
                    }
                });

            } else {
                next(apiErrorHelper.buildError(401,'FACEBOOK_PROFILE_NOT_FOUND',"No valid facebook profile found."));
            }
        });
    }
    else {
        // 400 BAD REQUEST
        console.log('error', 'Bad login request from ' +
            req.connection.remoteAddress + '. Reason: facebook access token and application name are required.');
        next(apiErrorHelper.buildError(400, 'BAD_REQUEST.FACEBOOK', 'Bad login request from ' +
            req.connection.remoteAddress + '. Reason: facebook access token and application name are required.'));
    }
}

