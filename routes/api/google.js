"use strict";

var socialLoginHelper = require('../../lib/social-login-helper');
var cors = require('../../lib/cors');
var googleHelper = require('../../lib/google-helper');
var finder = require ('../../lib/finder');
var apiErrorHelper = require('../../lib/api-error-helper');

module.exports = function (app, options) {
    /**
     * @swagger
     * definitions:
     *  GoogleToken:
     *      type: "object"
     *      properties:
     *           googleToken:
     *               type: "string"
     *               example: "345678765432345678765432aef"
     *               description: "Google token"
     */

    /**
     * @swagger
     * /api/v2/signup/google:
     *   post:
     *     description: facegooglebook signup
     *     tags: [AUTH]
     *     operationId: "googleSignup"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "googleToken"
     *            description: "google token"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/googleToken"
     *     responses:
     *          "200":
     *            description: "signup succeed"
     */


    app.post('/api/v2/signup/google', cors, function (req, res, next) {
        googleSignup(req, res, next);
    });
};

function googleSignup(req, res, next) {
    var googleIdToken = req.body.idToken;
    var remoteProfile;

    if (googleIdToken && googleIdToken.length > 0) {
        googleHelper.verifyGoogleIdToken(googleIdToken).then(
            function (googleProfile) {
                // If the googleProfile already exists and his account is not validated
                // i.e.: there is a user in the database with the same id and this user email is not validated
                remoteProfile = socialLoginHelper.buildRemoteProfile(googleHelper.buildGoogleId(googleProfile.provider_uid), googleProfile.display_name, googleProfile.email, googleProfile.givenName, googleProfile.familyName, googleProfile.gender, null);
                return finder.findUserByLocalAccountEmail(googleProfile.email);
            }
        ).then(
            function (localLoginInDb) {
                if (localLoginInDb && !localLoginInDb.verified) {
                    next(apiErrorHelper.buildError(400, 'LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_GOOGLE', 'Login invalid by google.', req.__("LOGIN_INVALID_EMAIL_BECAUSE_NOT_VALIDATED_GOOGLE")));
                } else {
                    socialLoginHelper.performLogin(remoteProfile, socialLoginHelper.GOOGLE, req.body.client_id, function (error, response) {
                        if (response) {
                            res.status(200).json(response);
                        } else {
                            next(500, 'INTERNAL_SERVER_ERROR.GOOGLE_LOGIN', 'Google login error.', '', [], error.message);
                        }
                    });
                }
            }
        ).catch(
            function (error) {
                next(500, 'INTERNAL_SERVER_ERROR.GOOGLE_LOGIN', 'Google login error.', '', [], error.message);
            }
        );
    }
    else {
        next(apiErrorHelper.buildError(401,'GOOGLE_PROFILE_NOT_FOUND',"Missing google ID token to connect with Google account."));
    }
}

