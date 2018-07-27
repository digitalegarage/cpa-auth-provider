"use strict";

var passport = require('passport');
var cors = require('cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models');
var userHelper = require('../../../../lib/user-helper');
var authHelper = require('../../../../lib/auth-helper');
var passport = require('passport');


var user_profile = function (req, res) {
    logger.debug('[API-V2][Profile][user_id', req.user.id, ']');
    if (req.user.LocalLogin) {
        res.json({
            user: {
                id: req.user.id,
                email: req.user.LocalLogin ? req.user.LocalLogin.login : null,
                email_verified: req.user.LocalLogin ? req.user.LocalLogin.verified : null,
                display_name: req.user.display_name,
                name: req.user.display_name || (req.user.LocalLogin ? req.user.LocalLogin.login : ''),
                firstname: req.user.firstname,
                lastname: req.user.lastname,
                gender: req.user.gender,
                date_of_birth: req.user.date_of_birth,
                date_of_birth_ymd: req.user.date_of_birth_ymd,
            },
           scope: req.authInfo && req.authInfo.scope ? req.authInfo.scope : null
        });
    } else {
        db.SocialLogin.findOne({where: {user_id: req.user.id}}).then(function (socialLogin) {
            res.json({
                user: {
                    id: req.user.id,
                    email: socialLogin.email,
                    email_verified: true,
                    display_name: socialLogin.display_name ? socialLogin.display_name : socialLogin.email,
                    name: socialLogin.display_name ? socialLogin.display_name : socialLogin.email,
                    firstname: socialLogin.firstname,
                    lastname: socialLogin.lastname,
                    gender: socialLogin.gender,
                    date_of_birth: socialLogin.date_of_birth,
                    date_of_birth_ymd: socialLogin.date_of_birth_ymd
                },
                scope: req.authInfo && req.authInfo.scope ? req.authInfo.scope : null
            });
        });
    }
};


var user_profile_update =
    function (req, res) {
        logger.debug('[API-V2][Profile udpate][user_id', req.user.id, ']');
        userHelper.validateProfileUpdateDataV2(req).then(function (result) {
            if (!result.isEmpty()) {
                result.useFirstErrorOnly();
                res.status(400).json({errors: result.array({onlyFirstError: true})});
                return;
            }
            userHelper.updateProfileV2(req.user, req.body).then(
                function () {
                    res.json({msg: req.__('BACK_PROFILE_UPDATE_SUCCESS')});
                },
                function (err) {
                    logger.error('[PUT /user/profile][ERROR', err, ']');
                    res.status(500).json({msg: req.__('BACK_PROFILE_UPDATE_FAIL') + err});
                }
            );
        });
    };


module.exports = function (router) {

    // TODO :
    // - swagger
    // - CPA
    // use that endpoint with profile page

    // TODO configure the restriction of origins on the CORS preflight call
    var cors_headers = cors({origin: true, methods: ['GET']});
    router.options('/api/v2/oauth2/profile', cors_headers);

    router.get('/api/v2/oauth2/profile', cors_headers, passport.authenticate('bearer', {session: false}), user_profile);
    router.put('/api/v2/oauth2/profile', cors_headers, passport.authenticate('bearer', {session: false}), user_profile_update);

    router.get('/api/v2/session/profile', cors_headers, authHelper.ensureAuthenticated, user_profile);
    router.put('/api/v2/session/profile', cors_headers, authHelper.ensureAuthenticated, user_profile_update);

    router.get('/api/v2/jwt/profile', cors_headers, passport.authenticate('jwt', {session: false}), user_profile);
    router.put('/api/v2/jwt/profile', cors_headers, passport.authenticate('jwt', {session: false}), user_profile_update);

    // router.get('/api/v2/cpa/profile', cors_headers, xxx, user_profile);
    // router.put('/api/v2/cpa/profile', cors_headers, xxx, user_profile_update);
};