"use strict";

var passport = require('passport');
var cors = require('cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models');
var userHelper = require('../../../../lib/user-helper');
var authHelper = require('../../../../lib/auth-helper');
var passport = require('passport');
var dateFormat = require('dateformat');

var user_profile = function (req, res) {
    logger.debug('[API-V2][Profile][user_id', req.user.id, ']');
    if (req.user.LocalLogin) {
        let data = {
            user: {
                id: req.user.id,
                email: req.user.LocalLogin ? req.user.LocalLogin.login : null,
                email_verified: req.user.LocalLogin && req.user.LocalLogin.verified ? true : false,
                display_name: req.user.display_name,
                name: req.user.display_name || (req.user.LocalLogin ? req.user.LocalLogin.login : ''),
                firstname: req.user.firstname,
                lastname: req.user.lastname,
                gender: req.user.gender,
                date_of_birth: req.user.date_of_birth,
                date_of_birth_ymd: req.user.date_of_birth_ymd ? dateFormat(req.user.date_of_birth_ymd, "yyyy-mm-dd") : null,
            }
        };
        if (req.authInfo && req.authInfo.scope) {
            data.score = req.authInfo.scope;
        }
        res.json(data);
    } else {
        db.SocialLogin.findOne({where: {user_id: req.user.id}}).then(function (socialLogin) {
            let data = {
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
                    date_of_birth_ymd: socialLogin.date_of_birth_ymd ? dateFormat(socialLogin.date_of_birth_ymd, "yyyy-mm-dd") : null,
                }
            };
            if (req.authInfo && req.authInfo.scope) {
                data.score = req.authInfo.scope;
            }
            res.json(data);
        });
    }
};


var user_profile_update =
    function (req, res) {
        logger.debug('[API-V2][Profile udpate][user_id', req.user.id, ']');
        userHelper.validateProfileUpdateData(req).then(function (result) {
            if (!result.isEmpty()) {
                result.useFirstErrorOnly();
                res.status(400).json({errors: result.array({onlyFirstError: true})});
                return;
            }
            userHelper.updateProfile(req.user, req.body).then(
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

    /**
     * @swagger
     * definition:
     *  Profile:
     *      properties:
     *          user:
     *              type: object
     *              properties:
     *                  id:
     *                      type: integer
     *                      example: 42
     *                      description: database primary key
     *                      required: true
     *                  firstName:
     *                      type: string
     *                      example: John
     *                      description: user firstname
     *                  lastName:
     *                      type: string
     *                      example: Doe
     *                      description: user lastname
     *                  display_name:
     *                      type: string
     *                      example: John Doe
     *                      description: user display name
     *                  email:
     *                      type: string
     *                      example: john@doe.com
     *                      description: user email
     *                  email_verified:
     *                      type: string
     *                      example: false
     *                      description: true if email had benn verified
     *                  gender:
     *                      type: string
     *                      enum: [other, male, female]
     *                      example: male
     *                      description: user gender
     *                  date_of_birth:
     *                      type: integer
     *                      example: 12345678
     *                  date_of_birth_ymd:
     *                      type: string
     *                      example: 2018-08-31
     *                      description: user data of birth using yyyy-mm-dd format
     *          scope:
     *              type: string
     *              description: oAuth2 stuff
     */

        // TODO configure the restriction of origins on the CORS preflight call
    var cors_headers = cors({origin: true, methods: ['GET, PUT']});


    /**
     * @swagger
     * /api/v2/oauth2/user/profile:
     *   get:
     *     description: get logged (oAuth token) user profile
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.get('/api/v2/oauth2/user/profile', cors_headers, passport.authenticate('bearer', {session: false}), user_profile);
    router.put('/api/v2/oauth2/user/profile', cors_headers, passport.authenticate('bearer', {session: false}), user_profile_update);
    router.options('/api/v2/oauth2/user/profile', cors_headers);


    /**
     * @swagger
     * /api/v2/session/user/profile:
     *   get:
     *     description: get logged (session cookie) user profile
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.get('/api/v2/session/user/profile', cors_headers, authHelper.ensureAuthenticated, user_profile);
    router.put('/api/v2/session/user/profile', cors_headers, authHelper.ensureAuthenticated, user_profile_update);
    router.options('/api/v2/session/user/profile', cors_headers);


    /**
     * @swagger
     * /api/v2/jwt/user/profile:
     *   get:
     *     description: get logged (jwt) user profile
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.get('/api/v2/jwt/user/profile', cors_headers, passport.authenticate('jwt', {session: false}), user_profile);
    router.put('/api/v2/jwt/user/profile', cors_headers, passport.authenticate('jwt', {session: false}), user_profile_update);
    router.options('/api/v2/jwt/user/profile', cors_headers);

    // router.get('/api/v2/cpa/profile', cors_headers, xxx, user_profile);
    // router.put('/api/v2/cpa/profile', cors_headers, xxx, user_profile_update);
    // router.options('/api/v2/cpa/user/profile', cors_headers);
};