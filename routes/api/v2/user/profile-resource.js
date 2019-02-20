"use strict";

const passport = require('passport');
const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const logger = require('../../../../lib/logger');
const uuidValidator = require('uuid-validate');
const userHelper = require('../../../../lib/user-helper');
const authHelper = require('../../../../lib/auth-helper');
const socialLoginHelper = require('../../../../lib/social-login-helper');

var user_profile = function(req, res) {
    logger.debug('[API-V2][Profile][user_id', req.user.id, ']');
    if (req.user) {
        let user = req.user;
        socialLoginHelper.getSocialEmails(user).then(function(emails) {
            var socialEmails = [];
            if (emails && emails.length > 0) {
                socialEmails = emails;
            }
            // var socialEmail = (emails && emails.length > 0) ? emails[0] : "";
            socialLoginHelper.getSocialLogins(user).then(function(logins) {
                var email = user.LocalLogin ? user.LocalLogin.login : undefined;
                var data = {
                    user: {
                        id: user.id,
                        email: email,
                        email_verified: !user.LocalLogin || user.LocalLogin.verified,
                        display_name: user.getDisplayName("FIRSTNAME_LASTNAME", email),
                        firstname: user.firstname,
                        lastname: user.lastname,
                        gender: user.gender,
                        date_of_birth: user.date_of_birth_ymd ? user.date_of_birth_ymd : null,
                        public_uid: user.public_uid,
                        language: user.language,
                        social_emails: socialEmails,
                        login: email,
                        has_password: user.LocalLogin && !!user.LocalLogin.password,
                        has_facebook_login: logins.indexOf(socialLoginHelper.FB) > -1,
                        has_google_login: logins.indexOf(socialLoginHelper.GOOGLE) > -1,
                        has_social_login: logins.length > 0,
                        has_local_login: user.LocalLogin && user.LocalLogin.login != null,
                    },
                    captcha: req.recaptcha,
                };
                if (req.authInfo && req.authInfo.scope) {
                    data.score = req.authInfo.scope;
                }
                res.json(data);
            });
        });
    } else {
        res.status(401).send();
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
                    res.status(204).send();
                },
                function (err) {
                    logger.error('[PUT /user/profile][ERROR', err, ']');
                    res.status(500).json({msg: req.__('BACK_PROFILE_UPDATE_FAIL') + err});
                }
            );
        });
    };

var user_nameByPublicUid = function(req,res,next) {
    if (config.allow_name_access_by_puid) {
        if (uuidValidator(req.params.puid, 4)) {
            userHelper.getUserNameByPublicId(req.params.puid)
            .then((username) => {
                if (!username) {
                    logger.error("UUID request for non-existant user",req.params.puid);
                    res.sendStatus(404);
                }
                else
                    res.json(username);
            })
            .catch((e) => {
                logger.error("Error fetching user name by public id",e);
                res.status(500);
            });
        } else {
            res.sendErrorResponse(400, "bad_request", "No valid UUIDv4!");
        }
    } else {
        res.sendErrorResponse(409, "disabled", "Service disabled by configuration.");
    }
};

module.exports = function (router) {

    /**
     * @swagger
     * definitions:
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
     *                  email:
     *                      type: string
     *                      example: john@doe.com
     *                      description: user email
     *                  email_verified:
     *                      type: boolean
     *                      example: false
     *                      description: true if email has been verified
     *                  display_name:
     *                      type: string
     *                      example: John Doe
     *                      description: user display name
     *                  firstName:
     *                      type: string
     *                      example: John
     *                      description: user firstname
     *                  lastName:
     *                      type: string
     *                      example: Doe
     *                      description: user lastname
     *                  gender:
     *                      type: string
     *                      enum: [other, male, female]
     *                      example: male
     *                      description: user gender
     *                  date_of_birth:
     *                      type: string
     *                      example: 2018-08-31
     *                      description: user data of birth using yyyy-mm-dd format
     *                  public_uid:
     *                      type: string
     *                      example: 2b61aade-f9b5-47c3-8b5b-b9f4545ec9f9
     *                      description: public id for unauthorized get of public data
     *                  language:
     *                      type: string
     *                      example: en
     *                      description: user language using 2 letters iso code
     *                  social_emails:
     *                      type: array
     *                      example: ['john.doe@gmail.com', 'john.doe@isp.com']
     *                      description: user emails' from social login
     *                  login:
     *                      type: string
     *                      example: john.doe@isp.com
     *                      description: user login (email in current implementation)
     *                  has_password:
     *                      type: boolean
     *                      example: true
     *                      description: user has defined a password / has a local login
     *                  has_facebook_login:
     *                      type: boolean
     *                      example: true
     *                      description: user has a facebook login on the IDP
     *                  has_google_login:
     *                      type: boolean
     *                      example: true
     *                      description: user has a google login on the IDP
     *                  has_social_login:
     *                      type: boolean
     *                      example: true
     *                      description: user has a social login (google of facebook in current implementation)
     *                  has_local_login:
     *                      type: boolean
     *                      example: true
     *                      description: user has a local login (login using username and password)
     *          scope:
     *              type: string
     *              description: oAuth2 stuff
     *
     *  ProfileUpdate:
     *      type: "object"
     *      properties:
     *           firstname:
     *               type: "string"
     *               example: "John"
     *               description: "user firstname"
     *           lastname:
     *               type: "string"
     *               example: "Doe"
     *               description: "user lastname"
     *           date_of_birth:
     *               type: "string"
     *               example: "2018-08-31"
     *               description: "user date of birth using yyyy-mm-dd format"
     *           gender:
     *               type: "string"
     *               example: "male"
     *               enum: [other, male, female]
     *               description: "user gender (might be 'male', 'female', 'other)"
     *           language:
     *               type: "string"
     *               example: "en"
     *               description: "user language (ISO 639-1)"
     *
     */

    /**
     * @swagger
     * /api/v2/oauth/user/profile:
     *   get:
     *     description: get logged (using oAuth token security) user profile
     *     tags: [OAUTH]
     *     parameters:
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: Bearer blablabla
     *            description: oAuth access token
     *            required: true
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.options('/api/v2/oauth/user/profile', cors);
    router.get('/api/v2/oauth/user/profile', cors, passport.authenticate('bearer', {session: false}), user_profile);

    /**
     * @swagger
     * /api/v2/oauth/user/profile:
     *   put:
     *     description: update user profile (using oAuth token security)
     *     tags: [OAUTH]
     *     operationId: "updateProfile"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "profile"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ProfileUpdate"
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: Bearer blablabla
     *            description: oAuth access token
     *            required: true
     *     responses:
     *          "204":
     *            description: "profile updated"
     *          "400":
     *            description: "bad update data"
     */
    router.put('/api/v2/oauth/user/profile', cors, passport.authenticate('bearer', {session: false}), user_profile_update);


    /**
     * @swagger
     * /api/v2/session/user/profile:
     *   get:
     *     description: get logged (using session cookie security) user profile
     *     tags: [Session]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.options('/api/v2/session/user/profile', cors);
    router.get('/api/v2/session/user/profile', cors, authHelper.ensureAuthenticated, user_profile);

    /**
     * @swagger
     * /api/v2/session/user/profile:
     *   put:
     *     description: update user profile (using session cookie security)
     *     tags: [Session]
     *     operationId: "updateProfile"
     *     content:
     *        - application/json
     *     parameters:
     *          -
     *            name: "profile"
     *            in: "body"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ProfileUpdate"
     *     responses:
     *          "204":
     *            description: "profile updated"
     *          "400":
     *            description: "bad update data"
     */
    router.put('/api/v2/session/user/profile', cors, authHelper.ensureAuthenticated, user_profile_update);

    /**
     * @swagger
     * /api/v2/jwt/user/profile:
     *   get:
     *     description: get logged (using JWT token security) user profile
     *     tags: [JWT]
     *     parameters:
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: JWT blablabla
     *            description: JWT token
     *            required: true
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.options('/api/v2/jwt/user/profile', cors);
    router.get('/api/v2/jwt/user/profile', cors, passport.authenticate('jwt', {session: false}), user_profile);

    /**
     * @swagger
     * /api/v2/jwt/user/profile:
     *   put:
     *     description: update user profile (using JWT token security)
     *     tags: [JWT]
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "profile"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ProfileUpdate"
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: JWT blablabla
     *            description: JWT token
     *            required: true
     *     responses:
     *          "204":
     *            description: "profile updated"
     *          "400":
     *            description: "bad update data"
     */
    router.put('/api/v2/jwt/user/profile', cors, passport.authenticate('jwt', {session: false}), user_profile_update);

    /**
     * @swagger
     * /api/v2/cpa/user/profile:
     *   get:
     *     description: get logged (using CPA token security) user profile
     *     tags: [CPA]
     *     parameters:
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: blablabla
     *            description: CPA token
     *            required: true
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Return logged user profile
     *         schema:
     *           $ref: '#/definitions/Profile'
     */
    router.options('/api/v2/cpa/user/profile', cors);
    router.get('/api/v2/cpa/user/profile', cors, authHelper.ensureCpaAuthenticated, user_profile);

    /**
     * @swagger
     * /api/v2/cpa/user/profile:
     *   put:
     *     description: update user profile (using CPA token security)
     *     tags: [CPA]
     *     operationId: "updateProfile"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "profile"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ProfileUpdate"
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: Bearer blablabla
     *            description: CPA token
     *            required: true
     *     responses:
     *          "204":
     *            description: "profile updated"
     *          "400":
     *            description: "bad update data"
     */
    router.put('/api/v2/cpa/user/profile', cors, authHelper.ensureCpaAuthenticated, user_profile_update);

    /**
     * @swagger
     * /api/v2/all/nameByUid/{puid}:
     *   get:
     *     description: get the saved names by public_uid
     *     operationId: "getNamesByPUid"
     *     content:
     *       - application/json
     *     parameters:
     *        - in: path
     *          name: "puid"
     *          description: "uid to fetch names for"
     *          required: true
     *          schema:
     *            type: UUIDv4
     *     responses:
     *        "200":
     *          description: "anonymous object containing first- and lastname"
     *        "400":
     *          description: "not valid UUIDv4!"
     *        "404":
     *          description: "user not found"
     *        "409":
     *          description: "dervice disabled by configuration"
     *        "500":
     *          description: "error fetching user name by public id"
     */
    router.get('/api/v2/all/nameByUid/:puid', cors, user_nameByPublicUid);
};