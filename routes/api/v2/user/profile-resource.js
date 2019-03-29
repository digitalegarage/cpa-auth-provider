"use strict";

const passport = require('passport');
const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const logger = require('../../../../lib/logger');
const uuidValidator = require('uuid-validate');
const userHelper = require('../../../../lib/user-helper');
const authHelper = require('../../../../lib/auth-helper');
const apiErrorHelper = require('../../../../lib/api-error-helper');

var user_profile = function(req, res, next) {
    logger.debug('[API-V2][Profile][user_id', req.user.id, ']');
    if (req.user) {
        userHelper.getProfileByReq(req)
        .then(profile => {
            res.json(profile);
        })
        .catch(e => {
            next(e);
        });
    } else {
        apiErrorHelper.throwError(401, 'NO_USER_IN_REQUEST', 'No user in the request object.');
    }
};


var user_profile_update =
    function (req) {
        return new Promise(function(resolve,reject) {
            logger.debug('[API-V2][Profile udpate][user_id', req.user.id, ']');
            return userHelper.validateProfileUpdateData(req).then((result) => {
                if (!result.isEmpty()) {
                    var errors = result.array();
                    var subErrors = [];
                    var message = '';
                    for (var i = 0; i < errors.length; i++) {
                        message += ' - ' + errors[i].msg + '<br/>';
                        subErrors.push(apiErrorHelper.buildFieldError(errors[i].param, apiErrorHelper.TYPE.BAD_FORMAT_OR_MISSING, null, errors[i].msg, errors[i].msg, {value: errors[i].value}));
                    }
                    reject(apiErrorHelper.buildError(400, 'BAD_PROFILE_DATA', 'Profile data not valid.', message, subErrors, errors));
                } else {
                    return userHelper.updateProfile(req.user, req.body).then(() => {
                        resolve();
                    }).catch((err) => {
                        reject(err);
                    });
                }
            }).catch((err) => {
                reject(err);
            });
        });
    };

var user_nameByPublicUid = function(req,res,next) {
    if (config.allow_name_access_by_puid) {
        if (uuidValidator(req.params.puid, 4)) {
            userHelper.getUserNameByPublicId(req.params.puid)
            .then((username) => {
                if (!username) {
                    logger.error("UUID request for non-existant user",req.params.puid);
                    next(apiErrorHelper.buildError(404,'USER_WITH_UUID_NOT_FOUND','UUID request for non-existant user'));
                }
                else
                    res.json(username);
            })
            .catch((e) => {
                logger.error("Error fetching user name by public id",e);
                next(apiErrorHelper.buildError(500, 'SERVICE_ERROR','Error fetching user name by public id.', '',[], e));
            });
        } else {
            apiErrorHelper.throwError(400, 'BAD_REQUEST_INVALID_UUIDV4', "No valid UUIDv4!");
        }
    } else {
        apiErrorHelper.throwError(409, 'SERVICE_DISABLED_BY_CONFIGURATION', 'Service disabled by configuration.');
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
     *       400:
     *         description: "Possible error are: BAD_PROFILE_DATA"
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
     *            description: "Possible error are: BAD_PROFILE_DATA"
     */
    router.put('/api/v2/oauth/user/profile', cors, passport.authenticate('bearer', {session: false}), function(req, res, next) {
        user_profile_update(req).then(() => {
            res.sendStatus(204);
        }).catch((err) => {
            next(err);
        });
    });


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
     *       400:
     *         description: "Possible error are: NO_USER_IN_REQUEST"
     *         schema:
     *           $ref: '#/definitions/error'
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
     *            description: "Possible error are: BAD_PROFILE_DATA"
     *            schema:
     *              $ref: '#/definitions/error'
     */
    router.put('/api/v2/session/user/profile', cors, authHelper.ensureAuthenticated, function(req, res, next) {
        user_profile_update(req)
        .then(() => {
            res.sendStatus(204);
        }).catch((err) => {
            next(err);
        });
    });

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
     *       400:
     *         description: "Possible error are: NO_USER_IN_REQUEST"
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
     *            description: "Possible error are: BAD_PROFILE_DATA"
     */
    router.put('/api/v2/jwt/user/profile', cors, passport.authenticate('jwt', {session: false}), function(req, res, next) {
        user_profile_update(req).then(() => {
            res.sendStatus(204);
        }).catch((err) => {
            next(err);
        });
    });

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
     *       400:
     *         description: "Possible error are: NO_USER_IN_REQUEST"
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
     *            description: "Possible error are: BAD_PROFILE_DATA"
     */
    router.put('/api/v2/cpa/user/profile', cors, authHelper.ensureCpaAuthenticated, function(req, res, next) {
        user_profile_update(req).then(() => {
            res.sendStatus(204);
        }).catch((err) => {
            next(err);
        });
    });

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
     *            description: "Possible error are: USER_WITH_UUID_NOT_FOUND, SERVICE_ERROR, BAD_REQUEST_INVALID_UUIDV4 and SERVICE_DISABLED_BY_CONFIGURATION"
     *        "404":
     *          description: "user not found"
     *        "409":
     *          description: "service disabled by configuration"
     *        "500":
     *          description: "error fetching user name by public id"
     */
    router.get('/api/v2/all/nameByUid/:puid', cors, user_nameByPublicUid);

};