"use strict";

const passport = require('passport');
const cors = require('../../../../lib/cors');
const logger = require('../../../../lib/logger');
const db = require('../../../../models');
const userHelper = require('../../../../lib/user-helper');
const authHelper = require('../../../../lib/auth-helper');

var user_profile = function (req, res) {
    logger.debug('[API-V2][Profile][user_id', req.user.id, ']');
    if (req.user) {
        let data = req.user.getProfile();
        if (req.authInfo && req.authInfo.scope) {
            data.score = req.authInfo.scope;
        }
        res.json(data);
    } else {
        db.SocialLogin.findOne({where: {user_id: req.user.id}}).then(function (socialLogin) {
            let data = socialLogin.getProfile();
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
                    res.status(204).send();
                },
                function (err) {
                    logger.error('[PUT /user/profile][ERROR', err, ']');
                    res.status(500).json({msg: req.__('BACK_PROFILE_UPDATE_FAIL') + err});
                }
            );
        });
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
     *                      type: boolean
     *                      example: false
     *                      description: true if email has been verified
     *                  gender:
     *                      type: string
     *                      enum: [other, male, female]
     *                      example: male
     *                      description: user gender
     *                  date_of_birth:
     *                      type: string
     *                      example: 2018-08-31
     *                      description: user data of birth using yyyy-mm-dd format
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
     * /api/v2/oauth2/user/profile:
     *   get:
     *     description: get logged (using oAuth token security) user profile
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
    router.options('/api/v2/oauth2/user/profile', cors);
    router.get('/api/v2/oauth2/user/profile', cors, passport.authenticate('bearer', {session: false}), user_profile);

    /**
     * @swagger
     * /api/v2/oauth2/user/profile:
     *   put:
     *     description: update user profile (using oAuth token security)
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
     *            description: "profile udpated"
     */
    router.put('/api/v2/oauth2/user/profile', cors, passport.authenticate('bearer', {session: false}), user_profile_update);


    /**
     * @swagger
     * /api/v2/session/user/profile:
     *   get:
     *     description: get logged (using session cookie security) user profile
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
     *            description: "profile udpated"
     */
    router.put('/api/v2/session/user/profile', cors, authHelper.ensureAuthenticated, user_profile_update);

    /**
     * @swagger
     * /api/v2/jwt/user/profile:
     *   get:
     *     description: get logged (using JWT token security) user profile
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
     *            example: JWT blablabla
     *            description: JWT token
     *            required: true
     *     responses:
     *          "204":
     *            description: "profile udpated"
     */
    router.put('/api/v2/jwt/user/profile', cors, passport.authenticate('jwt', {session: false}), user_profile_update);

    /**
     * @swagger
     * /api/v2/cpa/user/profile:
     *   get:
     *     description: get logged (using CPA token security) user profile
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
     *            description: "profile udpated"
     */
    router.put('/api/v2/cpa/user/profile', cors, authHelper.ensureCpaAuthenticated, user_profile_update);


};