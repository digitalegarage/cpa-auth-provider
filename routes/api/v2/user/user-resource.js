"use strict";

const passport = require('passport');
const cors = require('../../../../lib/cors');
const logger = require('../../../../lib/logger');
const db = require('../../../../models/index');
const auth = require('basic-auth');
const jwtHelper = require('../../../../lib/jwt-helper');
const passwordHelper = require('../../../../lib/password-helper');
const authHelper = require('../../../../lib/auth-helper');
const userHelper = require('../../../../lib/user-helper');
const _ = require('underscore');

function delete_user_by_id(userId, res) {
// Transactional part
    return db.sequelize.transaction(function (transaction) {
        return db.LocalLogin.destroy({
            where: {user_id: userId},
            transaction: transaction
        }).then(function () {
            return db.SocialLogin.destroy({
                where: {user_id: userId},
                transaction: transaction
            });
        }).then(function () {
            return db.User.destroy({
                where: {id: userId},
                transaction: transaction
            });
        }).then(function () {
            return res.status(204).send();
        });
    });
}

function delete_user(req, res){
    return delete_user_by_id(req.user.id, res);
}

var delete_user_with_credentials = function (req, res) {
    logger.debug('[API-V2][User][DELETE]');

    var user = auth(req);

    if (!user) {
        return res.json({error: 'missing credentials'}).status(400).send();
    } else {
        var login = user.name;
        var password = user.pass;


        db.LocalLogin.findOne({where: {login: login}}).then(function (localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password)
                    .then(function (isMatch) {
                        logger.info('isMatch', isMatch);
                        if (isMatch) {
                            return delete_user_by_id(localLogin.user_id, res);
                        } else {
                            return res.status(401).send();
                        }
                    });
            }
        });
    }
};

var get_user_id = function (req, res) {
    var auth = req.headers.authorization;
    if (!auth) {
        return res.status(401).send({error: 'missing header Authorization'});
    } else {
        if (auth.indexOf("Bearer ") == 0) {
            var token = auth.substring("Bearer ".length);
            try {
                let userId = jwtHelper.decode(token).id;
                return res.status(200).send({id: userId});
            } catch (err) {
                return res.status(401).send({error: 'Cannot parse JWT token'});
            }
        } else {
            return res.status(401).send({error: 'Authorization doesn\'t have the expect format "Bearer [token]"'});
        }
    }

};

var get_user = function (req,res) {
    if (!req.headers.authorization || !auth(req)) {
        return res.status(401).send({error: 'missing or bad credential in header Authorization'});
    } else {
        var user = auth(req);
        var login = user.name;
        var password = user.pass;
        db.LocalLogin.findOne({where: {login: login}})
        .then(function (localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password)
                .then(function (isMatch) {
                    logger.info('isMatch', isMatch);
                    if (isMatch) {
                        db.User.findOne({
                            where: {id: localLogin.user_id},
                            include: [db.Permission]
                        })
                        .then(function (user) {
                            // be sure about what we send? here we go.
                            res.json(_.pick(user,'id','display_name','firstname','lastname','gender','language','permission_id', 'public_uid'));
                        })
                        .catch(function (error) {
                            logger.error(error);
                            res.sendStatus(500);
                        });
                    } else {
                        logger.debug("Authentication failed for " + user.name);
                        res.sendStatus(401);
                    }
                });
            }
        });
    }
};

var create_local_login = function (req, res) {
    req.checkBody('email', req.__('BACK_CHANGE_PWD_MAIL_EMPTY')).notEmpty();
    req.checkBody('password', req.__('BACK_CHANGE_PWD_NEW_PASS_EMPTY')).notEmpty();
    req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
    req.checkBody('password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

    req.getValidationResult().then(function (result) {
        if (!result.isEmpty()) {
            res.status(400).json({errors: result.array()});
        } else {
            if (!passwordHelper.isStrong(req.body.email, req.body.password)) {
                res.status(400).json({
                    errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}],
                    password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                    score: passwordHelper.getQuality(req.body.email, req.body.password)
                });
            } else {
                userHelper.addLocalLogin(req.user, req.body.email, req.body.password).then(
                    function () {
                        res.json({success: true, msg: req.__('BACK_SUCCESS_PASS_CREATED')});
                    },
                    function (err) {
                        if (err.message === userHelper.EXCEPTIONS.EMAIL_TAKEN) {
                            return res.status(400).json({
                                success: false,
                                msg: req.__('API_SIGNUP_EMAIL_ALREADY_EXISTS')
                            });
                        } else if (err.message === userHelper.EXCEPTIONS.PASSWORD_WEAK) {
                            return res.status(400).json({
                                success: false,
                                msg: req.__('API_SIGNUP_PASS_IS_NOT_STRONG_ENOUGH'),
                                password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                                errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}]
                            });
                        } else {
                            logger.error('[POST /api/v2/<security>/user/login/create][email', req.body.email, '][ERR', err, ']');
                            res.status(500).json({
                                success: false,
                                msg: req.__('API_ERROR') + err
                            });
                        }
                    }
                );
            }

        }
    });
};

module.exports = function (router) {

    /**
     * @swagger
     * definitions:
     *  User:
     *     type: object
     *     properties:
     *         id:
     *             type: integer
     *             example: 42
     *             description: database primary key
     *             required: true
     *         firstName:
     *             type: string
     *             example: John
     *             description: user firstname
     *         lastName:
     *             type: string
     *             example: Doe
     *             description: user lastname
     *         display_name:
     *             type: string
     *             example: John Doe
     *             description: user display name
     *         gender:
     *             type: string
     *             enum: [other, male, female]
     *             example: male
     *             description: user gender
     *         language:
     *             type: string
     *             example: fr
     *             description: user language
     *         permission_id:
     *             type: integer
     *             example: 2
     *             description: user has permission with id
     *         public_uid:
     *             type: string
     *             example: 2b61aade-f9b5-47c3-8b5b-b9f4545ec9f9
     *             description: public id for unauthorized get of public data
     */

    /**
     * @swagger
     * /api/v2/basicauth/user:
     *   delete:
     *     description: delete the user providing user credentials
     *     operationId: "deleteUser"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "user credentials basic authentication format AKA base64 applied to login+':'+password prefixed by 'Basic '"
     *            required: true
     *            schema:
     *              type: string
     *            example: Basic ZG9taW5pcXVlLmNoaW9uQGdtYWlsLmNvbTphemVydHl1aW9wYXplcnR5dWlvcA==
     *     responses:
     *          "204":
     *            description: "user had been deleted"
     *   get:
     *     description: get a users profile by credentials
     *     operationId: "getUser"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "user credentials basic authentication format AKA base64 applied to login+':'+password prefixed by 'Basic '"
     *            required: true
     *            schema:
     *              type: string
     *            example: Basic ZG9taW5pcXVlLmNoaW9uQGdtYWlsLmNvbTphemVydHl1aW9wYXplcnR5dWlvcA==
     *     responses:
     *          "200":
     *            description: "user profile including permissions in json body"
     *            schema:
     *              $ref: '#/definitions/User'     */
    router.options('/api/v2/basicauth/user', cors);
    router.delete('/api/v2/basicauth/user', cors, delete_user_with_credentials);
    router.get('/api/v2/basicauth/user', cors, get_user);

    /**
     * @swagger
     * /api/v2/jwt/user:
     *   delete:
     *     description: delete the user providing user credentials
     *     operationId: "deleteUser"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "JWT token"
     *            required: true
     *            schema:
     *              type: string
     *              example: JWT blablabla
     *     responses:
     *          "204":
     *            description: "user had been deleted"
     */

    router.delete('/api/v2/jwt/user', cors, passport.authenticate('jwt', {session: false}), delete_user);

    /**
     * @swagger
     * /api/v2/jwt/user/id:
     *   get:
     *     description: retreive user id from jwt token (id is retrieved in jwt token not from the database)
     *     operationId: "getUserId"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "jwt token"
     *            required: true
     *            schema:
     *              type: string
     *              example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c=
     *     responses:
     *          "200":
     *            description: "user had been deleted"
     *            schema:
     *              type: string
     *              example: 42b
     */
    router.options('/api/v2/jwt/user/id', cors);
    router.get('/api/v2/jwt/user/id', cors, get_user_id);


    /**
     * @swagger
     * definitions:
     *  AddLocalLogin:
     *      properties:
     *          email:
     *              type: string
     *              example: jhon@doe.com
     *              description: oAuth2 stuff
     *          password:
     *              type: string
     *              example: passw0rd
     *              description: the password to set
     *          confirm_password:
     *              type: string
     *              example: passw0rd
     *              description:  confirm password
     */

    /**
     * @swagger
     * /api/v2/session/user/password/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     operationId: "createPassword"
     *     content:
     *       - application/json
     *     parameters:
     *          -
     *            name: "localLoginData"
     *            in: "body"
     *            description: "local login data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/AddLocalLogin"
     *     responses:
     *        "200":
     *          description: "local login had been created"
     */

    router.options('/api/v2/session/user/login/create', cors);
    router.post('/api/v2/session/user/login/create', cors, authHelper.ensureAuthenticated, create_local_login);

    /**
     * @swagger
     * /api/v2/jwt/user/password/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     operationId: "createPassword"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "jwt token"
     *            required: true
     *            schema:
     *              type: string
     *              example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c=
     *          -
     *            name: "localLoginData"
     *            in: "body"
     *            description: "local login data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/AddLocalLogin"
     *     responses:
     *        "200":
     *          description: "local login had been created"
     */

    router.options('/api/v2/jwt/user/login/create', cors);
    router.post('/api/v2/jwt/user/login/create', cors, passport.authenticate('jwt', {session: false}), create_local_login);

    // Those endpoints are not available since there is no way in IDP to get an oAuth access token from a facebook or google login. So there is no way to have a valid oAuth access token without a local login
    // router.options('/api/v2/oauth2/user/login/create', cors);
    // router.post('/api/v2/oauth2/user/login/create', cors, passport.authenticate('bearer', {session: false}), create_local_login);

    /**
     * @swagger
     * /api/v2/cpa/user/password/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     operationId: "createPassword"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: blablabla
     *            description: CPA token
     *            required: true
     *          -
     *            name: "localLoginData"
     *            in: "body"
     *            description: "local login data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/AddLocalLogin"
     *     responses:
     *        "200":
     *          description: "local login had been created"
     */

    router.options('/api/v2/cpa/user/login/create', cors);
    router.post('/api/v2/cpa/user/login/create', cors, authHelper.ensureCpaAuthenticated, create_local_login);

};
