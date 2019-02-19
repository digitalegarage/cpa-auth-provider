'use strict';

const passport = require('passport');
const cors = require('../../../../lib/cors');
const logger = require('../../../../lib/logger');
const db = require('../../../../models/index');
const auth = require('basic-auth');
const jwtHelper = require('../../../../lib/jwt-helper');
const passwordHelper = require('../../../../lib/password-helper');
const authHelper = require('../../../../lib/auth-helper');
const appHelper = require('../../../../lib/app-helper');
const userHelper = require('../../../../lib/user-helper');
const changeEmailHelper = require('../../../email/change-email-helper');
const config = require('../../../../config');
const emailHelper = require('../../../../lib/email-helper');
const codeHelper = require('../../../../lib/code-helper');
const limiterHelper = require('../../../../lib/limiter-helper');
const i18n = require('i18n');
const _ = require('underscore');

function delete_user_by_id(userId, res) {
// Transactional part
    return db.sequelize.transaction(function(transaction) {
        return db.LocalLogin.destroy({
            where: {user_id: userId},
            transaction: transaction
        }).then(function() {
            return db.SocialLogin.destroy({
                where: {user_id: userId},
                transaction: transaction
            });
        }).then(function() {
            return db.User.destroy({
                where: {id: userId},
                transaction: transaction
            });
        }).then(function() {
            return res.status(204).send();
        });
    });
}

function delete_user(req, res) {
    return delete_user_by_id(req.user.id, res);
}

const delete_user_with_credentials = function(req, res) {
    logger.debug('[API-V2][User][DELETE]');

    var user = auth(req);

    if (!user) {
        return res.json({error: 'missing credentials'}).status(400).send();
    } else {
        var login = user.name;
        var password = user.pass;

        db.LocalLogin.findOne({where: {login: login}}).then(function(localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password).then(function(isMatch) {
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

const get_user_id_from_jwt = function(req, res) {
    var auth = req.headers.authorization;
    if (!auth) {
        return res.status(401).send({error: 'missing header Authorization'});
    } else {
        if (auth.indexOf('Bearer ') == 0) {
            var token = auth.substring('Bearer '.length);
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

const get_user = function(req, res) {
    if (!req.headers.authorization || !auth(req)) {
        return res.status(401).send({error: 'missing or bad credential in header Authorization'});
    } else {
        var user = auth(req);
        var login = user.name;
        var password = user.pass;
        db.LocalLogin.findOne({where: {login: login}}).then(function(localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password).then(function(isMatch) {
                    logger.info('isMatch', isMatch);
                    if (isMatch) {
                        db.User.findOne({
                            where: {id: localLogin.user_id},
                            include: [db.Permission]
                        }).then(function(user) {
                            // be sure about what we send? here we go.
                            res.json(_.pick(user, 'id', 'display_name', 'firstname', 'lastname', 'gender', 'language', 'permission_id', 'public_uid'));
                        }).catch(function(error) {
                            logger.error(error);
                            res.sendStatus(500);
                        });
                    } else {
                        logger.debug('Authentication failed for ' + user.name);
                        res.sendStatus(401);
                    }
                });
            }
        });
    }
};

const create_local_login = function(req, res) {
    req.checkBody('email', req.__('BACK_CHANGE_PWD_MAIL_EMPTY')).notEmpty();
    req.checkBody('password', req.__('BACK_CHANGE_PWD_NEW_PASS_EMPTY')).notEmpty();
    req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
    req.checkBody('password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

    req.getValidationResult().then(function(result) {
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
                    function() {
                        res.sendStatus(204);
                    },
                    function(err) {
                        if (err.message === userHelper.EXCEPTIONS.EMAIL_TAKEN) {
                            return res.status(400).json({
                                msg: req.__('API_SIGNUP_EMAIL_ALREADY_EXISTS')
                            });
                        } else if (err.message === userHelper.EXCEPTIONS.PASSWORD_WEAK) {
                            return res.status(400).json({
                                msg: req.__('API_SIGNUP_PASS_IS_NOT_STRONG_ENOUGH'),
                                password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                                errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}]
                            });
                        } else {
                            logger.error('[POST /api/v2/<security>/user/login/create][email', req.body.email, '][ERR', err, ']');
                            res.status(500).json({
                                msg: req.__('API_ERROR') + err
                            });
                        }
                    }
                );
            }

        }
    });
};

const change_password = function(req, res) {
    req.checkBody('email', req.__('API_PASSWORD_RECOVER_PLEASE_PASS_EMAIL')).isEmail();
    req.checkBody('previous_password', req.__('BACK_CHANGE_PWD_PREV_PASS_EMPTY')).notEmpty();
    req.checkBody('new_password', req.__('BACK_CHANGE_PWD_NEW_PASS_EMPTY')).notEmpty();
    req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
    req.checkBody('new_password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

    req.getValidationResult().then(function(result) {
        if (!result.isEmpty()) {
            res.status(400).json({errors: result.array()});
        } else {
            let email = req.body.email;
            let newPassword = req.body.new_password;
            if (!passwordHelper.isStrong(email, newPassword)) {
                res.status(400).json({
                    errors: [{msg: passwordHelper.getWeaknessesMsg(email, newPassword, req)}],
                    password_strength_errors: passwordHelper.getWeaknesses(email, newPassword, req),
                    score: passwordHelper.getQuality(email, newPassword)
                });
            } else {
                db.LocalLogin.findOne({
                    where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), email.toLowerCase()),
                    include: [db.User]
                }).then(function(localLogin) {
                    if (!localLogin) {
                        return res.status(401).send({errors: [{msg: req.__('BACK_USER_NOT_FOUND')}]});
                    } else {
                        localLogin.verifyPassword(req.body.previous_password).then(function(isMatch) {
                            // if user is found and password is right change password
                            if (isMatch) {
                                localLogin.setPassword(req.body.new_password).then(
                                    function() {
                                        appHelper.destroySessionsByUserId(localLogin.User.id, req.sessionID).then(function() {
                                            return res.json({msg: req.__('BACK_SUCCESS_PASS_CHANGED')});
                                        }).catch(function(e) {
                                            logger.error(e);
                                            return res.sendStatus(500);
                                        });
                                    },
                                    function(err) {
                                        logger.error(err);
                                        res.status(500).json({errors: [err]});
                                    }
                                );
                            } else {
                                res.status(401).json({errors: [{msg: req.__('BACK_INCORRECT_PREVIOUS_PASS')}]});
                            }
                        });
                    }
                });
            }
        }
    });
};

const resend_validation_email = function(req, res) {
    if (req.recaptcha.error){
        return res.status(400).json({msg: 'reCaptcha is empty or wrong. '});
    }

    var user = req.user;
    var email = req.user.LocalLogin ? req.user.LocalLogin.login : '';
    codeHelper.getOrGenereateEmailVerificationCode(user).then(function(code) {
        emailHelper.send(
            config.mail.from,
            email,
            'validation-email',
            {log: false},
            {
                confirmLink: config.mail.host + '/email_verify?email=' + encodeURIComponent(email) + '&code=' + encodeURIComponent(code),
                host: config.mail.host,
                mail: email,
                code: code
            },
            (user.language) ? user.language : i18n.getLocale()
        ).then(
            function() {
            },
            function() {
            }
        );
    });
    return res.sendStatus(204);

};

module.exports = function(router) {

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
     *     tags: [Basic Auth]
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
     *          "400":
     *            description: "missing credentials"
     *          "401":
     *            description: "wrong login or password"
     *   get:
     *     description: get a users profile by credentials
     *     tags: [Basic Auth]
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
     *     description: delete the user providing a jwt token
     *     tags: [JWT]
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
     *     tags: [JWT]
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
     *              type: integer
     *              example: 42
     *          "401":
     *            description: "Bad authentication header format or bad jwt token"
     */
    router.options('/api/v2/jwt/user/id', cors);
    router.get('/api/v2/jwt/user/id', cors, get_user_id_from_jwt);

    /**
     * @swagger
     * definitions:
     *  AddLocalLogin:
     *      properties:
     *          email:
     *              type: string
     *              example: jhon@doe.com
     *              description: user email / login
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
     * /api/v2/session/user/login/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     tags: [Session]
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
     *        "204":
     *          description: "local login had been created"
     *        "400":
     *          description: "bad data. Could be both password doesn't match, Password not strong enough. Email already taken"
     *        "500":
     *          description: "unexpected error"
     */

    router.options('/api/v2/session/user/login/create', cors);
    router.post('/api/v2/session/user/login/create', cors, authHelper.ensureAuthenticated, create_local_login);

    /**
     * @swagger
     * /api/v2/jwt/user/login/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     tags: [JWT]
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
     *        "204":
     *          description: "local login had been created"
     *        "400":
     *          description: "bad data. Could be both password doesn't match, Password not strong enough. Email already taken"
     *        "500":
     *          description: "unexpected error"
     */

    router.options('/api/v2/jwt/user/login/create', cors);
    router.post('/api/v2/jwt/user/login/create', cors, passport.authenticate('jwt', {session: false}), create_local_login);

    // Those endpoints are not available since there is no way in IDP to get an oAuth access token from a facebook or google login. So there is no way to have a valid oAuth access token without a local login
    // router.options('/api/v2/oauth2/user/login/create', cors);
    // router.post('/api/v2/oauth2/user/login/create', cors, passport.authenticate('bearer', {session: false}), create_local_login);

    /**
     * @swagger
     * /api/v2/cpa/user/login/create:
     *   post:
     *     description: add a local login for an user having only social logins
     *     tags: [CPA]
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
     *        "204":
     *          description: "local login had been created"
     *        "400":
     *          description: "bad data. Could be both password doesn't match, Password not strong enough. Email already taken"
     *        "500":
     *          description: "unexpected error"
     */

    router.options('/api/v2/cpa/user/login/create', cors);
    router.post('/api/v2/cpa/user/login/create', cors, authHelper.ensureCpaAuthenticated, create_local_login);

    /**
     * @swagger
     * definitions:
     *  ChangePassword:
     *      properties:
     *          email:
     *              type: string
     *              example: jhon@doe.com
     *              description: user email / login
     *          previous_password:
     *              type: string
     *              example: 0ldPassw0rd
     *              description:  previous password
     *          new_password:
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
     * /api/v2/all/user/password:
     *   post:
     *     description: change user password
     *     operationId: "createPassword"
     *     content:
     *       - application/json
     *     parameters:
     *          -
     *            name: "ChangePassword"
     *            in: "body"
     *            description: "changing password data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ChangePassword"
     *     responses:
     *        "204":
     *          description: "local login had been created"
     *        "400":
     *          description: "bad data. Could be both password doesn't match, Password not strong enough. Email already taken"
     *        "401":
     *          description: "wrong previous password and or login"
     *        "500":
     *          description: "unexpected error"
     */
    router.options('/api/v2/all/user/password', cors);
    router.post('/api/v2/all/user/password', cors, change_password); // Password is checked in change password so security is not checked

    /**
     * @swagger
     * definitions:
     *  ChangeEmail:
     *      properties:
     *          new_email:
     *              type: string
     *              example: jhon@doe.com
     *              description: user email / login
     *          password:
     *              type: string
     *              example: Passw0rd
     *              description:  previous password
     *          use_custom_redirect:
     *              type: boolean
     *              example: false
     *              description: if set to true then broadcaster specific redirection'd be used
     *              required: false
     */

    /**
     * @swagger
     * /api/v2/session/user/email/change:
     *   post:
     *     description: add a local login for an user having only social logins
     *     tags: [Session]
     *     operationId: "changeEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          -
     *            name: "ChangeEmail"
     *            in: "body"
     *            description: "changing password data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ChangePassword"
     *     responses:
     *        "204":
     *          description: "Change email request had been done"
     *        "401":
     *          description: "Unauthorized"
     *        "403":
     *          description: "Wrong password"
     *        "429":
     *          description: "Too many request"
     */
    router.options('/api/v2/session/user/email/change', cors);
    router.post('/api/v2/session/user/email/change', cors, authHelper.ensureAuthenticated, changeEmailHelper.change_email);

    /**
     * @swagger
     * /api/v2/jwt/user/email/change:
     *   post:
     *     description: request email change
     *     tags: [JWT]
     *     operationId: "requestChangeEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "JWT token"
     *            required: true
     *            schema:
     *              type: string
     *              example: JWT blablabla
     *          -
     *            name: "ChangeEmail"
     *            in: "body"
     *            description: "changing email data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ChangeEmail"
     *     responses:
     *        "204":
     *          description: "Change email request had been done"
     *        "401":
     *          description: "Unauthorized"
     *        "403":
     *          description: "Wrong password"
     *        "429":
     *          description: "Too many request"
     */
    router.post('/api/v2/jwt/user/email/change', cors, passport.authenticate('jwt', {session: false}), changeEmailHelper.change_email);

    /**
     * @swagger
     * /api/v2/cpa/user/email/change:
     *   post:
     *     description: request email change
     *     tags: [CPA]
     *     operationId: "requestChangeEmail"
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
     *            name: "ChangeEmail"
     *            in: "body"
     *            description: "changing email data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ChangeEmail"
     *     responses:
     *        "204":
     *          description: "Change email request had been done"
     *        "401":
     *          description: "Unauthorized"
     *        "403":
     *          description: "Wrong password"
     *        "429":
     *          description: "Too many request"
     */
    router.post('/api/v2/cpa/user/email/change', cors, authHelper.ensureCpaAuthenticated, changeEmailHelper.change_email);

    /**
     * @swagger
     * /api/v2/session/user/email/change:
     *   post:
     *     description: request email change
     *     tags: [Session]
     *     operationId: "requestChangeEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          -
     *            name: "ChangeEmail"
     *            in: "body"
     *            description: "changing email data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/ChangeEmail"
     *     responses:
     *        "204":
     *          description: "Change email request had been done"
     *        "401":
     *          description: "Unauthorized"
     *        "403":
     *          description: "Wrong password"
     *        "429":
     *          description: "Too many request"
     */
    router.post('/api/v2/oauth/user/email/change', cors, passport.authenticate('bearer', {session: false}), changeEmailHelper.change_email);

    /**
     * @swagger
     * /api/v2/all/user/email/move/{token}:
     *   post:
     *     description: request email change
     *     operationId: "requestChangeEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: "path"
     *            name: "token"
     *            description: "token for email changing"
     *            required: true
     *            schema:
     *              type: string
     *          - in: "query"
     *            name: "use_custom_redirect"
     *            description: "if set to true then user'd be redirected to broadcaster specified redirect URI"
     *            required: false
     *            schema:
     *              type: boolean
     *              example: false
     *     responses:
     *        "200":
     *          description: a confirmation page is displayed and indicate if the email had been updated or not
     *        "302":
     *          description: User is to broadcaster specified redirect URI post fixed with '?success=true/false' depending on the success of email change. That happens when use_custom_redirect query parameter is set to true
     */
    router.get('/api/v2/all/user/email/move/:token', changeEmailHelper.move_email);


    /**
     * @swagger
     * /api/v2/session/user/profile/request_verification_email:
     *   post:
     *     description: request another validation email
     *     tags: [Session]
     *     operationId: "requestValidationEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: "body"
     *            name: "g-recaptcha-response"
     *            description: "recaptcha response (sent if broadcaster user recaptcha limiter)"
     *            required: false
     *            schema:
     *              type: string
     *              example: 03AF6jDqXLGOZaeru76ARh5oz5qUj8QPoTygDbK_cnM6TGyqIHhZSBlYqs2T5K7H9oVKRP-ZEdO0N1rAcBTBKe8RpCtSHpwYRuevIcs7WHD9_ixzCLNiP3NJWeASnFkzTA1nlu0Pp5vmFyEfWgIZ-k0bkoGa7Ep5xVwpqPXCQorprVWpQJmDgKkhM8uhWZVZU2ayrIVCoT8DI6sxO5ct11aUZhdYFYH12gniuxIOTdgURetCulOtVzh3lyq6RmeTuQneV94UeaMWAze0S1z3WDfBhhGILeWrsUw187a6Y8B1Mi6BazG79_M8A
     *     responses:
     *        "204":
     *          description: another validation email had been sent
     *        "400":
     *          description: bad recaptcha (if apply)
     */
    router.options('/api/v2/session/user/profile/request_verification_email', cors);
    router.post('/api/v2/session/user/profile/request_verification_email', [authHelper.ensureAuthenticated, limiterHelper.verify], resend_validation_email);

    /**
     * @swagger
     * /api/v2/jwt/user/profile/request_verification_email:
     *   post:
     *     description: request another validation email
     *     tags: [JWT]
     *     operationId: "requestValidationEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "JWT token"
     *            required: true
     *            schema:
     *              type: string
     *              example: JWT blablabla
     *          - in: "body"
     *            name: "g-recaptcha-response"
     *            description: "recaptcha response (sent if broadcaster user recaptcha limiter)"
     *            required: false
     *            schema:
     *              type: string
     *              example: 03AF6jDqXLGOZaeru76ARh5oz5qUj8QPoTygDbK_cnM6TGyqIHhZSBlYqs2T5K7H9oVKRP-ZEdO0N1rAcBTBKe8RpCtSHpwYRuevIcs7WHD9_ixzCLNiP3NJWeASnFkzTA1nlu0Pp5vmFyEfWgIZ-k0bkoGa7Ep5xVwpqPXCQorprVWpQJmDgKkhM8uhWZVZU2ayrIVCoT8DI6sxO5ct11aUZhdYFYH12gniuxIOTdgURetCulOtVzh3lyq6RmeTuQneV94UeaMWAze0S1z3WDfBhhGILeWrsUw187a6Y8B1Mi6BazG79_M8A
     *     responses:
     *        "204":
     *          description: another validation email had been sent
     *        "400":
     *          description: bad recaptcha (if apply)
     */

    router.post('/api/v2/jwt/user/profile/request_verification_email', [ passport.authenticate('jwt', {session: false}), limiterHelper.verify], resend_validation_email);

    /**
     * @swagger
     * /api/v2/cpa/user/profile/request_verification_email:
     *   post:
     *     description: request another validation email
     *     tags: [CPA]
     *     operationId: "requestValidationEmail"
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
     *          - in: "body"
     *            name: "g-recaptcha-response"
     *            description: "recaptcha response (sent if broadcaster user recaptcha limiter)"
     *            required: false
     *            schema:
     *              type: string
     *              example: 03AF6jDqXLGOZaeru76ARh5oz5qUj8QPoTygDbK_cnM6TGyqIHhZSBlYqs2T5K7H9oVKRP-ZEdO0N1rAcBTBKe8RpCtSHpwYRuevIcs7WHD9_ixzCLNiP3NJWeASnFkzTA1nlu0Pp5vmFyEfWgIZ-k0bkoGa7Ep5xVwpqPXCQorprVWpQJmDgKkhM8uhWZVZU2ayrIVCoT8DI6sxO5ct11aUZhdYFYH12gniuxIOTdgURetCulOtVzh3lyq6RmeTuQneV94UeaMWAze0S1z3WDfBhhGILeWrsUw187a6Y8B1Mi6BazG79_M8A
     *     responses:
     *        "204":
     *          description: another validation email had been sent
     *        "400":
     *          description: bad recaptcha (if apply)
     */

    router.post('/api/v2/cpa/user/profile/request_verification_email', [authHelper.ensureCpaAuthenticated, limiterHelper.verify], resend_validation_email);

    /**
     * @swagger
     * /api/v2/oauth/user/profile/request_verification_email:
     *   post:
     *     description: request another validation email
     *     tags: [OAUTH]
     *     operationId: "requestValidationEmail"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: Authorization
     *            schema:
     *              type: string
     *            example: Bearer blablabla
     *            description: oAuth access token
     *            required: true
     *          - in: "body"
     *            name: "g-recaptcha-response"
     *            description: "recaptcha response (sent if broadcaster user recaptcha limiter)"
     *            required: false
     *            schema:
     *              type: string
     *              example: 03AF6jDqXLGOZaeru76ARh5oz5qUj8QPoTygDbK_cnM6TGyqIHhZSBlYqs2T5K7H9oVKRP-ZEdO0N1rAcBTBKe8RpCtSHpwYRuevIcs7WHD9_ixzCLNiP3NJWeASnFkzTA1nlu0Pp5vmFyEfWgIZ-k0bkoGa7Ep5xVwpqPXCQorprVWpQJmDgKkhM8uhWZVZU2ayrIVCoT8DI6sxO5ct11aUZhdYFYH12gniuxIOTdgURetCulOtVzh3lyq6RmeTuQneV94UeaMWAze0S1z3WDfBhhGILeWrsUw187a6Y8B1Mi6BazG79_M8A
     *     responses:
     *        "204":
     *          description: another validation email had been sent
     *        "400":
     *          description: bad recaptcha (if apply)
     */

    router.post('/api/v2/oauth/user/profile/request_verification_email', [passport.authenticate('bearer', {session: false}), limiterHelper.verify], resend_validation_email);

};
