"use strict";

const passport = require('passport');
const afterLoginHelper = require('../../../../lib/afterlogin-helper');
const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const db = require('../../../../models');
const logger = require('../../../../lib/logger');
const requestHelper = require('../../../../lib/request-helper');
const LocalStrategy = require('passport-local').Strategy;
const authLocalHelper = require('../../../../lib/auth-local-helper');
const limiterHelper = require('../../../../lib/limiter-helper');
const authHelper = require('../../../../lib/auth-helper');
const afterLogoutHelper = require('../../../../lib/afterlogout-helper');
const userHelper = require('../../../../lib/user-helper');
const passwordHelper = require('../../../../lib/password-helper');
const jwt = require('jwt-simple');
const loginService = require('../../../../services/login-service');
const errors = require('../../../../services/errors');
const Op = db.sequelize.Op;


const SESSION_LOGIN_PATH = '/api/v2/session/cookie';

var localStrategyConf = {
    // by default, local strategy uses username and password, we will override with email
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true // allows us to pass back the entire request to the callback
};

const LOCAL_REDIRECT_STRATEGY = 'local-redirect';


// TODO move that to login service
passport.use(LOCAL_REDIRECT_STRATEGY, new LocalStrategy(localStrategyConf, authLocalHelper.localStrategyCallback));


module.exports = function (app, options) {

    /**
     * @swagger
     * definitions:
     *   Credentials:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password"
     *   SignupData:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password"
     *           confirm_password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password confirm value"
     *           gender:
     *               type: "string"
     *               enum: [other, male, female]
     *               example: male
     *               description: user gender
     *           date_of_birth:
     *               type: "string"
     *               example: 31.08.1978
     *               description: "user date of birth"
     *   SessionToken:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "s%3AhWMtLUjPHIUvc-nSw2Lr-2YLZf_bE4hy.GXWJQgyHtd1ad3DubqvYNMKsJQ2bHceDdIZN1oTfcEY"
     *               description: "user session cookie value"
     *   JWTToken:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6OCwiZGlzcGxheV9uYW1lIjoibWFpbEBtYWlsLm1haWwiLCJ1cGRhdGVkX2F0IjoiMjAxOC0wOS0xMFQxMTo1Nzo1OS41MTRaIiwiY3JlYXRlZF9hdCI6IjIwMTgtMDktMTBUMTE6NTc6NTkuNTE0WiJ9.grw08gCjKH36rJKDN3thhgjo9HbXTk42BMX-q1Hlv4c"
     *               description: "user session cookie value"
     *
     *
     */


    /**
     * @swagger
     * /api/v2/session/signup:
     *   post:
     *     description: signup
     *     operationId: "signup"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "signup data"
     *            description: "signup data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/SignupData"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *          - in: query
     *            name: "code"
     *            example: "true"
     *            schema:
     *              type: string
     *              description: if present a first redirect'd be request to /api/v2/session/cookie
     *     responses:
     *          "204":
     *            description: "signup succeed"
     *          "302":
     *            schema:
     *              $ref: '#/definitions/SessionToken'
     */
    app.post('/api/v2/session/signup', limiterHelper.verify, function (req, res, next) {
        signupREST(req, res, handleAfterSessionRestLogin);
    });

    app.post('/responsive/session/signup', limiterHelper.verify, function (req, res, next) {
        signupHTML(req, res, handleAfterSessionHtlmLogin);
    });


    /**
     * @swagger
     * /api/v2/session/login:
     *   post:
     *     description: login
     *     operationId: "sessionLogin"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "credentials"
     *            description: "user credential"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/Credentials"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *          - in: query
     *            name: "code"
     *            example: "true"
     *            schema:
     *              type: string
     *              description: if present a first redirect'd be request to /api/v2/session/cookie
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "302":
     *            description: "a redirect with token in body response"
     *            schema:
     *              $ref: '#/definitions/SessionToken'
     */
    app.post('/api/v2/session/login', cors,
        passport.authenticate(LOCAL_REDIRECT_STRATEGY, {session: true}),
        function (req, res) {

            afterLoginHelper.afterLogin(req.user, req.body.email || req.query.email, res);

            handleAfterSessionRestLogin(req.user, req, res);
        });


    /**
     * @swagger
     * /api/v2/session/logout:
     *   delete:
     *     description: disconnect
     *     operationId: "sessionDisconnect"
     *     responses:
     *          "204":
     *            description: "user disconnected"
     */
    app.delete('/api/v2/session/logout', cors, authHelper.ensureAuthenticated, function (req, res, next) {

        afterLogoutHelper.afterLogout(res);
        req.logout();
        req.session.destroy(function (err) {
            if (err) {
                return next(err);
            }
            return res.sendStatus(204);
        });
    });


    /**
     * @swagger
     * /api/v2/session/cookie:
     *   get:
     *     description: login
     *     operationId: "getSessionCookie"
     *     parameters:
     *          - in: query
     *            name: "redirect"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *     responses:
     *          "200":
     *            description: "current session cookie"
     *            schema:
     *              $ref: '#/definitions/Token'
     *          "302":
     *            description: "a redirect with token as a get query parameter"
     */
    app.get(SESSION_LOGIN_PATH, cors, function (req, res, next) {
        const REDIRECT_URI = req.query.redirect;
        if (REDIRECT_URI && isAllowedRedirectUri(REDIRECT_URI)) {
            res.redirect(REDIRECT_URI + '?token=' + encodeURIComponent(req.cookies[config.auth_session_cookie.name]));
        } else {
            res.status(400).json({msg: 'redirect uri ' + REDIRECT_URI + ' is not an allowed redirection'});
        }
    });


    /**
     * @swagger
     * /api/v2/jwt/signup:
     *   post:
     *     description: signup
     *     operationId: "signup"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "signup data"
     *            description: "signup data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/SignupData"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the JWT token
     *     responses:
     *          "200":
     *            description: "signup succeed"
     *            schema:
     *              $ref: '#/definitions/JWTToken'
     *          "302":
     *            description: "redirect"

     */
    app.post('/api/v2/jwt/signup', limiterHelper.verify, function (req, res, next) {
        signupREST(req, res, handleAfterJWTRestLogin);
    });


    /**
     * @swagger
     * /api/v2/jwt/login:
     *   post:
     *     description: login
     *     operationId: "sessionLogin"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "credentials"
     *            description: "user credential"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/Credentials"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *          - in: query
     *            name: "code"
     *            example: "true"
     *            schema:
     *              type: string
     *              description: if present a first redirect'd be request to /api/v2/session/cookie
     *     responses:
     *          "200":
     *            description: "signup succeed"
     *            schema:
     *              $ref: '#/definitions/JWTToken'
     *          "302":
     *            description: "redirect"
     */
    app.post('/api/v2/jwt/login', cors, function (req, res) {

        // TODO : move that code to login service

        db.LocalLogin.findOne({
            where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), {[Op.like]: req.body.email.toLowerCase()}),
            include: [db.User]
        }).then(function (localLogin) {
            if (localLogin && req.body.password) {
                localLogin.verifyPassword(req.body.password)
                    .then(function (isMatch) {
                        if (isMatch) {
                            localLogin.logLogin(localLogin.User);
                            handleAfterJWTRestLogin(localLogin.User, req, res);
                        } else {
                            res.status(401).json({msg: req.__('API_INCORRECT_LOGIN_OR_PASS')});
                        }
                    });
            } else {
                res.status(401).json({msg: req.__('API_INCORRECT_LOGIN_OR_PASS')});
            }
        });
    });


    app.get('/responsive/login', function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: '',
            email: req.query.email ? req.query.email : '',
            signup: requestHelper.getPath('/responsive/signup' + redirect),
            target: requestHelper.getPath('/api/v2/session/login' + redirect), //FIXME
            fbTarget: requestHelper.getPath('/api/v2/auth/facebook' + redirect),
            googleTarget: requestHelper.getPath('/api/v2/auth/google' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : '';
        res.render('./login/broadcaster/' + broadcaster + 'login.ejs', data);
    });

    app.get('/responsive/signup', function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: '',
            email: req.query.email ? req.query.email : '',
            date_of_birth: req.query.date_of_birth ? req.query.date_of_birth : '',
            firstname: req.query.firstname ? req.query.firstname : '',
            lastname: req.query.lastname ? req.query.lastname : '',
            login: requestHelper.getPath('/responsive/login' + redirect),
            target: requestHelper.getPath('/responsive/session/signup' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : '';
        res.render('./login/broadcaster/' + broadcaster + 'signup.ejs', data);
    });


}

// TODO Create /view/v2/signup or responsive/signup
// TODO validate endpoint naming


/////////////////////
// signup
function signupREST(req, res, handleAfterLogin) {
    loginService.checkSignupData(req)
        .then(function (userAttributes) {
            return loginService.signup(userAttributes, req.body.email, req.body.password);
        })
        .then(function (user) {
            req.logIn(user, function () {
                handleAfterLogin(user, req, res);
            });
        })
        .catch(function (err) {
            if (err.name === errors.VALIDATION_ERROR) {
                res.status(400).json({error: err.errorData});
            } else {
                logger.warn("unexpected error.", err);
                res.status(500).json({msg: "unexpected error."});
            }
        });
}

function signupHTML(req, res, handleAfterLogin) {
    loginService.checkSignupData(req)
        .then(function (userAttributes) {
            return loginService.signup(userAttributes, req.body.email, req.body.password);
        })
        .then(function (user) {
            req.logIn(user, function () {
                handleAfterLogin(user, req, res);
            });
        })
        .catch(function (err) {
            var redirect = getRedirectParams(req);

            var data = {
                message: req.__(err.errorData.key),
                email: req.body.email ? req.body.email : '',
                date_of_birth: req.body.date_of_birth ? req.body.date_of_birth : '',
                firstname: req.body.firstname ? req.body.firstname : '',
                lastname: req.body.lastname ? req.body.lastname : '',
                login: requestHelper.getPath('/responsive/login' + redirect),
                target: requestHelper.getPath('/responsive/session/signup' + redirect)
            };
            let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : '';
            res.render('./login/broadcaster/' + broadcaster + 'signup.ejs', data);
        });
}


/////////////////////
// handler depending on security


function handleAfterSessionRestLogin(user, req, res) {
    const REDIRECT_URI = req.query.redirect;
    if (REDIRECT_URI) {
        if (req.query.code) {
            var allowed = isAllowedRedirectUri(REDIRECT_URI);
            if (allowed) {
                res.redirect(requestHelper.getPath(SESSION_LOGIN_PATH + '?redirect=' + REDIRECT_URI));
            } else {
                res.status(400).json({msg: 'redirect uri ' + REDIRECT_URI + ' is not an allowed redirection'});
            }
        } else {
            res.redirect(REDIRECT_URI);
        }
    } else {
        res.sendStatus(204);
    }
}


function handleAfterSessionHtlmLogin(user, req, res) {
    const REDIRECT_URI = req.query.redirect;
    if (REDIRECT_URI) {
        res.redirect(REDIRECT_URI);
    } else {
        res.redirect('/');
    }
}


function handleAfterJWTRestLogin(user, req, res) {
    const token = jwt.encode(user, config.jwtSecret);
    const REDIRECT_URI = req.query.redirect;
    if (REDIRECT_URI) {
        if (req.query.code) {
            var allowed = isAllowedRedirectUri(REDIRECT_URI);
            if (allowed) {
                res.redirect(REDIRECT_URI + '?token=' + encodeURIComponent(req.cookies[config.auth_session_cookie.name]));
            } else {
                res.status(400).json({msg: 'redirect uri ' + REDIRECT_URI + ' is not an allowed redirection'});
            }
        } else {
            res.redirect(REDIRECT_URI);
        }
    } else {
        res.json({token: 'JWT ' + token});
    }
}

/////////////////////
// Utilities

function buildJsonForError(err, req, username) {
    var json;
    if (err.message === userHelper.EXCEPTIONS.EMAIL_TAKEN) {
        json = {msg: req.__('API_SIGNUP_EMAIL_ALREADY_EXISTS')};
    } else if (err.message === userHelper.EXCEPTIONS.PASSWORD_WEAK) {
        json = {
            msg: req.__('API_SIGNUP_PASS_IS_NOT_STRONG_ENOUGH'),
            password_strength_errors: passwordHelper.getWeaknesses(username, req.body.password, req),
            errors: [{msg: passwordHelper.getWeaknessesMsg(username, req.body.password, req)}],
            score: passwordHelper.getQuality(username, req.body.password)
        };
    } else if (err.message === userHelper.EXCEPTIONS.MISSING_FIELDS) {
        logger.debug('[POST /api/v2/session/signup][email', username, '][ERR', err, ']');
        json = {
            msg: req.__('API_SIGNUP_MISSING_FIELDS'),
            missingFields: err.data ? err.data.missingFields : undefined
        };
    } else if (err.message === userHelper.EXCEPTIONS.UNKNOWN_GENDER) {
        json = {
            msg: req.__('API_SIGNUP_MISSING_FIELDS')
        };
    } else if (err.message === userHelper.EXCEPTIONS.MALFORMED_DATE_OF_BIRTH) {
        json = {
            msg: req.__('API_SIGNUP_MISSING_FIELDS')
        };
    } else {
        logger.error('[POST /api/v2/session/signup][email', username, '][ERR', err, ']');
        json = {msg: req.__('API_ERROR') + err};
    }
    return json;
}


function isAllowedRedirectUri(redirectUri) {
    var allowed;
    if (config.afterLogin && config.afterLogin.allowedRedirectUris) {
        var allowedUris = config.afterLogin.allowedRedirectUris.split(',');
        for (var u in allowedUris) {
            allowed = redirectUri.indexOf(allowedUris[u]) == 0;
            if (allowed) {
                break;
            }
        }
    }
    return allowed;
}

function getRedirectParams(req) {
    var redirect = '';
    if (req.query.redirect) {
        redirect = '?redirect=' + encodeURI(req.query.redirect);
        if (req.query.withcode) {
            redirect += '&withcode=true';
        }
    }
    return redirect;
}
