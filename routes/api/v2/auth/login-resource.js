"use strict";

const cors = require('../../../../lib/cors');
const config = require('../../../../config');
const logger = require('../../../../lib/logger');
const requestHelper = require('../../../../lib/request-helper');
const userHelper = require('../../../../lib/user-helper');
const limiterHelper = require('../../../../lib/limiter-helper');
const authHelper = require('../../../../lib/auth-helper');
const afterLogoutHelper = require('../../../../lib/afterlogout-helper');
const jwt = require('jwt-simple');
const loginService = require('../../../../services/login-service');
const errors = require('../../../../services/errors');
var trackingCookie = require('../../../../lib/tracking-cookie');
var recaptcha = require('express-recaptcha');

const SESSION_LOGIN_PATH = '/api/v2/session/cookie';

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

    app.post('/responsive/session/signup', limiterHelper.verify, recaptcha.middleware.render, function (req, res, next) {
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
    app.post('/api/v2/session/login', cors, function (req, res) {

        loginService.login(req, res)
            .then(function (user) {
                req.logIn(user, function () {
                    handleAfterSessionRestLogin(user, req, res);
                });
            })
            .catch(function (err) {
                handleErrorForRestCalls(err, res);
            });
    });
    app.post('/responsive/session/login', cors, function (req, res) {

        loginService.login(req, res)
            .then(function (user) {
                req.logIn(user, function () {
                    handleAfterSessionHtlmLogin(user, req, res);
                });
            })
            .catch(function (err) {
                handleErrorForHtmlCalls(req, res, err);
            });
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
    app.get(SESSION_LOGIN_PATH, cors, function (req, res) {
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

        loginService.login(req, res)
            .then(function (user) {
                handleAfterJWTRestLogin(user, req, res);
            })
            .catch(function (err) {
                handleErrorForRestCalls(err, res);
            });
    });


    app.get('/responsive/login', trackingCookie.middleware, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: req.query.error ? req.__(req.query.error) : '',
            email: req.query.email ? req.query.email : '',
            signup: requestHelper.getPath('/responsive/signup' + redirect),
            forgotPassword: requestHelper.getPath('/responsive/forgotpassword' + redirect),
            target: requestHelper.getPath('/responsive/session/login' + redirect),
            fbTarget: requestHelper.getPath('/api/v2/auth/facebook' + redirect),
            googleTarget: requestHelper.getPath('/api/v2/auth/google' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        res.render('./login/broadcaster/' + broadcaster + 'login.ejs', data);
    });

    app.get('/responsive/signup', trackingCookie.middleware, recaptcha.middleware.render, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            captcha: req.recaptcha,
            requiredFields: userHelper.getRequiredFields(),
            message: req.query.error ? req.__(req.query.error) : '',
            email: req.query.email ? req.query.email : '',
            date_of_birth: req.query.date_of_birth ? req.query.date_of_birth : '',
            firstname: req.query.firstname ? req.query.firstname : '',
            lastname: req.query.lastname ? req.query.lastname : '',
            login: requestHelper.getPath('/responsive/login' + redirect),
            target: requestHelper.getPath('/responsive/session/signup' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        res.render('./login/broadcaster/' + broadcaster + 'signup.ejs', data);
    });


    app.get('/responsive/forgotpassword', recaptcha.middleware.render, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: '',
            captcha: req.recaptcha,
            email: req.query.email ? req.query.email : '',
            date_of_birth: req.query.date_of_birth ? req.query.date_of_birth : '',
            firstname: req.query.firstname ? req.query.firstname : '',
            lastname: req.query.lastname ? req.query.lastname : '',
            login: requestHelper.getPath('/responsive/login' + redirect),
            target: requestHelper.getPath('/api/local/password/recover' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        res.render('./login/broadcaster/' + broadcaster + 'forgot-password.ejs', data);
    });


};

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
            handleErrorForRestCalls(err, res);
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
                message: err.errorData ? req.__(err.errorData.key) : err.toString(),
                captcha: req.recaptcha,
                email: req.body.email ? req.body.email : '',
                date_of_birth: req.body.date_of_birth ? req.body.date_of_birth : '',
                firstname: req.body.firstname ? req.body.firstname : '',
                lastname: req.body.lastname ? req.body.lastname : '',
                login: requestHelper.getPath('/responsive/login' + redirect),
                target: requestHelper.getPath('/responsive/session/signup' + redirect)
            };
            let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
            res.render('./login/broadcaster/' + broadcaster + 'signup.ejs', data);
        });
}


/////////////////////
// handler depending on security


function handleAfterSessionRestLogin(user, req, res) {
    const REDIRECT_URI = req.query.redirect;
    if (REDIRECT_URI) {
        if (req.query.withcode) {
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
        if (req.query.withcode) {
            var allowed = isAllowedRedirectUri(REDIRECT_URI);
            if (allowed) {
                res.redirect(requestHelper.getPath(SESSION_LOGIN_PATH + '?redirect=' + REDIRECT_URI));
            } else {
                // This is not supposed to happen => json error message is acceptable
                res.status(400).json({msg: 'redirect uri ' + REDIRECT_URI + ' is not an allowed redirection'});
            }
        } else {
            res.redirect(REDIRECT_URI);
        }
    } else {
        res.redirect(requestHelper.getPath('/'));
    }
}


function handleAfterJWTRestLogin(user, req, res) {
    const token = jwt.encode(user, config.jwtSecret);
    const REDIRECT_URI = req.query.redirect;
    if (REDIRECT_URI) {
        if (req.query.withcode) {
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
        redirect = '?redirect=' + encodeURIComponent(req.query.redirect);
        if (req.query.withcode) {
            redirect += '&withcode=true';
        }
    }
    return redirect;
}


function handleErrorForRestCalls(err, res) {
    if (err.name === errors.VALIDATION_ERROR) {
        res.status(400).json({error: err.errorData});
    } else if (err.name === errors.BAD_CREDENTIAL_ERROR) {
        res.status(401).json({error: err.errorData});
    } else {
        logger.warn("unexpected error.", err);
        res.status(500).json({msg: "unexpected error."});
    }
}

function handleErrorForHtmlCalls(req, res, err) {
    var redirect = getRedirectParams(req);

    var data = {
        message: err.errorData ? req.__(err.errorData.key) : err.toString(),
        email: req.body.email ? req.body.email : '',
        signup: requestHelper.getPath('/responsive/signup' + redirect),
        forgotPassword: requestHelper.getPath('/responsive/forgotpassword' + redirect),
        target: requestHelper.getPath('/responsive/session/login' + redirect),
        fbTarget: requestHelper.getPath('/api/v2/auth/facebook' + redirect),
        googleTarget: requestHelper.getPath('/api/v2/auth/google' + redirect)
    };
    let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
    res.render('./login/broadcaster/' + broadcaster + 'login.ejs', data);
}
