"use strict";

const cors = require('../../../../lib/cors'),
    config = require('../../../../config'),
    logger = require('../../../../lib/logger'),
    requestHelper = require('../../../../lib/request-helper'),
    userHelper = require('../../../../lib/user-helper'),
    limiterHelper = require('../../../../lib/limiter-helper'),
    authHelper = require('../../../../lib/auth-helper'),
    afterLogoutHelper = require('../../../../lib/afterlogout-helper'),
    jwt = require('jwt-simple'),
    loginService = require('../../../../services/login-service'),
    errors = require('../../../../services/errors'),
    _ = require('underscore');



var trackingCookie = require('../../../../lib/tracking-cookie');
var recaptcha = require('express-recaptcha');
var fs = require('fs');


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
     *   PasswordRecover:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           g-recaptcha-response:
     *               type: "string"
     *               example: "03AF6jDqV2qwvu9iFUeXbiABG9fxCwSYB_NRewpquSl8UbQkniIB4yMSAK0hz3E29FSzxlaw78aQd18Nv9541LtYe5X6tCuZyb78_GUabMXGgDr4_VNGdP_drGR7zN4b1tIP6cTNlSNfgvSwsfYQN6BW8NC0QUlpa5wlDlNioTTn0hGLe0widNeHDqbHcLF292VvsYRDypqdR_D0nMDzKXXr9jEG_itB8c3tAkImmlbVzSeGMEUKORnbMl-ZI-NkFq6Hb_5zfZ1tAf8CcL38FAqywYmY79nrmP1RGSWN4G2xI8CcFx5b7tjtc"
     *               description: "recaptcha response"
     *
     *   PasswordUpdate:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           password:
     *               type: "string"
     *               example: "cr@zyNewP@ssword"
     *               description: "new password"
     *           code:
     *               type: "string"
     *               example: "f5a6f93fd5bf0099e1dad955746d6d"
     *               description: "user email"
     *
     */


    /**
     * @swagger
     * /api/v2/session/signup:
     *   post:
     *     description: signup
     *     tags: [Session]
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
    app.options('/api/v2/session/signup', cors);
    app.post('/api/v2/session/signup', limiterHelper.verify, function (req, res, next) {
        signupREST(req, res, handleAfterSessionRestLogin);
    });

    app.post('/signup', limiterHelper.verify, recaptcha.middleware.render, function (req, res, next) {
        signupHTML(req, res, handleAfterSessionHtlmLogin);
    });


    /**
     * @swagger
     * /api/v2/all/password/recover:
     *   post:
     *     description: password recover
     *     operationId: "passwordRecover"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "passwordRecoverData"
     *            description: "password recover data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/PasswordRecover"
     *     responses:
     *          "200":
     *            description: "a recovery email had been sent"
     */
    app.options('/api/v2/all/password/recover', cors);
    app.post('/api/v2/all/password/recover', cors, limiterHelper.verify, userHelper.password_recover);

    /**
     * @swagger
     * /api/v2/all/password/update:
     *   post:
     *     description: "password update errors could be WRONG_RECOVERY_CODE, NO_USER_FOR_THIS_MAIL OR DATA_VALIDATION_ERROR (with following causes: PWD_EMPTY OR CODE_MISSING)"
     *     operationId: "passwordUpdate"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "passwordUpdateData"
     *            description: "password update data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/PasswordUpdate"
     *     responses:
     *          "204":
     *            description: "Password"
     */
    app.options('/api/v2/all/password/update', cors);
    app.post('/api/v2/all/password/update', cors, userHelper.password_update);


    /**
     * @swagger
     * /api/v2/session/login:
     *   post:
     *     description: login
     *     tags: [Session]
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
    app.options('/api/v2/session/login', cors);
    app.post('/api/v2/session/login', cors, function (req, res, next) {

        loginService.login(req, res)
            .then(function (user) {
                // force renew cookie so a cookie value couldn't point at different time to different user
                req.session.regenerate(function (err) {
                    if (err) {
                        next(err);
                    } else {
                        req.logIn(user, function () {
                            handleAfterSessionRestLogin(user, req, res);
                        });
                    }
                });
            })
            .catch(function (err) {
                handleErrorForRestCalls(err, res);
            });
    });
    app.post('/login', cors, function (req, res, next) {

        loginService.login(req, res)
            .then(function (user) {
                // force renew cookie so a cookie value couldn't point at different time to different user
                req.session.regenerate(function (err) {
                    if (err) {
                        next(err);
                    } else {
                        req.logIn(user, function () {
                            handleAfterSessionHtlmLogin(user, req, res);
                        });
                    }
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
     *     tags: [Session]
     *     operationId: "sessionDisconnect"
     *     responses:
     *          "204":
     *            description: "user disconnected"
     */
    app.options('/api/v2/session/logout', cors);
    app.delete('/api/v2/session/logout', cors, authHelper.ensureAuthenticated, function (req, res, next) {

        afterLogoutHelper.afterLogout(res);
        req.logout();

        // force renew cookie so a cookie value couldn't point at different time to different user
        return req.session.regenerate(function (err) {
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
     *     tags: [Session]
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
    app.options(SESSION_LOGIN_PATH, cors);
    app.get(SESSION_LOGIN_PATH, cors, function (req, res) {
        const REDIRECT_URI = req.query.redirect;
        if (REDIRECT_URI && isAllowedRedirectUri(REDIRECT_URI)) {
            if (REDIRECT_URI.indexOf("?") >= 0) {
                res.redirect(REDIRECT_URI + '&token=' + encodeURIComponent(req.cookies[config.auth_session_cookie.name]));
            } else {
                res.redirect(REDIRECT_URI + '?token=' + encodeURIComponent(req.cookies[config.auth_session_cookie.name]));
            }
        } else {
            res.status(400).json({msg: 'redirect uri ' + REDIRECT_URI + ' is not an allowed redirection'});
        }
    });


    /**
     * @swagger
     * /api/v2/jwt/signup:
     *   post:
     *     description: signup
     *     tags: [JWT]
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
    app.options('/api/v2/jwt/signup', cors);
    app.post('/api/v2/jwt/signup', limiterHelper.verify, function (req, res, next) {
        signupREST(req, res, handleAfterJWTRestLogin);
    });


    /**
     * @swagger
     * /api/v2/jwt/login:
     *   post:
     *     description: login
     *     tags: [JWT]
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
    app.options('/api/v2/jwt/login', cors);
    app.post('/api/v2/jwt/login', cors, function (req, res) {

        loginService.login(req, res)
            .then(function (user) {
                handleAfterJWTRestLogin(user, req, res);
            })
            .catch(function (err) {
                handleErrorForRestCalls(err, res);
            });
    });

    /**
     * @swagger
     * /api/v2/session/jwt:
     *   get:
     *     description: login
     *     tags: [Session]
     *     operationId: "getJWTToken"
     *     responses:
     *          "200":
     *            description: "return jwt token for logged user"
     *            schema:
     *              $ref: '#/definitions/JWTToken'
     */
    app.get('/api/v2/session/jwt', cors, authHelper.ensureAuthenticated, function (req, res) {
        res.json({token: 'JWT ' + jwt.encode(req.user, config.jwtSecret)});
    });


    app.get('/login', trackingCookie.middleware, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: req.query.error ? req.__(req.query.error) : '',
            email: req.query.email ? req.query.email : '',
            signup: requestHelper.getPath('/signup' + redirect),
            forgotPassword: requestHelper.getPath('/forgotpassword' + redirect),
            target: requestHelper.getPath('/login' + redirect),
            fbTarget: requestHelper.getPath('/api/v2/auth/facebook' + redirect),
            googleTarget: requestHelper.getPath('/api/v2/auth/google' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        const path = './login/broadcaster/' + broadcaster + 'login.ejs';
        if (templateExists(path)) {
            res.render(path, data);
        } else {
            res.render('./login/broadcaster/default/login.ejs', data);
        }
    });

    app.get('/signup', trackingCookie.middleware, recaptcha.middleware.render, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            captcha: req.recaptcha,
            requiredFields: userHelper.getRequiredFields(),
            message: req.query.error ? req.__(req.query.error) : '',
            email: req.query.email ? req.query.email : '',
            date_of_birth: req.query.date_of_birth ? req.query.date_of_birth : '',
            firstname: req.query.firstname ? req.query.firstname : '',
            lastname: req.query.lastname ? req.query.lastname : '',
            login: requestHelper.getPath('/login' + redirect),
            target: requestHelper.getPath('/signup' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        const path = 'login/broadcaster/' + broadcaster + 'signup.ejs';
        if (templateExists(path)) {
            res.render(path, data);
        } else {
            res.render('./login/broadcaster/default/signup.ejs', data);
        }
    });


    app.get('/forgotpassword', recaptcha.middleware.render, function (req, res) {
        var redirect = getRedirectParams(req);

        var data = {
            message: '',
            captcha: req.recaptcha,
            email: req.query.email ? req.query.email : '',
            date_of_birth: req.query.date_of_birth ? req.query.date_of_birth : '',
            firstname: req.query.firstname ? req.query.firstname : '',
            lastname: req.query.lastname ? req.query.lastname : '',
            login: requestHelper.getPath('/login' + redirect),
            target: requestHelper.getPath('/api/v2/all/password/recover' + redirect)
        };
        let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
        const path = './login/broadcaster/' + broadcaster + 'forgot-password.ejs';
        if (templateExists(path)) {
            res.render(path, data);
        } else {
            res.render('./login/broadcaster/default/forgot-password.ejs', data);
        }
    });


};

/////////////////////
// signup
function signupREST(req, res, handleAfterLogin) {
    loginService.checkSignupData(req)
        .then(function (userAttributes) {
            return loginService.signup(userAttributes, req.body.email, req.body.password, req, res);
        })
        .then(function (user) {
            // force renew cookie so a cookie value couldn't point at different time to different user
            req.session.regenerate(function (err) {
                if (err) {
                    handleErrorForRestCalls(err, res);
                } else {
                    req.logIn(user, function () {
                        handleAfterLogin(user, req, res);
                    });
                }
            });
        })
        .catch(function (err) {
            handleErrorForRestCalls(err, res);
        });
}

function signupHTML(req, res, handleAfterLogin) {
    loginService.checkSignupData(req)
        .then(function (userAttributes) {
            return loginService.signup(userAttributes, req.body.email, req.body.password, req, res);
        })
        .then(function (user) {
            // force renew cookie so a cookie value couldn't point at different time to different user
            req.session.regenerate(function (err) {
                if (err) {
                    handleErrorForSignupHTMLCalls(req, err, res);
                } else {
                    req.logIn(user, function () {
                        handleAfterLogin(user, req, res);
                    });
                }
            });
        })
        .catch(function (err) {
            handleErrorForSignupHTMLCalls(req, err, res);
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
    userHelper.getProfileByReq(req,user)
    .then(profile => {
        // This merges the objects, so we don't loose data for services that rely on them
        const token = jwt.encode(_.extend({}, user.dataValues, profile.user), config.jwtSecret);
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
    })
    .catch(e => {
        logger.error(e);
        res.sendStatus(400); // 500 may be better, but I like the client to think *he* did wrong, not *us* :)
    });
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
        signup: requestHelper.getPath('/signup' + redirect),
        forgotPassword: requestHelper.getPath('/forgotpassword' + redirect),
        target: requestHelper.getPath('/login' + redirect),
        fbTarget: requestHelper.getPath('/api/v2/auth/facebook' + redirect),
        googleTarget: requestHelper.getPath('/api/v2/auth/google' + redirect)
    };
    let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
    const path = './login/broadcaster/' + broadcaster + 'login.ejs';
    if (templateExists(path)) {
        res.render(path, data);
    } else {
        res.render('./login/broadcaster/default/login.ejs', data);
    }
}

function handleErrorForSignupHTMLCalls(req, err, res) {
    var redirect = getRedirectParams(req);

    var data = {
        message: err.errorData ? req.__(err.errorData.key) : err.toString(),
        captcha: req.recaptcha,
        email: req.body.email ? req.body.email : '',
        date_of_birth: req.body.date_of_birth ? req.body.date_of_birth : '',
        firstname: req.body.firstname ? req.body.firstname : '',
        lastname: req.body.lastname ? req.body.lastname : '',
        login: requestHelper.getPath('/login' + redirect),
        target: requestHelper.getPath('/signup' + redirect)
    };
    let broadcaster = config.broadcaster && config.broadcaster.layout ? config.broadcaster.layout + '/' : 'default/';
    const path = './login/broadcaster/' + broadcaster + 'signup.ejs';
    if (templateExists(path)) {
        res.render(path, data);
    } else {
        res.render('./login/broadcaster/default/signup.ejs', data);
    }

}


function templateExists(path) {
    return fs.existsSync(__dirname + '/../../../../views/' + path);
}